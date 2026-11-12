// Command spark-push-relay delivers Spark servers' push notifications to the
// Spark apps (APNs for iPhone, iPad, Apple TV and Mac, FCM for Android) and
// hands the official Silo apps' Apple pushes on to the official Silo relay.
//
// It speaks the relay protocol Silo servers use: /v1/deployments/{register,
// renew,rotate} hand out signed capabilities, and /v1/apple/send and
// /v1/fcm/send take one "private_alert" push each. A push carries only the
// delivery ID; the app fetches the real text from its server.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"
)

type config struct {
	Listen            string
	DataFile          string
	CapabilitySecret  []byte
	TrustProxy        bool
	RegisterCIDRs     []*net.IPNet
	APNsTopics        []string
	ForwardAPNsTopics []string
	ForwardRelayURL   string
	AlertTitle        string
	AlertBody         string
}

type app struct {
	cfg     config
	store   *store
	apns    *apnsClient
	fcm     *fcmClient
	forward *forwarder
	log     *slog.Logger
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func list(key string) []string {
	var out []string
	for _, part := range strings.Split(os.Getenv(key), ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func loadConfig() (config, error) {
	cfg := config{
		Listen:            env("LISTEN", ":8080"),
		DataFile:          env("DATA_FILE", "/data/relay.json"),
		CapabilitySecret:  []byte(os.Getenv("CAPABILITY_SECRET")),
		TrustProxy:        env("TRUST_PROXY", "false") == "true",
		APNsTopics:        list("APNS_TOPICS"),
		ForwardAPNsTopics: list("FORWARD_APNS_TOPICS"),
		ForwardRelayURL:   strings.TrimRight(env("FORWARD_RELAY_URL", ""), "/"),
		AlertTitle:        env("ALERT_TITLE", "Spark"),
		AlertBody:         env("ALERT_BODY", "You have a new notification."),
	}
	if len(cfg.CapabilitySecret) < 32 {
		return cfg, errors.New("CAPABILITY_SECRET must be at least 32 characters (openssl rand -base64 48)")
	}
	for _, raw := range list("REGISTER_ALLOWED_CIDRS") {
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			return cfg, fmt.Errorf("REGISTER_ALLOWED_CIDRS: %w", err)
		}
		cfg.RegisterCIDRs = append(cfg.RegisterCIDRs, network)
	}
	if len(cfg.ForwardAPNsTopics) > 0 && cfg.ForwardRelayURL == "" {
		return cfg, errors.New("FORWARD_APNS_TOPICS needs FORWARD_RELAY_URL")
	}
	return cfg, nil
}

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg, err := loadConfig()
	if err != nil {
		log.Error("configuration", "error", err)
		os.Exit(1)
	}
	st, err := openStore(cfg.DataFile)
	if err != nil {
		log.Error("open data file", "path", cfg.DataFile, "error", err)
		os.Exit(1)
	}
	a := &app{cfg: cfg, store: st, log: log}
	if path := os.Getenv("APNS_KEY_FILE"); path != "" {
		if a.apns, err = newAPNsClient(path, os.Getenv("APNS_KEY_ID"), os.Getenv("APNS_TEAM_ID")); err != nil {
			log.Error("APNs key", "error", err)
			os.Exit(1)
		}
	}
	if path := os.Getenv("FCM_SERVICE_ACCOUNT_FILE"); path != "" {
		if a.fcm, err = newFCMClient(path); err != nil {
			log.Error("FCM service account", "error", err)
			os.Exit(1)
		}
	}
	if cfg.ForwardRelayURL != "" {
		a.forward = &forwarder{baseURL: cfg.ForwardRelayURL, store: st, http: &http.Client{Timeout: 15 * time.Second}}
	}
	log.Info("relay starting", "listen", cfg.Listen,
		"apns", a.apns != nil, "apns_topics", cfg.APNsTopics,
		"fcm", a.fcm != nil, "forward_topics", cfg.ForwardAPNsTopics)

	server := &http.Server{Addr: cfg.Listen, Handler: a.routes(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("listen", "error", err)
			os.Exit(1)
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}

func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("POST /v1/deployments/register", a.handleRegister)
	mux.HandleFunc("POST /v1/deployments/renew", a.handleAdvance(false))
	mux.HandleFunc("POST /v1/deployments/rotate", a.handleAdvance(true))
	mux.HandleFunc("POST /v1/apple/send", a.handleAppleSend)
	mux.HandleFunc("POST /v1/fcm/send", a.handleFCMSend)
	return mux
}

// --- sends ---

type target struct {
	ServerID  string `json:"server_id,omitempty"`
	ProfileID string `json:"profile_id,omitempty"`
}

type appleSendRequest struct {
	Token          string  `json:"token"`
	Environment    string  `json:"environment"`
	Topic          string  `json:"topic"`
	Mode           string  `json:"mode"`
	ServerDeviceID string  `json:"server_device_id"`
	DeliveryID     string  `json:"delivery_id"`
	CollapseID     *string `json:"collapse_id,omitempty"`
	target
}

type fcmSendRequest struct {
	Token          string  `json:"token"`
	Mode           string  `json:"mode"`
	ServerDeviceID string  `json:"server_device_id"`
	DeliveryID     string  `json:"delivery_id"`
	CollapseID     *string `json:"collapse_id,omitempty"`
	target
}

// sendContext is what both send endpoints share: the authorized deployment,
// the request's raw body, and idempotency handling.
type sendContext struct {
	requestID    string
	deploymentID string
	idemKey      string
	payloadHash  string
	raw          []byte
}

func (a *app) beginSend(w http.ResponseWriter, r *http.Request, dst any, allowed map[string]bool) (*sendContext, bool) {
	sc := &sendContext{requestID: requestIDOf(r)}
	claims, apiErr := a.authorize(r, false)
	if apiErr != nil {
		writeError(w, sc.requestID, apiErr)
		return nil, false
	}
	sc.deploymentID = claims.DeploymentID
	raw, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	if err != nil {
		writeError(w, sc.requestID, &apiError{http.StatusBadRequest, "invalid_body", "The body could not be read"})
		return nil, false
	}
	sc.raw = raw
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		writeError(w, sc.requestID, &apiError{http.StatusBadRequest, "invalid_json", "The body is not a JSON object"})
		return nil, false
	}
	for name := range fields {
		if !allowed[name] {
			writeError(w, sc.requestID, &apiError{http.StatusBadRequest, "unexpected_field", "unexpected field: " + name})
			return nil, false
		}
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		writeError(w, sc.requestID, &apiError{http.StatusBadRequest, "invalid_field", "A field has the wrong type"})
		return nil, false
	}
	sc.idemKey = strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if sc.idemKey == "" || len(sc.idemKey) > 200 {
		writeError(w, sc.requestID, &apiError{http.StatusBadRequest, "invalid_idempotency_key", "Idempotency-Key is required"})
		return nil, false
	}
	canonical, _ := json.Marshal(dst)
	sum := sha256.Sum256(append([]byte(r.URL.Path+"\x00"), canonical...))
	sc.payloadHash = hex.EncodeToString(sum[:])
	var record *idempotencyRecord
	a.store.read(func(d *storeData) { record = d.Idempotency[sc.storeKey()] })
	if record != nil {
		if record.PayloadHash != sc.payloadHash {
			writeError(w, sc.requestID, &apiError{http.StatusUnprocessableEntity, "idempotency_key_reuse", "This Idempotency-Key was used with a different payload"})
			return nil, false
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(record.Status)
		_, _ = w.Write(record.Body)
		return nil, false
	}
	return sc, true
}

func (sc *sendContext) storeKey() string { return sc.deploymentID + "\x00" + sc.idemKey }

// finish answers the send and records definite outcomes (delivered, or
// rejected for good) so a retry under the same key is replayed.
func (a *app) finish(w http.ResponseWriter, sc *sendContext, status int, body any, retryAfter string) {
	raw, _ := json.Marshal(body)
	if status == http.StatusOK || status == http.StatusUnprocessableEntity {
		_ = a.store.update(func(d *storeData) error {
			d.Idempotency[sc.storeKey()] = &idempotencyRecord{PayloadHash: sc.payloadHash, Status: status, Body: raw, At: time.Now()}
			return nil
		})
	}
	if retryAfter != "" {
		w.Header().Set("Retry-After", retryAfter)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

var appleFields = map[string]bool{"token": true, "environment": true, "topic": true, "mode": true,
	"server_device_id": true, "delivery_id": true, "collapse_id": true, "server_id": true, "profile_id": true}

var fcmFields = map[string]bool{"token": true, "mode": true, "server_device_id": true,
	"delivery_id": true, "collapse_id": true, "server_id": true, "profile_id": true}

func validTarget(t target) bool {
	if t.ServerID == "" && t.ProfileID == "" {
		return true
	}
	return t.ServerID != "" && t.ProfileID != "" && len(t.ServerID) <= 128 && len(t.ProfileID) <= 128
}

func (a *app) handleAppleSend(w http.ResponseWriter, r *http.Request) {
	var req appleSendRequest
	sc, ok := a.beginSend(w, r, &req, appleFields)
	if !ok {
		return
	}
	switch {
	case req.Token == "" || req.DeliveryID == "" || req.Topic == "":
		writeError(w, sc.requestID, &apiError{http.StatusBadRequest, "missing_field", "token, topic and delivery_id are required"})
		return
	case req.Mode != "private_alert" && req.Mode != "background_wake":
		writeError(w, sc.requestID, &apiError{http.StatusBadRequest, "invalid_field", "mode must be private_alert"})
		return
	case !validTarget(req.target):
		writeError(w, sc.requestID, &apiError{http.StatusBadRequest, "invalid_field", "server_id and profile_id go together, 1 to 128 characters each"})
		return
	}

	if slices.Contains(a.cfg.ForwardAPNsTopics, req.Topic) && a.forward != nil {
		resp, err := a.forward.send(sc.raw, sc.deploymentID, sc.idemKey)
		if err != nil {
			a.log.Warn("forward to official relay failed", "error", err)
			writeError(w, sc.requestID, &apiError{http.StatusBadGateway, "forward_unreachable", "The official Silo relay could not be reached"})
			return
		}
		var body any = json.RawMessage(resp.Body)
		if !json.Valid(resp.Body) {
			body = map[string]any{"error": map[string]string{"code": "forward_bad_response", "message": "The official relay answered " + fmt.Sprint(resp.Status)}}
		}
		a.finish(w, sc, resp.Status, body, resp.RetryAfter)
		return
	}
	if !slices.Contains(a.cfg.APNsTopics, req.Topic) || a.apns == nil {
		writeError(w, sc.requestID, &apiError{http.StatusUnprocessableEntity, "topic_not_allowed", "This relay does not push to topic " + req.Topic})
		return
	}
	result, err := a.apns.send(req, a.cfg.AlertTitle, a.cfg.AlertBody)
	if err != nil {
		a.log.Warn("APNs request failed", "error", err)
		writeError(w, sc.requestID, &apiError{http.StatusBadGateway, "apns_unreachable", "APNs could not be reached"})
		return
	}
	switch {
	case result.Status == http.StatusOK:
		a.finish(w, sc, http.StatusOK, map[string]string{"request_id": sc.requestID, "apns_id": result.APNsID, "status": "delivered"}, "")
	case result.Status == http.StatusTooManyRequests || result.Status >= 500:
		a.finish(w, sc, http.StatusServiceUnavailable, errorBody(sc.requestID, "apns_unavailable", "APNs is busy: "+result.Reason), result.RetryAfter)
	case result.Status == http.StatusForbidden && (result.Reason == "ExpiredProviderToken" || result.Reason == "InvalidProviderToken"):
		a.log.Error("APNs refused the relay's key; check APNS_KEY_ID, APNS_TEAM_ID and the .p8", "reason", result.Reason)
		a.finish(w, sc, http.StatusServiceUnavailable, errorBody(sc.requestID, "apns_auth_failed", "APNs refused the relay's key"), "")
	default:
		a.finish(w, sc, http.StatusUnprocessableEntity, errorBody(sc.requestID, "apns_rejected", "APNs rejected the notification: "+result.Reason), "")
	}
}

func (a *app) handleFCMSend(w http.ResponseWriter, r *http.Request) {
	var req fcmSendRequest
	sc, ok := a.beginSend(w, r, &req, fcmFields)
	if !ok {
		return
	}
	switch {
	case req.Token == "" || req.DeliveryID == "":
		writeError(w, sc.requestID, &apiError{http.StatusBadRequest, "missing_field", "token and delivery_id are required"})
		return
	case req.Mode != "private_alert" && req.Mode != "background_wake":
		writeError(w, sc.requestID, &apiError{http.StatusBadRequest, "invalid_field", "mode must be private_alert"})
		return
	case !validTarget(req.target):
		writeError(w, sc.requestID, &apiError{http.StatusBadRequest, "invalid_field", "server_id and profile_id go together, 1 to 128 characters each"})
		return
	case a.fcm == nil:
		writeError(w, sc.requestID, &apiError{http.StatusServiceUnavailable, "fcm_not_configured", "This relay has no Firebase project"})
		return
	}
	result, err := a.fcm.send(req, a.cfg.AlertTitle, a.cfg.AlertBody)
	if err != nil {
		a.log.Warn("FCM request failed", "error", err)
		writeError(w, sc.requestID, &apiError{http.StatusBadGateway, "fcm_unreachable", "FCM could not be reached"})
		return
	}
	switch {
	case result.Status == http.StatusOK:
		a.finish(w, sc, http.StatusOK, map[string]string{"request_id": sc.requestID, "fcm_name": result.Name, "status": "delivered"}, "")
	case result.Status == http.StatusTooManyRequests || result.Status >= 500:
		a.finish(w, sc, http.StatusServiceUnavailable, errorBody(sc.requestID, "fcm_unavailable", "FCM is busy: "+result.ErrorCode), result.RetryAfter)
	case result.Status == http.StatusUnauthorized || result.Status == http.StatusForbidden:
		a.log.Error("FCM refused the relay's service account", "code", result.ErrorCode)
		a.finish(w, sc, http.StatusServiceUnavailable, errorBody(sc.requestID, "fcm_auth_failed", "FCM refused the relay's service account"), "")
	default:
		a.finish(w, sc, http.StatusUnprocessableEntity, errorBody(sc.requestID, "fcm_rejected", "FCM rejected the notification: "+result.ErrorCode), "")
	}
}

// --- HTTP helpers ---

type apiError struct {
	Status  int
	Code    string
	Message string
}

func errorBody(requestID, code, message string) map[string]any {
	return map[string]any{"error": map[string]string{"code": code, "message": message, "request_id": requestID}}
}

func writeError(w http.ResponseWriter, requestID string, e *apiError) {
	writeJSON(w, e.Status, errorBody(requestID, e.Code, e.Message))
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func requestIDOf(r *http.Request) string {
	if id := strings.TrimSpace(r.Header.Get("X-Request-ID")); id != "" && len(id) <= 64 {
		return id
	}
	return randomID("req_", 8)
}

func clientIP(r *http.Request, trustProxy bool) net.IP {
	if trustProxy {
		// The proxy appends the address it saw; earlier entries come from the
		// client and prove nothing.
		forwarded := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		if ip := net.ParseIP(strings.TrimSpace(forwarded[len(forwarded)-1])); ip != nil {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}

func (a *app) registerAllowed(r *http.Request) bool {
	if len(a.cfg.RegisterCIDRs) == 0 {
		return true
	}
	ip := clientIP(r, a.cfg.TrustProxy)
	for _, network := range a.cfg.RegisterCIDRs {
		if ip != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}
