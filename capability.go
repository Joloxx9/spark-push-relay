package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

const (
	capabilityPrefix   = "sk_"
	capabilityLifetime = 90 * 24 * time.Hour
	// renewalGrace is how long past its expiry a capability may still renew.
	renewalGrace = 30 * 24 * time.Hour
)

type capabilityClaims struct {
	DeploymentID string `json:"d"`
	Generation   int    `json:"g"`
	ExpiresAt    int64  `json:"e"`
}

type credentialResponse struct {
	RequestID    string   `json:"request_id"`
	DeploymentID string   `json:"deployment_id"`
	APIKey       string   `json:"api_key"`
	KeyPrefix    string   `json:"key_prefix"`
	APNsTopics   []string `json:"apns_topics"`
	ExpiresAt    string   `json:"expires_at"`
}

func signCapability(secret []byte, claims capabilityClaims) string {
	payload, _ := json.Marshal(claims)
	body := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(body))
	return capabilityPrefix + body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

var errBadCapability = errors.New("invalid capability")

func parseCapability(secret []byte, token string) (capabilityClaims, error) {
	var claims capabilityClaims
	rest, ok := strings.CutPrefix(token, capabilityPrefix)
	if !ok {
		return claims, errBadCapability
	}
	body, sig, ok := strings.Cut(rest, ".")
	if !ok {
		return claims, errBadCapability
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return claims, errBadCapability
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(body))
	if !hmac.Equal(got, mac.Sum(nil)) {
		return claims, errBadCapability
	}
	payload, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil || json.Unmarshal(payload, &claims) != nil || claims.DeploymentID == "" {
		return claims, errBadCapability
	}
	return claims, nil
}

func randomID(prefix string, n int) string {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return prefix + hex.EncodeToString(buf)
}

func bearer(r *http.Request) string {
	value, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return ""
	}
	return strings.TrimSpace(value)
}

// authorize checks a capability for a send. allowExpired lets renew and
// rotate accept a capability inside its renewal grace.
func (a *app) authorize(r *http.Request, allowExpired bool) (capabilityClaims, *apiError) {
	claims, err := parseCapability(a.cfg.CapabilitySecret, bearer(r))
	if err != nil {
		return claims, &apiError{http.StatusUnauthorized, "invalid_token", "The capability is not valid for this relay"}
	}
	expires := time.Unix(claims.ExpiresAt, 0)
	now := time.Now()
	if now.After(expires) && (!allowExpired || now.After(expires.Add(renewalGrace))) {
		return claims, &apiError{http.StatusUnauthorized, "token_expired", "The capability has expired"}
	}
	var dep *deployment
	a.store.read(func(d *storeData) { dep = d.Deployments[claims.DeploymentID] })
	switch {
	case dep == nil:
		return claims, &apiError{http.StatusUnauthorized, "unknown_deployment", "This relay does not know the deployment"}
	case dep.Disabled:
		return claims, &apiError{http.StatusUnauthorized, "deployment_disabled", "This deployment is disabled"}
	case dep.Generation != claims.Generation:
		return claims, &apiError{http.StatusUnauthorized, "capability_superseded", "A newer capability replaced this one"}
	}
	return claims, nil
}

func (a *app) issue(requestID, deploymentID string, generation int) credentialResponse {
	expires := time.Now().Add(capabilityLifetime).UTC().Truncate(time.Second)
	key := signCapability(a.cfg.CapabilitySecret, capabilityClaims{DeploymentID: deploymentID, Generation: generation, ExpiresAt: expires.Unix()})
	topics := append(append([]string{}, a.cfg.APNsTopics...), a.cfg.ForwardAPNsTopics...)
	return credentialResponse{
		RequestID:    requestID,
		DeploymentID: deploymentID,
		APIKey:       key,
		KeyPrefix:    key[:min(len(key), 12)],
		APNsTopics:   topics,
		ExpiresAt:    expires.Format(time.RFC3339),
	}
}

func (a *app) handleRegister(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDOf(r)
	if !a.registerAllowed(r) {
		writeError(w, requestID, &apiError{http.StatusForbidden, "registration_not_allowed", "Registration is not allowed from this address"})
		return
	}
	id := randomID("dep_", 12)
	err := a.store.update(func(d *storeData) error {
		d.Deployments[id] = &deployment{Generation: 1, CreatedAt: time.Now().UTC()}
		return nil
	})
	if err != nil {
		writeError(w, requestID, &apiError{http.StatusInternalServerError, "storage_failed", "The relay could not save the deployment"})
		return
	}
	a.log.Info("deployment registered", "deployment_id", id, "remote", clientIP(r, a.cfg.TrustProxy))
	writeJSON(w, http.StatusOK, a.issue(requestID, id, 1))
}

// handleAdvance serves renew and rotate: both move the deployment to its next
// generation and return a fresh capability. A rotation repeated with the same
// Idempotency-Key gets the first answer again.
func (a *app) handleAdvance(rotate bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID := requestIDOf(r)
		key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if rotate && key != "" {
			claims, _ := parseCapability(a.cfg.CapabilitySecret, bearer(r))
			var replay *credentialResponse
			a.store.read(func(d *storeData) {
				if dep := d.Deployments[claims.DeploymentID]; dep != nil && dep.LastRotationKey == key {
					replay = dep.LastRotation
				}
			})
			if replay != nil {
				writeJSON(w, http.StatusOK, replay)
				return
			}
		}
		claims, apiErr := a.authorize(r, true)
		if apiErr != nil {
			writeError(w, requestID, apiErr)
			return
		}
		var resp credentialResponse
		err := a.store.update(func(d *storeData) error {
			dep := d.Deployments[claims.DeploymentID]
			dep.Generation++
			resp = a.issue(requestID, claims.DeploymentID, dep.Generation)
			if rotate && key != "" {
				dep.LastRotationKey, dep.LastRotation = key, &resp
			}
			return nil
		})
		if err != nil {
			writeError(w, requestID, &apiError{http.StatusInternalServerError, "storage_failed", "The relay could not save the deployment"})
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}
