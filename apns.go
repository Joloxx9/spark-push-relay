package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// apnsClient sends with token-based APNs auth: an ES256 JWT signed with the
// team's .p8 key, refreshed every 40 minutes (Apple allows 20 to 60).
type apnsClient struct {
	key    *ecdsa.PrivateKey
	keyID  string
	teamID string
	http   *http.Client

	mu       sync.Mutex
	jwt      string
	issuedAt time.Time
}

func newAPNsClient(path, keyID, teamID string) (*apnsClient, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("APNs key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("APNs key is not an EC key")
	}
	return &apnsClient{key: key, keyID: keyID, teamID: teamID, http: &http.Client{Timeout: 10 * time.Second}}, nil
}

func (c *apnsClient) token() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.jwt != "" && time.Since(c.issuedAt) < 40*time.Minute {
		return c.jwt, nil
	}
	enc := base64.RawURLEncoding
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": c.keyID})
	now := time.Now()
	claims, _ := json.Marshal(map[string]any{"iss": c.teamID, "iat": now.Unix()})
	signing := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, c.key, digest[:])
	if err != nil {
		return "", err
	}
	sig := append(pad32(r), pad32(s)...)
	c.jwt, c.issuedAt = signing+"."+enc.EncodeToString(sig), now
	return c.jwt, nil
}

func pad32(n *big.Int) []byte {
	out := make([]byte, 32)
	b := n.Bytes()
	copy(out[32-len(b):], b)
	return out
}

type apnsResult struct {
	Status     int
	APNsID     string
	Reason     string
	RetryAfter string
}

func (c *apnsClient) send(req appleSendRequest, alertTitle, alertBody string) (apnsResult, error) {
	payload := map[string]any{
		"aps": map[string]any{
			"alert":           map[string]string{"title": alertTitle, "body": alertBody},
			"sound":           "default",
			"mutable-content": 1,
		},
		"silo_delivery_id": req.DeliveryID,
		"silo_mode":        req.Mode,
	}
	if req.ServerID != "" {
		payload["silo_server_id"] = req.ServerID
		payload["silo_profile_id"] = req.ProfileID
	}
	body, _ := json.Marshal(payload)
	host := "https://api.push.apple.com"
	if req.Environment == "development" || req.Environment == "sandbox" {
		host = "https://api.sandbox.push.apple.com"
	}
	httpReq, err := http.NewRequest(http.MethodPost, host+"/3/device/"+req.Token, bytes.NewReader(body))
	if err != nil {
		return apnsResult{}, err
	}
	jwt, err := c.token()
	if err != nil {
		return apnsResult{}, err
	}
	httpReq.Header.Set("authorization", "bearer "+jwt)
	httpReq.Header.Set("apns-topic", req.Topic)
	httpReq.Header.Set("apns-push-type", "alert")
	httpReq.Header.Set("apns-priority", "10")
	httpReq.Header.Set("apns-expiration", fmt.Sprint(time.Now().Add(24*time.Hour).Unix()))
	if req.CollapseID != nil && *req.CollapseID != "" {
		collapse := *req.CollapseID
		if len(collapse) > 64 {
			collapse = collapse[:64]
		}
		httpReq.Header.Set("apns-collapse-id", collapse)
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return apnsResult{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var parsed struct {
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(data, &parsed)
	return apnsResult{
		Status:     resp.StatusCode,
		APNsID:     resp.Header.Get("apns-id"),
		Reason:     strings.TrimSpace(parsed.Reason),
		RetryAfter: resp.Header.Get("Retry-After"),
	}, nil
}
