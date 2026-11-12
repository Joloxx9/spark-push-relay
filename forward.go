package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"
)

// forwarder hands the official Silo apps' pushes to the official Silo relay.
// The device tokens of those apps belong to Silo's APNs topic, which only
// that relay can push to. This relay registers there as one deployment of its
// own, the same way a Silo server does, and keeps that credential fresh.
type forwarder struct {
	baseURL string
	store   *store
	http    *http.Client
	mu      sync.Mutex
}

type forwardResponse struct {
	Status     int
	Body       []byte
	RetryAfter string
}

func (f *forwarder) credential(force bool) (*forwardCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var current *forwardCredential
	f.store.read(func(d *storeData) { current = d.Forward })
	if current != nil && !force {
		if time.Until(current.ExpiresAt) > 7*24*time.Hour {
			return current, nil
		}
		if renewed, err := f.request("/v1/deployments/renew", current.APIKey); err == nil {
			return renewed, nil
		}
	}
	return f.request("/v1/deployments/register", "")
}

func (f *forwarder) request(path, capability string) (*forwardCredential, error) {
	req, err := http.NewRequest(http.MethodPost, f.baseURL+path, bytes.NewReader([]byte("{}")))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Spark-Push-Relay/1.0")
	if capability != "" {
		req.Header.Set("Authorization", "Bearer "+capability)
	}
	resp, err := f.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("official relay refused " + path + ": " + resp.Status)
	}
	var parsed credentialResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&parsed); err != nil {
		return nil, err
	}
	expires, err := time.Parse(time.RFC3339, parsed.ExpiresAt)
	if err != nil || parsed.APIKey == "" {
		return nil, errors.New("official relay returned an incomplete credential")
	}
	cred := &forwardCredential{DeploymentID: parsed.DeploymentID, APIKey: parsed.APIKey, ExpiresAt: expires}
	if err := f.store.update(func(d *storeData) error { d.Forward = cred; return nil }); err != nil {
		return nil, err
	}
	return cred, nil
}

// send posts one Apple push to the official relay. The idempotency key is
// derived from the caller's deployment and key, so two Spark servers never
// share one and a retry of the same attempt keeps its key.
func (f *forwarder) send(body []byte, deploymentID, idempotencyKey string) (forwardResponse, error) {
	digest := sha256.Sum256([]byte(deploymentID + "\x00" + idempotencyKey))
	key := "spark-" + hex.EncodeToString(digest[:16])
	for attempt := 0; attempt < 2; attempt++ {
		cred, err := f.credential(attempt > 0)
		if err != nil {
			return forwardResponse{}, err
		}
		req, err := http.NewRequest(http.MethodPost, f.baseURL+"/v1/apple/send", bytes.NewReader(body))
		if err != nil {
			return forwardResponse{}, err
		}
		req.Header.Set("Authorization", "Bearer "+cred.APIKey)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Spark-Push-Relay/1.0")
		req.Header.Set("Idempotency-Key", key)
		resp, err := f.http.Do(req)
		if err != nil {
			return forwardResponse{}, err
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			continue // register a fresh forwarding deployment and try once more
		}
		return forwardResponse{Status: resp.StatusCode, Body: data, RetryAfter: resp.Header.Get("Retry-After")}, nil
	}
	return forwardResponse{}, errors.New("official relay rejected a fresh credential")
}
