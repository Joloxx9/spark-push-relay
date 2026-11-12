package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func newTestApp(t *testing.T) (*app, *httptest.Server) {
	t.Helper()
	st, err := openStore(filepath.Join(t.TempDir(), "relay.json"))
	if err != nil {
		t.Fatal(err)
	}
	a := &app{cfg: config{CapabilitySecret: bytes.Repeat([]byte("k"), 48), APNsTopics: []string{"com.joloxx9.spark"}},
		store: st, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	srv := httptest.NewServer(a.routes())
	t.Cleanup(srv.Close)
	return a, srv
}

func post(t *testing.T, url, auth, idem string, body any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	if idem != "" {
		req.Header.Set("Idempotency-Key", idem)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func errCode(out map[string]any) string {
	e, _ := out["error"].(map[string]any)
	code, _ := e["code"].(string)
	return code
}

// The credential lifecycle the Silo server drives: register, renew, rotate
// (replayed under one key), and an old generation refused as superseded.
func TestCredentialLifecycle(t *testing.T) {
	_, srv := newTestApp(t)
	status, reg := post(t, srv.URL+"/v1/deployments/register", "", "", struct{}{})
	if status != 200 || reg["deployment_id"] == "" || reg["expires_at"] == "" {
		t.Fatalf("register %d %v", status, reg)
	}
	first := reg["api_key"].(string)
	status, renewed := post(t, srv.URL+"/v1/deployments/renew", first, "", struct{}{})
	if status != 200 || renewed["deployment_id"] != reg["deployment_id"] {
		t.Fatalf("renew %d %v", status, renewed)
	}
	second := renewed["api_key"].(string)
	if status, out := post(t, srv.URL+"/v1/deployments/renew", first, "", struct{}{}); status != 401 || errCode(out) != "capability_superseded" {
		t.Fatalf("old generation %d %v", status, out)
	}
	_, rot1 := post(t, srv.URL+"/v1/deployments/rotate", second, "rot-1", struct{}{})
	_, rot2 := post(t, srv.URL+"/v1/deployments/rotate", second, "rot-1", struct{}{})
	if rot1["api_key"] == nil || rot1["api_key"] != rot2["api_key"] {
		t.Fatalf("rotation not replayed: %v / %v", rot1, rot2)
	}
}

// A field the relay does not know is refused the way the server's fallback
// expects; a topic the relay does not serve fails without a retry.
func TestSendValidation(t *testing.T) {
	_, srv := newTestApp(t)
	_, reg := post(t, srv.URL+"/v1/deployments/register", "", "", struct{}{})
	key := reg["api_key"].(string)
	status, out := post(t, srv.URL+"/v1/apple/send", key, "a1", map[string]any{"token": "t", "topic": "com.joloxx9.spark", "mode": "private_alert", "delivery_id": "d", "extra": 1})
	if status != 400 || errCode(out) != "unexpected_field" || errCode(out) == "" {
		t.Fatalf("unexpected field %d %v", status, out)
	}
	status, out = post(t, srv.URL+"/v1/apple/send", key, "a2", map[string]any{"token": "t", "environment": "production", "topic": "org.example.other", "mode": "private_alert", "server_device_id": "s", "delivery_id": "d", "server_id": "srv", "profile_id": "p"})
	if status != 422 || errCode(out) != "topic_not_allowed" {
		t.Fatalf("topic %d %v", status, out)
	}
	if status, out := post(t, srv.URL+"/v1/fcm/send", "sk_bogus.sig", "a3", map[string]any{}); status != 401 || errCode(out) != "invalid_token" {
		t.Fatalf("bad token %d %v", status, out)
	}
}
