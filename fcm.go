package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// fcmClient sends data-only messages through FCM HTTP v1 with a Google
// service account of the Firebase project that holds the Spark Android app.
type fcmClient struct {
	projectID   string
	clientEmail string
	tokenURI    string
	key         *rsa.PrivateKey
	http        *http.Client

	mu          sync.Mutex
	accessToken string
	expiresAt   time.Time
}

func newFCMClient(path string) (*fcmClient, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var account struct {
		ProjectID   string `json:"project_id"`
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
		TokenURI    string `json:"token_uri"`
	}
	if err := json.Unmarshal(raw, &account); err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(account.PrivateKey))
	if block == nil {
		return nil, errors.New("service account private_key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("service account key is not RSA")
	}
	if account.TokenURI == "" {
		account.TokenURI = "https://oauth2.googleapis.com/token"
	}
	return &fcmClient{
		projectID: account.ProjectID, clientEmail: account.ClientEmail, tokenURI: account.TokenURI,
		key: key, http: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (c *fcmClient) token() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.accessToken != "" && time.Until(c.expiresAt) > 5*time.Minute {
		return c.accessToken, nil
	}
	enc := base64.RawURLEncoding
	now := time.Now()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iss":   c.clientEmail,
		"scope": "https://www.googleapis.com/auth/firebase.messaging",
		"aud":   c.tokenURI,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	})
	signing := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {signing + "." + enc.EncodeToString(sig)},
	}
	resp, err := c.http.PostForm(c.tokenURI, form)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	var parsed struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&parsed); err != nil || parsed.AccessToken == "" {
		return "", fmt.Errorf("google token exchange failed: HTTP %d", resp.StatusCode)
	}
	c.accessToken, c.expiresAt = parsed.AccessToken, now.Add(time.Duration(parsed.ExpiresIn)*time.Second)
	return c.accessToken, nil
}

type fcmResult struct {
	Status     int
	Name       string
	ErrorCode  string
	RetryAfter string
}

func (c *fcmClient) send(req fcmSendRequest, alertTitle, alertBody string) (fcmResult, error) {
	data := map[string]string{
		"silo_delivery_id": req.DeliveryID,
		"silo_mode":        req.Mode,
		"title":            alertTitle,
		"body":             alertBody,
	}
	if req.ServerID != "" {
		data["silo_server_id"] = req.ServerID
		data["silo_profile_id"] = req.ProfileID
	}
	android := map[string]any{"priority": "HIGH", "ttl": "86400s"}
	if req.CollapseID != nil && *req.CollapseID != "" {
		android["collapse_key"] = *req.CollapseID
	}
	body, _ := json.Marshal(map[string]any{"message": map[string]any{
		"token": req.Token, "data": data, "android": android,
	}})
	access, err := c.token()
	if err != nil {
		return fcmResult{}, err
	}
	httpReq, err := http.NewRequest(http.MethodPost,
		"https://fcm.googleapis.com/v1/projects/"+url.PathEscape(c.projectID)+"/messages:send", bytes.NewReader(body))
	if err != nil {
		return fcmResult{}, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+access)
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return fcmResult{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	var parsed struct {
		Name  string `json:"name"`
		Error struct {
			Status  string `json:"status"`
			Details []struct {
				ErrorCode string `json:"errorCode"`
			} `json:"details"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &parsed)
	code := parsed.Error.Status
	for _, detail := range parsed.Error.Details {
		if detail.ErrorCode != "" {
			code = detail.ErrorCode
		}
	}
	return fcmResult{Status: resp.StatusCode, Name: parsed.Name, ErrorCode: strings.TrimSpace(code), RetryAfter: resp.Header.Get("Retry-After")}, nil
}
