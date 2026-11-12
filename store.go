package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// deployment is one Spark server registered with this relay. Its generation
// rises on every renewal or rotation; a capability naming an older generation
// is superseded, which makes a copied credential (a database clone, say)
// register a deployment of its own instead of sharing one.
type deployment struct {
	Generation int       `json:"generation"`
	Disabled   bool      `json:"disabled,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	// LastRotationKey and LastRotation replay a repeated rotation request.
	LastRotationKey string              `json:"last_rotation_key,omitempty"`
	LastRotation    *credentialResponse `json:"last_rotation,omitempty"`
}

// idempotencyRecord is a finished send, kept for a day so a server's retry of
// the same attempt is answered without pushing again.
type idempotencyRecord struct {
	PayloadHash string    `json:"payload_hash"`
	Status      int       `json:"status"`
	Body        []byte    `json:"body"`
	At          time.Time `json:"at"`
}

// forwardCredential is this relay's own registration with the official Silo
// relay, used for the official apps' pushes.
type forwardCredential struct {
	DeploymentID string    `json:"deployment_id"`
	APIKey       string    `json:"api_key"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type storeData struct {
	Deployments map[string]*deployment        `json:"deployments"`
	Idempotency map[string]*idempotencyRecord `json:"idempotency"`
	Forward     *forwardCredential            `json:"forward,omitempty"`
}

// store keeps the relay's state in one JSON file, rewritten atomically. The
// relay is a single small process, so this is all the database it needs.
type store struct {
	mu   sync.Mutex
	path string
	data storeData
}

const idempotencyTTL = 24 * time.Hour

func openStore(path string) (*store, error) {
	s := &store{path: path, data: storeData{
		Deployments: map[string]*deployment{},
		Idempotency: map[string]*idempotencyRecord{},
	}}
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s, s.saveLocked()
	case err != nil:
		return nil, err
	}
	if err := json.Unmarshal(raw, &s.data); err != nil {
		return nil, err
	}
	if s.data.Deployments == nil {
		s.data.Deployments = map[string]*deployment{}
	}
	if s.data.Idempotency == nil {
		s.data.Idempotency = map[string]*idempotencyRecord{}
	}
	return s, nil
}

// update runs fn under the lock and persists the result when fn succeeds.
func (s *store) update(fn func(d *storeData) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(&s.data); err != nil {
		return err
	}
	return s.saveLocked()
}

func (s *store) read(fn func(d *storeData)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.data)
}

func (s *store) saveLocked() error {
	now := time.Now()
	for key, record := range s.data.Idempotency {
		if now.Sub(record.At) > idempotencyTTL {
			delete(s.data.Idempotency, key)
		}
	}
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
