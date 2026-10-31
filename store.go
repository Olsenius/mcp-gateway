package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type client struct {
	ID           string    `json:"id"`
	Name         string    `json:"name,omitempty"`
	RedirectURIs []string  `json:"redirect_uris"`
	SecretHash   string    `json:"secret_hash,omitempty"`
	Manual       bool      `json:"manual,omitempty"` // made on the admin page
	Created      time.Time `json:"created"`
	LastUsed     time.Time `json:"last_used,omitempty"`
}

// grant is a refresh token or a personal access token, stored hashed.
type grant struct {
	Hash     string    `json:"hash"`
	Kind     string    `json:"kind"` // "refresh" or "personal"
	ClientID string    `json:"client_id,omitempty"`
	Name     string    `json:"name,omitempty"`
	Resource string    `json:"resource"` // upstream name, or "*" for all
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires,omitempty"` // zero = never
}

type persisted struct {
	Clients map[string]*client `json:"clients"`
	Grants  []grant            `json:"grants"`
}

// store keeps gateway state in DATA_DIR/gateway.json (mode 0600).
type store struct {
	mu   sync.Mutex
	path string
	st   persisted
}

func openStore(dir string, log *slog.Logger) *store {
	s := &store{st: persisted{Clients: map[string]*client{}}}
	if dir == "" {
		log.Warn("DATA_DIR is empty: clients and tokens are lost on restart")
		return s
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Warn("data dir not usable: clients and tokens are lost on restart", "dir", dir, "err", err)
		return s
	}
	s.path = filepath.Join(dir, "gateway.json")
	data, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		log.Warn("could not read state", "err", err)
	default:
		if err := json.Unmarshal(data, &s.st); err != nil {
			log.Warn("state file is corrupt, starting empty", "err", err)
		}
	}
	if s.st.Clients == nil {
		s.st.Clients = map[string]*client{}
	}
	return s
}

func (s *store) update(fn func(*persisted)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.st)
	now := time.Now()
	kept := s.st.Grants[:0]
	for _, g := range s.st.Grants {
		if g.Expires.IsZero() || g.Expires.After(now) {
			kept = append(kept, g)
		}
	}
	s.st.Grants = kept
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("save state: %w", err)
	}
	return os.Rename(tmp, s.path)
}

func (s *store) read(fn func(*persisted)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.st)
}

// ---------- secrets ----------

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func constEq(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
