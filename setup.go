package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type setupCapability struct {
	Status      string `json:"status"`
	StatusLabel string `json:"status_label,omitempty"`
}
type setupAttempt struct {
	AttemptID        string  `json:"attempt_id"`
	AuthorizationURL string  `json:"authorization_url"`
	Instructions     string  `json:"instructions"`
	ExpiresAt        float64 `json:"expires_at"`
}
type boundSetup struct {
	Backend, CSRF string
	Expires       time.Time
}

func safeLoginURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil
}

func (g *gateway) handleSetup(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	s := g.requireAdmin(w, r)
	if s == nil {
		return
	}
	u := g.upstreamFromPath(w, r)
	if u == nil {
		return
	}
	doc, err := g.loadConfig(r.Context(), u)
	if err != nil || doc.Setup == nil {
		g.renderError(w, "Setup unavailable", "This server does not support login.")
		return
	}
	action := r.PathValue("action")
	if action != "start" && action != "complete" && action != "cancel" {
		http.NotFound(w, r)
		return
	}
	var attempt setupAttempt
	msg, errMsg := "", ""
	body := map[string]string{}
	if action != "start" {
		id := r.PostFormValue("attempt_id")
		g.mu.Lock()
		binding, exists := g.setupAttempts.Load(u.Name + ":" + id)
		b, valid := binding.(boundSetup)
		if !exists || !valid || b.Backend != u.Name || b.CSRF != s.CSRF || time.Now().After(b.Expires) {
			g.mu.Unlock()
			g.renderError(w, "Invalid login attempt", "Start login again in this browser session.")
			return
		}
		g.setupAttempts.Delete(u.Name + ":" + id)
		g.mu.Unlock()
		body["attempt_id"] = id
		if action == "complete" {
			body["input"] = r.PostFormValue("input")
		}
	}
	data, _ := json.Marshal(body)
	if action == "start" {
		_, err = g.upstreamCall(r.Context(), u, "POST", "/setup/start", bytes.NewReader(data), &attempt)
		if err == nil && (attempt.AttemptID == "" || !safeLoginURL(attempt.AuthorizationURL) || attempt.ExpiresAt <= float64(time.Now().Unix()) || attempt.ExpiresAt > float64(time.Now().Add(10*time.Minute+time.Second).Unix())) {
			errMsg = "Server returned an invalid login attempt."
			attempt = setupAttempt{}
		}
		if err == nil && errMsg == "" {
			// Bind each attempt to its admin session and backend; never trust a form alone.
			g.setupAttempts.Range(func(k, v any) bool {
				if time.Now().After(v.(boundSetup).Expires) {
					g.setupAttempts.Delete(k)
				}
				return true
			})
			g.setupAttempts.Store(u.Name+":"+attempt.AttemptID, boundSetup{u.Name, s.CSRF, time.Unix(int64(attempt.ExpiresAt), 0)})
		}
	} else {
		var result health
		_, err = g.upstreamCall(r.Context(), u, "POST", "/setup/"+action, bytes.NewReader(data), &result)
		if err == nil {
			if action == "cancel" {
				msg = "Login cancelled."
			} else if result.OK {
				msg = "Connected."
			} else {
				msg = "Login submitted. Use Test to verify the connection; tokens may already be saved."
			}
		}
	}
	if updated, loadErr := g.loadConfig(r.Context(), u); loadErr == nil {
		doc = updated
	}
	// Do not render upstream errors: they could contain pasted return data.
	if err != nil {
		attempt = setupAttempt{}
		errMsg = "Login failed. Check the settings and start again."
	}
	g.render(w, "upstream", page{Title: u.Name, Upstream: u.Name, CSRF: s.CSRF, Config: doc, Setup: &attempt, Message: msg, Error: errMsg, MCPURL: strings.TrimRight(g.base(r), "/") + "/" + u.Name + "/mcp"})
}
