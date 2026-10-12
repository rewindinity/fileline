package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"fileline/internal/auth"
	"fileline/internal/db"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
)

// formatPasskeysDisplay transforms stored JSON passkeys into a display-friendly slice
func formatPasskeysDisplay(webAuthnData string) []map[string]interface{} {
	var passkeys []auth.Passkey
	if webAuthnData != "" {
		_ = json.Unmarshal([]byte(webAuthnData), &passkeys)
	}
	var passkeysDisplay []map[string]interface{}
	for i, pk := range passkeys {
		name := pk.Name
		if name == "" {
			name = fmt.Sprintf("Passkey %d", i+1)
		}
		passkeysDisplay = append(passkeysDisplay, map[string]interface{}{
			"Index": i + 1,
			"Name":  name,
			"ID":    base64.URLEncoding.EncodeToString(pk.Credential.ID),
		})
	}
	return passkeysDisplay
}

func (s *Server) settingsAccountHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)
	s.mu.RLock()
	cfg := s.cfg
	database := s.db
	s.mu.RUnlock()
	user, _ := db.GetUserByUsername(r.Context(), database, username)
	passkeysDisplay := formatPasskeysDisplay(user.WebAuthnData)
	successMsg := r.URL.Query().Get("success")
	errorMsg := r.URL.Query().Get("error")
	s.renderTemplate(w, r, "settings_account.html", map[string]interface{}{
		"Title":          "Account Settings",
		"Username":       username,
		"User":           user,
		"Config":         cfg,
		"Passkeys":       passkeysDisplay,
		"SuccessMessage": successMsg,
		"ErrorMessage":   errorMsg,
	})
}

func (s *Server) totpGenerateHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "FileLine",
		AccountName: username,
	})
	if err != nil {
		http.Redirect(w, r, "/settings/account?error=Failed+to+generate+2FA", http.StatusFound)
		return
	}
	// Save temporary
	s.totpTempStore.Store(username, key.Secret())
	// Generate QR Code
	var png []byte
	png, err = qrcode.Encode(key.String(), qrcode.Medium, 256)
	if err != nil {
		http.Redirect(w, r, "/settings/account?error=Failed+to+generate+QR", http.StatusFound)
		return
	}
	qrBase64 := base64.StdEncoding.EncodeToString(png)

	w.Header().Set("Content-Type", "text/html")
	w.Write(fmt.Appendf(nil, `
		<h2>Scan this QR Code</h2>
		<img src="data:image/png;base64,%s" />
		<p>Secret: %s</p>
		<form method="POST" action="/settings/2fa/verify">
			<input type="text" name="code" placeholder="6-digit code" required />
			<button type="submit">Verify & Enable</button>
		</form>
		<a href="/settings">Cancel</a>
	`, qrBase64, key.Secret()))
}

func (s *Server) totpVerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	username := r.Context().Value("username").(string)
	code := r.FormValue("code")
	secretAny, ok := s.totpTempStore.Load(username)
	if !ok {
		http.Redirect(w, r, "/settings/account?error=2FA+session+expired", http.StatusFound)
		return
	}
	secret := secretAny.(string)
	if !totp.Validate(code, secret) {
		http.Redirect(w, r, "/setting/accounts?error=Invalid+code", http.StatusFound)
		return
	}

	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()

	user, err := db.GetUserByUsername(r.Context(), database, username)
	if err == nil {
		db.UpdateUserAuthData(r.Context(), database, username, secret, user.WebAuthnData)
	}
	s.totpTempStore.Delete(username)
	http.Redirect(w, r, "/settings/account?success=2FA+Enabled+Successfully", http.StatusFound)
}

func (s *Server) totpDisableHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	username := r.Context().Value("username").(string)
	code := r.FormValue("code")

	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()

	user, err := db.GetUserByUsername(r.Context(), database, username)
	if err != nil || user.TOTPSecret == "" {
		http.Redirect(w, r, "/settings/account?error=2FA+is+not+enabled", http.StatusFound)
		return
	}
	if !totp.Validate(code, user.TOTPSecret) {
		http.Redirect(w, r, "/settings/account?error=Invalid+2FA+code", http.StatusFound)
		return
	}
	if err := db.UpdateUserAuthData(r.Context(), database, username, "", user.WebAuthnData); err != nil {
		http.Redirect(w, r, "/settings/account?error=Failed+to+disable+2FA", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/settings/account?success=2FA+Disabled+Successfully", http.StatusFound)
}

func (s *Server) webAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)

	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()

	dbUser, err := db.GetUserByUsername(r.Context(), database, username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	user := auth.NewWebAuthnUser(dbUser)
	options, sessionData, err := s.webAuthn.BeginRegistration(
		user,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sessionID := generateRandomSessionID()
	s.webAuthnTempStore.Store(sessionID, *sessionData)
	http.SetCookie(w, &http.Cookie{
		Name:     "wa_session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   300,
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

func (s *Server) webAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)
	cookie, err := r.Cookie("wa_session")
	if err != nil {
		http.Error(w, "Session expired", http.StatusBadRequest)
		return
	}

	sessionDataAny, ok := s.webAuthnTempStore.Load(cookie.Value)
	if !ok {
		http.Error(w, "Session expired", http.StatusBadRequest)
		return
	}
	sessionData := sessionDataAny.(webauthn.SessionData)
	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()
	dbUser, err := db.GetUserByUsername(r.Context(), database, username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	user := auth.NewWebAuthnUser(dbUser)
	credential, err := s.webAuthn.FinishRegistration(user, sessionData, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	passkeyName := r.URL.Query().Get("name")
	if passkeyName == "" {
		passkeyName = "Passkey " + time.Now().Format("2006-01-02 15:04")
	}
	var passkeys []auth.Passkey
	if dbUser.WebAuthnData != "" {
		_ = json.Unmarshal([]byte(dbUser.WebAuthnData), &passkeys)
	}
	newPasskey := auth.Passkey{
		Credential: *credential,
		Name:       passkeyName,
	}
	passkeys = append(passkeys, newPasskey)
	credsJSON, _ := json.Marshal(passkeys)
	if err := db.UpdateUserAuthData(r.Context(), database, username, dbUser.TOTPSecret, string(credsJSON)); err != nil {
		http.Error(w, "Failed to save credential", http.StatusInternalServerError)
		return
	}
	s.webAuthnTempStore.Delete(cookie.Value)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) webAuthnDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	username := r.Context().Value("username").(string)
	idToDelete := r.FormValue("id")

	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()

	user, err := db.GetUserByUsername(r.Context(), database, username)
	if err != nil || user.WebAuthnData == "" {
		http.Redirect(w, r, "/settings/account?error=User+or+passkeys+not+found", http.StatusFound)
		return
	}
	var passkeys []auth.Passkey
	if err := json.Unmarshal([]byte(user.WebAuthnData), &passkeys); err != nil {
		http.Redirect(w, r, "/settings/account?error=Failed+to+parse+passkeys", http.StatusFound)
		return
	}
	var updatedPasskeys []auth.Passkey
	deleted := false
	for _, pk := range passkeys {
		encodedID := base64.URLEncoding.EncodeToString(pk.Credential.ID)
		if encodedID == idToDelete {
			deleted = true
			continue
		}
		updatedPasskeys = append(updatedPasskeys, pk)
	}
	if !deleted {
		http.Redirect(w, r, "/settings/account?error=Passkey+not+found", http.StatusFound)
		return
	}
	var updatedJSON []byte
	if len(updatedPasskeys) > 0 {
		updatedJSON, _ = json.Marshal(updatedPasskeys)
	} else {
		updatedJSON = []byte("[]")
	}
	if err := db.UpdateUserAuthData(r.Context(), database, username, user.TOTPSecret, string(updatedJSON)); err != nil {
		http.Redirect(w, r, "/settings/account?error=Failed+to+delete+passkey", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/settings/account?success=Passkey+deleted+successfully", http.StatusFound)
}
