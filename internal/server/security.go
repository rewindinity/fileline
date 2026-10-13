package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"fileline/internal/auth"
	"fileline/internal/db"
	"fileline/internal/logger"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp/totp"
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
		s.internalError(w, r, "Failed to generate 2FA TOTP secret", err)
		return
	}
	// Save temporary
	s.totpTempStore.Store(username, key.Secret())
	logger.Action("User '%s' requested new 2FA TOTP secret generation", username)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"secret": key.Secret(),
		"url":    key.URL(),
	})
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
		logger.Action("User '%s' entered invalid 2FA code during setup", username)
		http.Redirect(w, r, "/settings/account?error=Invalid+code", http.StatusFound)
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
	logger.Action("User '%s' successfully enabled 2FA TOTP", username)
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
		logger.Action("User '%s' entered invalid 2FA code when attempting to disable 2FA", username)
		http.Redirect(w, r, "/settings/account?error=Invalid+2FA+code", http.StatusFound)
		return
	}
	if err := db.UpdateUserAuthData(r.Context(), database, username, "", user.WebAuthnData); err != nil {
		s.internalError(w, r, "Failed to disable 2FA in database", err)
		return
	}
	logger.Action("User '%s' disabled 2FA TOTP", username)
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
		s.internalError(w, r, "WebAuthn BeginRegistration failed", err)
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
	passkeyName := strings.TrimSpace(r.URL.Query().Get("name"))
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
		s.internalError(w, r, "Failed to save credential to database", err)
		return
	}
	s.webAuthnTempStore.Delete(cookie.Value)
	logger.Action("User '%s' registered new passkey credential '%s'", username, passkeyName)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) webAuthnRenameHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings/account", http.StatusSeeOther)
		return
	}
	username := r.Context().Value("username").(string)

	var idToRename, newName string
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var reqData struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&reqData); err == nil {
			idToRename = reqData.ID
			newName = strings.TrimSpace(reqData.Name)
		}
	} else {
		idToRename = r.FormValue("id")
		newName = strings.TrimSpace(r.FormValue("name"))
	}

	isJSON := strings.Contains(r.Header.Get("Accept"), "application/json")

	if idToRename == "" {
		if isJSON {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "Missing passkey id"}`))
			return
		}
		http.Redirect(w, r, "/settings/account?error=Missing+passkey+id", http.StatusFound)
		return
	}

	if newName == "" {
		newName = "Passkey " + time.Now().Format("2006-01-02 15:04")
	}

	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()

	user, err := db.GetUserByUsername(r.Context(), database, username)
	if err != nil || user.WebAuthnData == "" {
		if isJSON {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error": "User or passkeys not found"}`))
			return
		}
		http.Redirect(w, r, "/settings/account?error=User+or+passkeys+not+found", http.StatusFound)
		return
	}

	var passkeys []auth.Passkey
	if err := json.Unmarshal([]byte(user.WebAuthnData), &passkeys); err != nil {
		if isJSON {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error": "Failed to parse passkeys"}`))
			return
		}
		http.Redirect(w, r, "/settings/account?error=Failed+to+parse+passkeys", http.StatusFound)
		return
	}

	renamed := false
	for i := range passkeys {
		encodedID := base64.URLEncoding.EncodeToString(passkeys[i].Credential.ID)
		if encodedID == idToRename {
			passkeys[i].Name = newName
			renamed = true
			break
		}
	}

	if !renamed {
		if isJSON {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error": "Passkey not found"}`))
			return
		}
		http.Redirect(w, r, "/settings/account?error=Passkey+not+found", http.StatusFound)
		return
	}

	updatedJSON, err := json.Marshal(passkeys)
	if err != nil {
		s.internalError(w, r, "Failed to encode updated passkeys", err)
		return
	}

	if err := db.UpdateUserAuthData(r.Context(), database, username, user.TOTPSecret, string(updatedJSON)); err != nil {
		s.internalError(w, r, "Failed to update passkey name in database", err)
		return
	}

	logger.Action("User '%s' renamed passkey id '%s' to '%s'", username, idToRename, newName)

	if isJSON {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "ok",
			"name":   newName,
		})
		return
	}
	http.Redirect(w, r, "/settings/account?success=Passkey+renamed+successfully", http.StatusFound)
}

func (s *Server) webAuthnDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	username := r.Context().Value("username").(string)

	var idToDelete string
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var reqData struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&reqData); err == nil {
			idToDelete = reqData.ID
		}
	} else {
		idToDelete = r.FormValue("id")
	}

	isJSON := strings.Contains(r.Header.Get("Accept"), "application/json")

	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()

	user, err := db.GetUserByUsername(r.Context(), database, username)
	if err != nil || user.WebAuthnData == "" {
		if isJSON {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error": "User or passkeys not found"}`))
			return
		}
		http.Redirect(w, r, "/settings/account?error=User+or+passkeys+not+found", http.StatusFound)
		return
	}
	var passkeys []auth.Passkey
	if err := json.Unmarshal([]byte(user.WebAuthnData), &passkeys); err != nil {
		if isJSON {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error": "Failed to parse passkeys"}`))
			return
		}
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
		if isJSON {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error": "Passkey not found"}`))
			return
		}
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
		s.internalError(w, r, "Failed to delete passkey in database", err)
		return
	}
	logger.Action("User '%s' deleted passkey id '%s'", username, idToDelete)

	if isJSON {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
		return
	}
	http.Redirect(w, r, "/settings/account?success=Passkey+deleted+successfully", http.StatusFound)
}
