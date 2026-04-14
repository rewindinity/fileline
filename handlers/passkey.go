package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"fileline/auth"
	"fileline/database"
	"fileline/models"

	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	webAuthn            *webauthn.WebAuthn
	webAuthnMu          sync.RWMutex
	webAuthnRPID        string
	webAuthnRPOrigin    string
	webAuthnDisplayName = "FileLine"

	passkeySessionMu     sync.RWMutex
	passkeyAuthSessionMu sync.RWMutex
)

/*
*

	InitWebAuthn configures the relying-party context used for passkey operations.
	@param rpDisplayName - The relying party display name.
	@param rpID - The relying party identifier.
	@param rpOrigin - The relying party origin URL.
	@returns error - An error if the operation fails.
*/
func InitWebAuthn(rpDisplayName, rpID, rpOrigin string) error {
	webAuthnMu.Lock()
	defer webAuthnMu.Unlock()
	if rpDisplayName != "" {
		webAuthnDisplayName = rpDisplayName
	}
	wconfig := &webauthn.Config{
		RPDisplayName: webAuthnDisplayName,
		RPID:          rpID,
		RPOrigins:     []string{rpOrigin},
	}
	var err error
	webAuthn, err = webauthn.New(wconfig)
	if err == nil {
		webAuthnRPID = rpID
		webAuthnRPOrigin = rpOrigin
	}
	return err
}

func normalizeOriginHost(raw string) string {
	host := strings.TrimSpace(strings.Split(raw, ",")[0])
	if host == "" {
		return ""
	}
	if strings.Contains(host, "://") {
		if parsed, err := url.Parse(host); err == nil && parsed.Host != "" {
			host = parsed.Host
		}
	}
	host = strings.TrimSpace(strings.Split(host, "/")[0])
	return host
}

func hostWithoutPort(host string) string {
	if host == "" {
		return ""
	}
	parsedHost := host
	if strings.Contains(parsedHost, ":") {
		if h, _, err := net.SplitHostPort(parsedHost); err == nil {
			parsedHost = h
		}
	}
	return strings.Trim(parsedHost, "[]")
}

func resolvePasskeyOrigin(r *http.Request) (string, string) {
	host := normalizeOriginHost(r.Host)
	if database.Config.IsBehindProxy {
		if forwardedHost := normalizeOriginHost(r.Header.Get("X-Forwarded-Host")); forwardedHost != "" {
			host = forwardedHost
		}
	}
	if host == "" {
		host = normalizeOriginHost(database.Config.Domain)
	}
	if host == "" {
		host = "localhost"
		if database.Config.Port != 80 && database.Config.Port != 443 {
			host = host + ":" + strconv.Itoa(database.Config.Port)
		}
	}
	scheme := "http"
	if r.TLS != nil || database.Config.SSLEnabled {
		scheme = "https"
	}
	if database.Config.IsBehindProxy {
		if proto := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])); proto == "http" || proto == "https" {
			scheme = proto
		}
	}
	return hostWithoutPort(host), scheme + "://" + host
}

func ensureWebAuthnForRequest(r *http.Request) error {
	rpID, rpOrigin := resolvePasskeyOrigin(r)
	webAuthnMu.RLock()
	current := webAuthn
	currentID := webAuthnRPID
	currentOrigin := webAuthnRPOrigin
	webAuthnMu.RUnlock()
	if current != nil && currentID == rpID && currentOrigin == rpOrigin {
		return nil
	}
	webAuthnMu.Lock()
	defer webAuthnMu.Unlock()
	if webAuthn != nil && webAuthnRPID == rpID && webAuthnRPOrigin == rpOrigin {
		return nil
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: webAuthnDisplayName,
		RPID:          rpID,
		RPOrigins:     []string{rpOrigin},
	})
	if err != nil {
		return err
	}
	webAuthn = wa
	webAuthnRPID = rpID
	webAuthnRPOrigin = rpOrigin
	return nil
}

// WebAuthnUser adapts the persisted user model to the webauthn.User interface.
type WebAuthnUser struct {
	user *models.User
}

/*
*

	WebAuthnID returns a stable user handle for credential binding.
	@param none - This function does not accept parameters.
	@returns []byte - The resulting collection.
*/
func (u WebAuthnUser) WebAuthnID() []byte {
	return []byte(u.user.Username)
}

/*
*

	WebAuthnName returns the account name used by authenticators.
	@param none - This function does not accept parameters.
	@returns string - The resulting string value.
*/
func (u WebAuthnUser) WebAuthnName() string {
	return u.user.Username
}

/*
*

	WebAuthnDisplayName returns a user-facing display label.
	@param none - This function does not accept parameters.
	@returns string - The resulting string value.
*/
func (u WebAuthnUser) WebAuthnDisplayName() string {
	return u.user.Username
}

/*
*

	WebAuthnIcon is unused by this application.
	@param none - This function does not accept parameters.
	@returns string - The resulting string value.
*/
func (u WebAuthnUser) WebAuthnIcon() string {
	return ""
}

/*
*

	WebAuthnCredentials maps persisted passkeys into library credential structs.
	@param none - This function does not accept parameters.
	@returns []webauthn.Credential - The resulting collection.
*/
func (u WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	credentials := make([]webauthn.Credential, len(u.user.Passkeys))
	for i, pk := range u.user.Passkeys {
		credentials[i] = webauthn.Credential{
			ID:              pk.ID,
			PublicKey:       pk.PublicKey,
			AttestationType: pk.AttestationType,
			Authenticator: webauthn.Authenticator{
				AAGUID:    pk.AAGUID,
				SignCount: pk.SignCount,
			},
			Flags: webauthn.CredentialFlags{
				BackupEligible: pk.BackupEligible,
				BackupState:    pk.BackupState,
			},
		}
	}
	return credentials
}

/*
*

	HandlePasskeyRegistrationBegin starts the WebAuthn registration ceremony.
	@param w - The HTTP response writer.
	@param r - The incoming HTTP request.
	@returns void
*/
func HandlePasskeyRegistrationBegin(w http.ResponseWriter, r *http.Request) {
	if !CheckDatabaseConnection(w, r) {
		return
	}
	if auth.RequireSetup(w, r) {
		return
	}
	if auth.RequireAuth(w, r) {
		return
	}
	if err := ensureWebAuthnForRequest(r); err != nil {
		http.Error(w, "WebAuthn configuration error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	user := database.GetUser()
	if user == nil {
		http.Error(w, "User not found", http.StatusInternalServerError)
		return
	}
	webAuthnUser := WebAuthnUser{user: user}
	options, sessionData, err := webAuthn.BeginRegistration(webAuthnUser)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Bind WebAuthn ceremony state to the authenticated browser session.
	sessionID := auth.GetSessionCookie(r)
	if sessionID == "" {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}
	// Store session data temporarily (we'll use a simple in-memory map)
	passkeySessionMu.Lock()
	passkeySessionStore[sessionID] = sessionData
	passkeySessionMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

// Temporary in-memory store for passkey registration sessions.
// Sessions are process-local and intentionally short-lived.
var passkeySessionStore = make(map[string]*webauthn.SessionData)

/*
*

	HandlePasskeyRegistrationFinish verifies attestation and persists the new credential.
	@param w - The HTTP response writer.
	@param r - The incoming HTTP request.
	@returns void
*/
func HandlePasskeyRegistrationFinish(w http.ResponseWriter, r *http.Request) {
	if !CheckDatabaseConnection(w, r) {
		return
	}
	if auth.RequireSetup(w, r) {
		return
	}
	if auth.RequireAuth(w, r) {
		return
	}
	if err := ensureWebAuthnForRequest(r); err != nil {
		http.Error(w, "WebAuthn configuration error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	user := database.GetUser()
	if user == nil {
		http.Error(w, "User not found", http.StatusInternalServerError)
		return
	}
	sessionID := auth.GetSessionCookie(r)
	passkeySessionMu.RLock()
	sessionData, ok := passkeySessionStore[sessionID]
	passkeySessionMu.RUnlock()
	if !ok {
		http.Error(w, "Session not found", http.StatusBadRequest)
		return
	}
	defer func() {
		passkeySessionMu.Lock()
		delete(passkeySessionStore, sessionID)
		passkeySessionMu.Unlock()
	}()
	webAuthnUser := WebAuthnUser{user: user}
	credential, err := webAuthn.FinishRegistration(webAuthnUser, *sessionData, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Provide a deterministic fallback display name; user can rename later.
	passkeyName := "Passkey " + time.Now().Format("2006-01-02 15:04")
	// Add passkey to user
	newPasskey := models.Passkey{
		ID:              credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		AAGUID:          credential.Authenticator.AAGUID,
		SignCount:       credential.Authenticator.SignCount,
		BackupEligible:  credential.Flags.BackupEligible,
		BackupState:     credential.Flags.BackupState,
		Name:            passkeyName,
		CreatedAt:       time.Now().Format(time.RFC3339),
	}
	user.Passkeys = append(user.Passkeys, newPasskey)
	database.SetUser(user)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"success": "true"})
}

/*
*

	HandlePasskeyAuthBegin starts the WebAuthn authentication ceremony.
	@param w - The HTTP response writer.
	@param r - The incoming HTTP request.
	@returns void
*/
func HandlePasskeyAuthBegin(w http.ResponseWriter, r *http.Request) {
	if !CheckDatabaseConnection(w, r) {
		return
	}
	if auth.RequireSetup(w, r) {
		return
	}
	if err := ensureWebAuthnForRequest(r); err != nil {
		http.Error(w, "WebAuthn configuration error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	user := database.GetUser()
	if user == nil || len(user.Passkeys) == 0 {
		http.Error(w, "No passkeys registered", http.StatusBadRequest)
		return
	}
	webAuthnUser := WebAuthnUser{user: user}
	options, sessionData, err := webAuthn.BeginLogin(webAuthnUser)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Store ceremony state server-side and return a lookup key to the client.
	tempSessionID := GenerateID() + GenerateID()
	passkeyAuthSessionMu.Lock()
	passkeyAuthSessionStore[tempSessionID] = sessionData
	passkeyAuthSessionMu.Unlock()
	// Return both options and session ID
	response := map[string]interface{}{
		"options":   options,
		"sessionId": tempSessionID,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Temporary in-memory store for passkey auth sessions.
// Sessions are process-local and intentionally short-lived.
var passkeyAuthSessionStore = make(map[string]*webauthn.SessionData)

/*
*

	HandlePasskeyAuthFinish verifies assertion data and creates an application session.
	@param w - The HTTP response writer.
	@param r - The incoming HTTP request.
	@returns void
*/
func HandlePasskeyAuthFinish(w http.ResponseWriter, r *http.Request) {
	if !CheckDatabaseConnection(w, r) {
		return
	}
	if auth.RequireSetup(w, r) {
		return
	}
	if err := ensureWebAuthnForRequest(r); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "WebAuthn configuration error: " + err.Error()})
		return
	}
	// Get session ID from request
	sessionIDParam := r.URL.Query().Get("sessionId")
	if sessionIDParam == "" {
		http.Error(w, `{"error":"Session ID required"}`, http.StatusBadRequest)
		return
	}
	passkeyAuthSessionMu.RLock()
	sessionData, ok := passkeyAuthSessionStore[sessionIDParam]
	passkeyAuthSessionMu.RUnlock()
	if !ok {
		http.Error(w, `{"error":"Session not found"}`, http.StatusBadRequest)
		return
	}
	defer func() {
		passkeyAuthSessionMu.Lock()
		delete(passkeyAuthSessionStore, sessionIDParam)
		passkeyAuthSessionMu.Unlock()
	}()
	user := database.GetUser()
	if user == nil {
		http.Error(w, `{"error":"User not found"}`, http.StatusInternalServerError)
		return
	}
	webAuthnUser := WebAuthnUser{user: user}
	credential, err := webAuthn.FinishLogin(webAuthnUser, *sessionData, r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	// Persist authenticator metadata updates to support replay protection.
	for i := range user.Passkeys {
		if bytes.Equal(user.Passkeys[i].ID, credential.ID) {
			user.Passkeys[i].SignCount = credential.Authenticator.SignCount
			user.Passkeys[i].BackupEligible = credential.Flags.BackupEligible
			user.Passkeys[i].BackupState = credential.Flags.BackupState
			break
		}
	}
	database.SetUser(user)
	// Create session
	sessionID := auth.Store.Create(user.Username, false)
	auth.SetSessionCookie(w, sessionID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"success": "true", "redirect": "/"})
}

/*
*

	HandlePasskeyDelete removes one registered passkey from the user account.
	@param w - The HTTP response writer.
	@param r - The incoming HTTP request.
	@returns void
*/
func HandlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	if !CheckDatabaseConnection(w, r) {
		return
	}
	if auth.RequireSetup(w, r) {
		return
	}
	if auth.RequireAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	passkeyID := r.FormValue("id")
	if passkeyID == "" {
		http.Error(w, "Passkey ID required", http.StatusBadRequest)
		return
	}
	// Decode base64url ID
	passkeyIDBytes, err := base64.RawURLEncoding.DecodeString(passkeyID)
	if err != nil {
		http.Error(w, "Invalid passkey ID", http.StatusBadRequest)
		return
	}
	user := database.GetUser()
	if user == nil {
		http.Error(w, "User not found", http.StatusInternalServerError)
		return
	}
	// Find and remove the passkey
	newPasskeys := []models.Passkey{}
	found := false
	for _, pk := range user.Passkeys {
		if !bytes.Equal(pk.ID, passkeyIDBytes) {
			newPasskeys = append(newPasskeys, pk)
		} else {
			found = true
		}
	}
	if !found {
		http.Error(w, "Passkey not found", http.StatusNotFound)
		return
	}
	user.Passkeys = newPasskeys
	database.SetUser(user)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"success": "true"})
}

/*
*

	HandlePasskeyList returns passkey metadata safe for UI display.
	@param w - The HTTP response writer.
	@param r - The incoming HTTP request.
	@returns void
*/
func HandlePasskeyList(w http.ResponseWriter, r *http.Request) {
	if !CheckDatabaseConnection(w, r) {
		return
	}
	if auth.RequireSetup(w, r) {
		return
	}
	if auth.RequireAuth(w, r) {
		return
	}
	user := database.GetUser()
	if user == nil {
		http.Error(w, "User not found", http.StatusInternalServerError)
		return
	}
	// Return passkey info (without private keys)
	type PasskeyInfo struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		CreatedAt string `json:"created_at"`
	}
	passkeys := make([]PasskeyInfo, len(user.Passkeys))
	for i, pk := range user.Passkeys {
		passkeys[i] = PasskeyInfo{
			ID:        base64.RawURLEncoding.EncodeToString(pk.ID),
			Name:      pk.Name,
			CreatedAt: pk.CreatedAt,
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(passkeys)
}
