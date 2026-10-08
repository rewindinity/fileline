package auth

import (
	"encoding/json"
	"fileline/internal/db"
	"fmt"

	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthnUser implements webauthn.User interface
type WebAuthnUser struct {
	dbUser *db.User
}

type Passkey struct {
	Credential webauthn.Credential `json:"credential"`
	Name       string              `json:"name"`
}

func (p *Passkey) UnmarshalJSON(data []byte) error {
	// First try to unmarshal into the new wrapper format
	type Alias Passkey
	var alias Alias
	if err := json.Unmarshal(data, &alias); err == nil && alias.Credential.ID != nil {
		*p = Passkey(alias)
		return nil
	}

	// Fallback to legacy format
	var cred webauthn.Credential
	if err := json.Unmarshal(data, &cred); err != nil {
		return err
	}
	p.Credential = cred

	// Try to extract name from root level if present
	var root struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(data, &root); err == nil && root.Name != "" {
		p.Name = root.Name
	}

	return nil
}

func NewWebAuthnUser(u *db.User) *WebAuthnUser {
	return &WebAuthnUser{dbUser: u}
}

func (u *WebAuthnUser) WebAuthnID() []byte {
	return []byte(fmt.Sprintf("%d", u.dbUser.ID))
}

func (u *WebAuthnUser) WebAuthnName() string {
	return u.dbUser.Username
}

func (u *WebAuthnUser) WebAuthnDisplayName() string {
	return u.dbUser.Username
}

func (u *WebAuthnUser) WebAuthnIcon() string {
	return ""
}

func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	var passkeys []Passkey
	var creds []webauthn.Credential
	if u.dbUser.WebAuthnData != "" {
		_ = json.Unmarshal([]byte(u.dbUser.WebAuthnData), &passkeys)
		for _, pk := range passkeys {
			creds = append(creds, pk.Credential)
		}
	}
	return creds
}
