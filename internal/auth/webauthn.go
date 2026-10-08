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
	webauthn.Credential
	Name string `json:"name"`
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
