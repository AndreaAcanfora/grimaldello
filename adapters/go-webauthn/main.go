// grimaldello adapter for go-webauthn.
// Reads cases (JSON lines) on stdin, writes one verdict per line on stdout.
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
)

type testCase struct {
	ID                      string          `json:"id"`
	Ceremony                string          `json:"ceremony"`
	RP                      struct{ ID, Name, Origin string } `json:"rp"`
	RequireUserVerification bool            `json:"requireUserVerification"`
	Algorithms              []int           `json:"algorithms"`
	UserHandle              string          `json:"userHandle"`
	Registration            struct {
		Challenge string          `json:"challenge"`
		Response  json.RawMessage `json:"response"`
	} `json:"registration"`
	Authentication *struct {
		Challenge       string          `json:"challenge"`
		Response        json.RawMessage `json:"response"`
		StoredSignCount uint32          `json:"storedSignCount"`
	} `json:"authentication"`
}

type user struct {
	id    []byte
	creds []webauthn.Credential
}

func (u *user) WebAuthnID() []byte                         { return u.id }
func (u *user) WebAuthnName() string                       { return "grimaldello" }
func (u *user) WebAuthnDisplayName() string                { return "grimaldello" }
func (u *user) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func uvRequirement(required bool) protocol.UserVerificationRequirement {
	if required {
		return protocol.VerificationRequired
	}
	return protocol.VerificationPreferred
}

func register(w *webauthn.WebAuthn, c *testCase, u *user) (*webauthn.Credential, error) {
	params := make([]protocol.CredentialParameter, 0, len(c.Algorithms))
	for _, a := range c.Algorithms {
		params = append(params, protocol.CredentialParameter{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.COSEAlgorithmIdentifier(a)})
	}
	_, session, err := w.BeginRegistration(u,
		webauthn.WithCredentialParameters(params),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{UserVerification: uvRequirement(c.RequireUserVerification)}),
	)
	if err != nil {
		return nil, fmt.Errorf("BeginRegistration: %w", err)
	}
	session.Challenge = c.Registration.Challenge
	parsed, err := protocol.ParseCredentialCreationResponseBytes(c.Registration.Response)
	if err != nil {
		return nil, err
	}
	return w.CreateCredential(u, *session, parsed)
}

func verify(c *testCase) (err error) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "panic in %s: %v\n%s", c.ID, r, debug.Stack())
			os.Exit(3)
		}
	}()
	w, err := webauthn.New(&webauthn.Config{RPID: c.RP.ID, RPDisplayName: c.RP.Name, RPOrigins: []string{c.RP.Origin}})
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	uid, _ := base64.RawURLEncoding.DecodeString(c.UserHandle)
	u := &user{id: uid}
	cred, err := register(w, c, u)
	if c.Ceremony == "registration" || err != nil {
		if err != nil && c.Ceremony != "registration" {
			return fmt.Errorf("setup: registration failed: %w", err)
		}
		return err
	}
	a := c.Authentication
	cred.Authenticator.SignCount = a.StoredSignCount
	u.creds = []webauthn.Credential{*cred}
	_, session, err := w.BeginLogin(u, webauthn.WithUserVerification(uvRequirement(c.RequireUserVerification)))
	if err != nil {
		return fmt.Errorf("BeginLogin: %w", err)
	}
	session.Challenge = a.Challenge
	session.Expires = time.Now().Add(time.Hour)
	parsed, err := protocol.ParseCredentialRequestResponseBytes(a.Response)
	if err != nil {
		return err
	}
	updated, err := w.ValidateLogin(u, *session, parsed)
	if err != nil {
		return err
	}
	// The library reports a counter problem through a flag instead of an error;
	// an application is expected to check it.
	if updated.Authenticator.CloneWarning {
		return errors.New("CloneWarning set")
	}
	return nil
}

func describe(err error) string {
	var perr *protocol.Error
	if errors.As(err, &perr) {
		return fmt.Sprintf("%s: %s %s", perr.Type, perr.Details, perr.DevInfo)
	}
	return err.Error()
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--info" {
		version := "unknown"
		if bi, ok := debug.ReadBuildInfo(); ok {
			for _, d := range bi.Deps {
				if d.Path == "github.com/go-webauthn/webauthn" {
					version = d.Version
				}
			}
		}
		json.NewEncoder(os.Stdout).Encode(map[string]string{"library": "go-webauthn", "version": version, "language": "Go"})
		return
	}
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 16<<20), 16<<20)
	out := json.NewEncoder(os.Stdout)
	for in.Scan() {
		line := bytes.TrimSpace(in.Bytes())
		if len(line) == 0 {
			continue
		}
		var c testCase
		if err := json.Unmarshal(line, &c); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		res := map[string]any{"id": c.ID, "verdict": "accept"}
		if err := verify(&c); err != nil {
			res["verdict"] = "reject"
			res["error"] = describe(err)
			// The library reports failures as *protocol.Error; anything else is
			// an error type applications do not expect.
			var perr *protocol.Error
			if !errors.As(err, &perr) && err.Error() != "CloneWarning set" {
				res["unexpected"] = true
			}
		}
		out.Encode(res)
	}
}
