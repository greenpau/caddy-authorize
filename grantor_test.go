// Copyright 2020 Paul Greenberg (greenpau@outlook.com)

package jwt

import (
	"testing"
	"time"
)

func TestNewGrantor(t *testing.T) {
	secret := "75f03764-147c-4d87-b2f0-4fda89e331c8"

	claims := &UserClaims{}
	claims.ExpiresAt = time.Now().Add(time.Duration(900) * time.Second).Unix()
	claims.Name = "Smith, John"
	claims.Email = "jsmith@gmail.com"
	claims.Origin = "localhost"
	claims.Subject = "jsmith"
	claims.Roles = append(claims.Roles, "anonymous")

	grantor := NewTokenGrantor()
	if err := grantor.Validate(); err == nil {
		t.Fatalf("grantor validation expected to fail, but succeeded")
	}

	if _, err := grantor.GrantToken("DUMMY", claims); err == nil {
		t.Fatalf("grantor signing with dummy method expected to fail, but succeeded")
	}

	if _, err := grantor.GrantToken("HS512", claims); err == nil {
		t.Fatalf("grantor signing with misconfiguration expected to fail, but succeeded")
	}

	if _, err := grantor.GrantToken("HS512", nil); err == nil {
		t.Fatalf("grantor signing of nil claims expected to fail, but succeeded")
	}

	grantor.TokenSecret = secret
	if err := grantor.Validate(); err != nil {
		t.Fatalf("grantor validation expected to succeeded, but failed: %s", err)
	}

	token, err := grantor.GrantToken("HS512", claims)
	if err != nil {
		t.Fatalf("grantor signing of user claims failed, but expected to succeed: %s", err)
	}
	t.Logf("Granted Token: %s", token)

	validator := NewTokenValidator()
	validator.TokenSecret = secret
	if err := validator.ConfigureTokenBackends(); err != nil {
		t.Fatalf("validator backend configuration failed: %s", err)
	}

	entry := NewAccessListEntry()
	entry.Allow()
	if err := entry.SetClaim("roles"); err != nil {
		t.Fatalf("default access list configuration error: %s", err)
	}

	for _, v := range []string{"anonymous", "guest"} {
		if err := entry.AddValue(v); err != nil {
			t.Fatalf("default access list configuration error: %s", err)
		}
	}
	validator.AccessList = append(validator.AccessList, entry)

	userClaims, valid, err := validator.ValidateToken(token)
	if err != nil {
		t.Fatalf("token validation error: %s, valid: %t, claims: %v", err, valid, userClaims)
	}
	if !valid {
		t.Fatalf("token validation error: not valid, claims: %v", userClaims)
	}
	if userClaims == nil {
		t.Fatalf("token validation error: user claims is nil")
	}
	t.Logf("Token claims: %v", userClaims)

}
