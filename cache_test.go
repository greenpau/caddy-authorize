// Copyright 2020 Paul Greenberg (greenpau@outlook.com)

package jwt

import (
	"testing"
	"time"
)

func newDummyClaims() *UserClaims {
	claims := &UserClaims{}
	claims.ExpiresAt = time.Now().Add(time.Duration(900) * time.Second).Unix()
	claims.Name = "Greenberg, Paul"
	claims.Email = "greenpau@outlook.com"
	claims.Origin = "localhost"
	claims.Subject = "greenpau@outlook.com"
	claims.Roles = append(claims.Roles, "anonymous")
	claims.Roles = append(claims.Roles, "guest")
	return claims
}

func TestTokenCache(t *testing.T) {
	secret := "75f03764-147c-4d87-b2f0-4fda89e331c8"
	claims := newDummyClaims()
	token, err := claims.GetToken("HS512", []byte(secret))
	if err != nil {
		t.Fatalf("Failed to get JWT token for %v: %s", claims, err)
	}
	t.Logf("Token: %s", token)
	t.Logf("Claims: %v", claims)

	c := NewTokenCache()
	t.Logf("Token cache contains %d entries", len(c.Entries))

	c.Add(token, *claims)
	if len(c.Entries) != 1 {
		t.Fatalf("Token cache contains %d entries, not the expected 1 entry", len(c.Entries))
	}
	t.Logf("Token cache contains %d entries", len(c.Entries))

	cachedClaims := c.Get(token)
	if cachedClaims == nil {
		t.Fatalf("Token cache did not return previously cached claims")
	}

	t.Logf("Cached Claims: %v", claims)

	c.Delete(token)
	if len(c.Entries) != 0 {
		t.Fatalf("Token cache contains %d entries, not the expected 0 entries", len(c.Entries))
	}

	claims = newDummyClaims()
	claims.ExpiresAt = time.Now().Add(time.Duration(-900) * time.Second).Unix()
	token, err = claims.GetToken("HS512", []byte(secret))
	if err != nil {
		t.Fatalf("Failed to get JWT token for %v: %s", claims, err)
	}
	c.Add(token, *claims)
	if len(c.Entries) != 1 {
		t.Fatalf("Token cache contains %d entries, not the expected 1 entry", len(c.Entries))
	}
	t.Logf("Token cache contains %d entries", len(c.Entries))
	cachedClaims = c.Get(token)
	if cachedClaims != nil {
		t.Fatalf("Token cache returned previously cached expired claims")
	}
	if len(c.Entries) != 0 {
		t.Fatalf("Token cache contains %d entries, not the expected 0 entries", len(c.Entries))
	}

	t.Logf("Passed")

}
