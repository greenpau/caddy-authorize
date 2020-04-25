// Copyright 2020 Paul Greenberg (greenpau@outlook.com)

package jwt

import (
	"testing"
	"time"
)

func TestUserClaims(t *testing.T) {
	claims := &UserClaims{}
	claims.ExpiresAt = time.Now().Add(time.Duration(900) * time.Second).Unix()
	claims.Name = "Greenberg, Paul"
	claims.Email = "greenpau@outlook.com"
	claims.Origin = "localhost"
	claims.Subject = "greenpau@outlook.com"
	claims.Roles = append(claims.Roles, "anonymous")
	secret := "75f03764-147c-4d87-b2f0-4fda89e331c8"
	token, err := claims.GetToken("HS512", []byte(secret))
	if err != nil {
		t.Fatalf("Failed to get JWT token for %v: %s", claims, err)
	}
	t.Logf("Token: %s", token)
}
