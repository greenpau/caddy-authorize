// Copyright 2020 Paul Greenberg (greenpau@outlook.com)

package jwt

import (
	jwtlib "github.com/dgrijalva/jwt-go"
	"reflect"
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

func TestAppMetadata(t *testing.T) {
	secret := "75f03764147c4d87b2f04fda89e331c808ab50a932914e758ae17c7847ef27fa"
	encodedToken := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9." +
		"eyJleHAiOjI1NDI3MTkzOTgsInN1YiI6ImdyZWVucGF1QG91dGxvb2suY29tIiwibmFtZSI6IkdyZWV" +
		"uYmVyZywgUGF1bCIsImVtYWlsIjoiZ3JlZW5wYXVAb3V0bG9vay5jb20iLCJhcHBfbWV0YWRhdGEiOn" +
		"siYXV0aG9yaXphdGlvbiI6eyJyb2xlcyI6WyJhZG1pbiIsImVkaXRvciIsImd1ZXN0Il19fSwib3JpZ" +
		"2luIjoibG9jYWxob3N0In0." +
		"KnHyq1WhL3VbhVaHZBc5JyvHMZbU72505H5y9QJmLADmTfDSJbQ-Odjsnl5zZldG_PBMQ6XkvE11hsmXOIqyKA"
	expectedRoles := []string{"admin", "editor", "guest"}

	t.Logf("token Secret: %s", secret)
	t.Logf("encoded Token: %s", encodedToken)

	token, err := jwtlib.Parse(encodedToken, func(token *jwtlib.Token) (interface{}, error) {
		if _, validMethod := token.Method.(*jwtlib.SigningMethodHMAC); !validMethod {
			return nil, ErrUnexpectedSigningMethod.WithArgs(token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		t.Fatalf("failed parsing the encoded token: %s", err)
	}

	t.Logf("token: %v", token)

	claimMap := token.Claims.(jwtlib.MapClaims)
	claims, err := NewUserClaimsFromMap(claimMap)
	if err != nil {
		t.Fatalf("failed parsing claims for token: %s", err)
	}

	t.Logf("claims: %v", claims)

	if len(claims.Roles) == 0 {
		t.Fatalf("no roles found, expecting %s", expectedRoles)
	}

	if len(claims.Roles) != len(expectedRoles) {
		t.Fatalf("role count mismatch: %d (token) vs %d (expected)", len(claims.Roles), len(expectedRoles))
	}

	if !reflect.DeepEqual(claims.Roles, expectedRoles) {
		t.Fatalf("role mismatch: %s (token) vs %s (expected)", claims.Roles, expectedRoles)
	}

	t.Logf("token roles: %s", claims.Roles)

	return
}
