// Copyright 2020 Paul Greenberg (greenpau@outlook.com)

package jwt

import (
	"testing"
)

func TestTokenProviderConfig(t *testing.T) {
	p1 := NewTokenProviderConfig()

	t.Logf("TokenName: %s", p1.TokenName)
	t.Logf("TokenSecret: %s", p1.TokenSecret)
	t.Logf("TokenIssuer: %s", p1.TokenIssuer)
	t.Logf("TokenLifetime: %d", p1.TokenLifetime)

	p1.SetDefaults()

	if p1.TokenName == "" {
		t.Fatal("failed to set default token")
	}

	if p1.TokenSecret == "" {
		t.Fatal("failed to set default token secret")
	}

	if p1.TokenIssuer != "localhost" {
		t.Fatal("failed to set default token issuer")
	}

	if p1.TokenLifetime == 0 {
		t.Fatal("failed to set default token lifetime")
	}

	p1.SetDefaults()

	t.Logf("TokenName: %s", p1.TokenName)
	t.Logf("TokenSecret: %s", p1.TokenSecret)
	t.Logf("TokenIssuer: %s", p1.TokenIssuer)
	t.Logf("TokenLifetime: %d", p1.TokenLifetime)
}
