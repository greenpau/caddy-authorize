package kms

import (
	"encoding/json"
	"fmt"
	"github.com/greenpau/caddy-auth-jwt/pkg/claims"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"github.com/greenpau/caddy-auth-jwt/pkg/tests"
	"testing"
	"time"
)

func TestSignToken(t *testing.T) {
	testcases := []struct {
		name                string
		claims              string
		tokenConfig         interface{}
		mandatorySignMethod interface{}
		err                 error
		shouldErr           bool
	}{
		{
			name: "valid HS256 token",
			claims: `{
                "addr": "10.0.2.2",
                "authenticated": true,
                "exp": 1613327613,
                "iat": 1613324013,
                "iss": "https://localhost:8443/auth",
                "jti": "a9d73486-b647-472a-b380-bea33a6115af",
                "mail": "webadmin@localdomain.local",
                "origin": "localhost",
                "roles": ["superadmin", "guest", "anonymous"],
                "sub": "jsmith"
            }`,
			tokenConfig: `{
                "token_secret": "e2c52192-261f-4e8f-ab83-c8eb928a8ddb",
                "token_name": "jwt_access_token",
                "token_lifetime": 1800
            }`,
		},
		{
			name:   "invalid sign method TB123",
			claims: fmt.Sprintf(`{"exp":%d}`, time.Now().Add(10*time.Minute).Unix()),
			tokenConfig: `{
                "token_secret": "e2c52192-261f-4e8f-ab83-c8eb928a8ddb",
                "token_name": "secure_token",
                "token_lifetime": 600
            }`,
			mandatorySignMethod: "TB123",
			shouldErr:           true,
			err:                 errors.ErrUnsupportedSigningMethod.WithArgs("TB123"),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tokenConfig, err := NewTokenConfig(tc.tokenConfig)
			if err != nil {
				t.Fatal(err)
			}
			claimMap := make(map[string]interface{})
			if err := json.Unmarshal([]byte(tc.claims), &claimMap); err != nil {
				t.Fatalf("json.Unmarshal() failed: %v", err)
			}
			userClaims, err := claims.NewUserClaimsFromMap(claimMap)
			if err != nil {
				t.Fatalf("NewUserClaimsFromMap() failed: %v", err)
			}
			// t.Logf("user claims: %v", userClaims.AsMap())
			km, err := NewKeyManager(tokenConfig)
			token, err := km.SignToken(tc.mandatorySignMethod, userClaims)
			if tests.EvalErr(t, err, token, tc.shouldErr, tc.err) {
				return
			}
			// t.Logf("signed token: %s", token)
		})
	}
}
