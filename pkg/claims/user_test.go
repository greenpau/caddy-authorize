// Copyright 2020 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package claims

import (
	"encoding/json"
	"fmt"
	jwtlib "github.com/dgrijalva/jwt-go"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"github.com/greenpau/caddy-auth-jwt/pkg/tests"
	"reflect"
	"testing"
	"time"
)

func TestTokenValidity(t *testing.T) {
	testcases := []struct {
		name      string
		data      []byte
		err       error
		shouldErr bool
	}{
		{
			name: "valid token",
			data: []byte(fmt.Sprintf(`{"exp":%d}`, time.Now().Add(10*time.Minute).Unix())),
		},
		{
			name:      "expired token",
			data:      []byte(fmt.Sprintf(`{"exp":%d}`, time.Now().Add(-10*time.Minute).Unix())),
			shouldErr: true,
			err:       errors.ErrExpiredToken,
		},
	}
	for i, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("test %d: %s", i, tc.name)
			tokenMap := make(map[string]interface{})
			if err := json.Unmarshal(tc.data, &tokenMap); err != nil {
				t.Fatalf("test %d: failed parsing json-formatted JWT token: %s", i, err)
			}
			claims, err := NewUserClaimsFromMap(tokenMap)
			if err != nil {
				t.Fatalf("test %d: unexpected claim parsing failure: %s", i, err)
			}
			t.Logf("test %d: parsed claims: %v", i, claims.AsMap())

			err = claims.Valid()
			if tc.shouldErr && err == nil {
				t.Fatalf("test %d: expected error, but got success", i)
			}
			if !tc.shouldErr && err != nil {
				t.Fatalf("test %d: expected success, but got error: %s", i, err)
			}
			if tc.shouldErr {
				if err.Error() != tc.err.Error() {
					t.Fatalf("test %d: unexpected error, got: %v, expected: %v", i, err, tc.err)
				}
				t.Logf("test %d: received expected error: %s", i, err)
				return
			}
			t.Logf("test %d: received expected success", i)

		})
	}
}

func TestNewUserClaimsFromMap(t *testing.T) {
	testcases := []struct {
		name      string
		data      []byte
		claims    *UserClaims
		err       error
		shouldErr bool
	}{
		{
			name: "valid claims with metadata mfa claims",
			data: []byte(`{"name":"John Smith","metadata":{"mfa_required":true,"mfa_authenticated":false}}`),
			claims: &UserClaims{
				Name:  "John Smith",
				Roles: []string{"anonymous", "guest"},
				Metadata: map[string]interface{}{
					"mfa_authenticated": false,
					"mfa_required":      true,
				},
			},
		},
		{
			name: "valid claims with email claim",
			data: []byte(`{"email":"jsmith@contoso.com"}`),
			claims: &UserClaims{
				Email: "jsmith@contoso.com",
				Roles: []string{"anonymous", "guest"},
			},
		},
		{
			name:      "invalid email claim",
			data:      []byte(`{"email": 123456}`),
			shouldErr: true,
			err:       errors.ErrInvalidEmailClaimType.WithArgs("email", 123456.00),
		},
		{
			name: "valid claims with mail claim",
			data: []byte(`{"mail":"jsmith@contoso.com"}`),
			claims: &UserClaims{
				Email: "jsmith@contoso.com",
				Roles: []string{"anonymous", "guest"},
			},
		},
		{
			name:      "invalid mail claim",
			data:      []byte(`{"mail": 123456}`),
			shouldErr: true,
			err:       errors.ErrInvalidEmailClaimType.WithArgs("mail", 123456.00),
		},
		{
			name: "valid claims with issuer claim",
			data: []byte(`{"iss":"https://127.0.0.1/auth"}`),
			claims: &UserClaims{
				Issuer: "https://127.0.0.1/auth",
				Roles:  []string{"anonymous", "guest"},
			},
		},
		{
			name:      "invalid issuer claim",
			data:      []byte(`{"iss": 123456}`),
			shouldErr: true,
			err:       errors.ErrInvalidIssuerClaimType.WithArgs(123456.00),
		},
		{
			name: "valid claims with exp, iat, nbf claim in float64",
			data: []byte(`{"exp": 1613327613.00, "nbf": 1613324013.00, "iat": 1613324013.00}`),
			claims: &UserClaims{
				Roles:     []string{"anonymous", "guest"},
				ExpiresAt: 1613327613,
				IssuedAt:  1613324013,
				NotBefore: 1613324013,
			},
		},
		{
			name:      "invalid exp claim",
			data:      []byte(`{"exp": "1613327613"}`),
			shouldErr: true,
			err:       errors.ErrInvalidClaimExpiresAt,
		},
		{
			name:      "invalid iat claim",
			data:      []byte(`{"iat": "1613327613"}`),
			shouldErr: true,
			err:       errors.ErrInvalidClaimIssuedAt,
		},
		{
			name:      "invalid nbf claim",
			data:      []byte(`{"nbf": "1613327613"}`),
			shouldErr: true,
			err:       errors.ErrInvalidClaimNotBefore,
		},
		{
			name: "valid jti, sub, aud, origin, addr, and picture claims",
			data: []byte(`{
				"jti": "a9d73486-b647-472a-b380-bea33a6115af",
				"sub":"jsmith",
				"aud":"portal",
				"origin": "localhost",
				"addr": "10.10.10.10",
				"picture": "https://127.0.0.1/avatar.png"
			}`),
			claims: &UserClaims{
				Audience:   []string{"portal"},
				ID:         "a9d73486-b647-472a-b380-bea33a6115af",
				Subject:    "jsmith",
				Origin:     "localhost",
				Roles:      []string{"anonymous", "guest"},
				Address:    "10.10.10.10",
				PictureURL: "https://127.0.0.1/avatar.png",
			},
		},
		{
			name: "valid aud claim with multiple entries",
			data: []byte(`{"aud":["portal","dashboard"]}`),
			claims: &UserClaims{
				Audience: []string{"portal", "dashboard"},
				Roles:    []string{"anonymous", "guest"},
			},
		},
		{
			name:      "invalid jti claim",
			data:      []byte(`{"jti": 1613327613}`),
			shouldErr: true,
			err:       errors.ErrInvalidIDClaimType.WithArgs(1613327613.00),
		},
		{
			name:      "invalid sub claim",
			data:      []byte(`{"sub": ["foo", "bar"]}`),
			shouldErr: true,
			err:       errors.ErrInvalidSubjectClaimType.WithArgs([]interface{}{"foo", "bar"}),
		},
		{
			name:      "invalid aud claim with numberic value",
			data:      []byte(`{"aud": 123456}`),
			shouldErr: true,
			err:       errors.ErrInvalidAudienceType.WithArgs(123456.00),
		},
		{
			name:      "invalid aud claim with numberic slice value",
			data:      []byte(`{"aud": [123456]}`),
			shouldErr: true,
			err:       errors.ErrInvalidAudience.WithArgs(123456.00),
		},
		{
			name:      "invalid origin claim",
			data:      []byte(`{"origin": 123456}`),
			shouldErr: true,
			err:       errors.ErrInvalidOriginClaimType.WithArgs(123456.00),
		},
		{
			name: "valid roles claim",
			data: []byte(`{"roles": "admin editor"}`),
			claims: &UserClaims{
				Roles: []string{"admin", "editor"},
			},
		},
		{
			name: "valid groups claim",
			data: []byte(`{"groups":["admin","editor"]}`),
			claims: &UserClaims{
				Roles: []string{"admin", "editor"},
			},
		},
		{
			name:      "invalid roles claim",
			data:      []byte(`{"roles": 123456}`),
			shouldErr: true,
			err:       errors.ErrInvalidRoleType.WithArgs(123456.00),
		},
		{
			name:      "invalid groups claim",
			data:      []byte(`{"roles":[123456, 234567]}`),
			shouldErr: true,
			err:       errors.ErrInvalidRole.WithArgs(234567.00),
		},
		{
			name: "valid name claim with slice",
			data: []byte(`{"name":["jsmith@contoso.com", "John Smith"]}`),
			claims: &UserClaims{
				Name:  "jsmith@contoso.com John Smith",
				Roles: []string{"anonymous", "guest"},
			},
		},
		{
			name: "valid name claim with slice and email claim with the email from name claim",
			data: []byte(`{"name":["jsmith@contoso.com", "John Smith"],"mail":"jsmith@contoso.com"}`),
			claims: &UserClaims{
				Name:  "John Smith",
				Email: "jsmith@contoso.com",
				Roles: []string{"anonymous", "guest"},
			},
		},
		{
			name:      "invalid name claim with numeric slice",
			data:      []byte(`{"name":[123456, 234567]}`),
			shouldErr: true,
			err:       errors.ErrInvalidNameClaimType.WithArgs([]interface{}{123456, 234567}),
		},
		{
			name:      "invalid name claim with numeric value",
			data:      []byte(`{"name": 234567}`),
			shouldErr: true,
			err:       errors.ErrInvalidNameClaimType.WithArgs(234567.00),
		},
		{
			name:      "invalid addr claim",
			data:      []byte(`{"addr": 234567}`),
			shouldErr: true,
			err:       errors.ErrInvalidAddrType.WithArgs(234567.00),
		},
		{
			name:      "invalid picture claim",
			data:      []byte(`{"picture": 234567}`),
			shouldErr: true,
			err:       errors.ErrInvalidPictureClaimType.WithArgs(234567.00),
		},
		{
			name:      "invalid metadata claim",
			data:      []byte(`{"metadata": 234567}`),
			shouldErr: true,
			err:       errors.ErrInvalidMetadataClaimType.WithArgs(234567.00),
		},

		{
			name: "valid app_metadata claim",
			data: []byte(`{"app_metadata":{"authorization":{"roles":["admin", "editor"]}}}`),
			claims: &UserClaims{
				Roles: []string{"admin", "editor"},
			},
		},
		{
			name:      "invalid app_metadata claim with numeric roles slice",
			data:      []byte(`{"app_metadata":{"authorization":{"roles":[123456, 234567]}}}`),
			shouldErr: true,
			err:       errors.ErrInvalidRole.WithArgs(123456.00),
		},
		{
			name:      "invalid app_metadata claim with numeric roles value",
			data:      []byte(`{"app_metadata":{"authorization":{"roles": 123456}}}`),
			shouldErr: true,
			err:       errors.ErrInvalidAppMetadataRoleType.WithArgs(123456.00),
		},
		{
			name: "valid realm_access claim",
			data: []byte(`{"realm_access":{"roles":["admin", "editor"]}}`),
			claims: &UserClaims{
				Roles: []string{"admin", "editor"},
			},
		},
		{
			name:      "invalid realm_access claim with numeric roles slice",
			data:      []byte(`{"realm_access":{"roles":[123456, 234567]}}`),
			shouldErr: true,
			err:       errors.ErrInvalidRole.WithArgs(123456.00),
		},
		{
			name: "valid acl claim with paths map",
			data: []byte(`{"acl":{"paths":{"/*/users/**": {}, "/*/conversations/**": {}}}}`),
			claims: &UserClaims{
				Roles: []string{"anonymous", "guest"},
				AccessList: &AccessListClaim{
					Paths: map[string]interface{}{
						"/*/conversations/**": map[string]interface{}{},
						"/*/users/**":         map[string]interface{}{},
					},
				},
			},
		},
		{
			name: "valid acl claim with paths slice",
			data: []byte(`{"acl":{"paths":["/*/users/**", "/*/conversations/**"]}}`),
			claims: &UserClaims{
				Roles: []string{"anonymous", "guest"},
				AccessList: &AccessListClaim{
					Paths: map[string]interface{}{
						"/*/conversations/**": map[string]interface{}{},
						"/*/users/**":         map[string]interface{}{},
					},
				},
			},
		},
		{
			name:      "invalid acl claim with numeric paths slice",
			data:      []byte(`{"acl":{"paths":["/*/users/**", 123456]}}`),
			shouldErr: true,
			err:       errors.ErrInvalidAccessListPath.WithArgs(123456.00),
		},
		{
			name: "valid scopes claim with string slice",
			data: []byte(`{"scopes": ["repo", "public_repo"]}`),
			claims: &UserClaims{
				Roles:  []string{"anonymous", "guest"},
				Scopes: []string{"repo", "public_repo"},
			},
		},
		{
			name: "valid scopes claim string value",
			data: []byte(`{"scopes": "repo public_repo"}`),
			claims: &UserClaims{
				Roles:  []string{"anonymous", "guest"},
				Scopes: []string{"repo", "public_repo"},
			},
		},
		{
			name:      "invalid scopes claim with numeric slice",
			data:      []byte(`{"scopes": [123456]}`),
			shouldErr: true,
			err:       errors.ErrInvalidScope.WithArgs(123456.00),
		},
		{
			name:      "invalid scopes claim with numeric value",
			data:      []byte(`{"scopes": 123456}`),
			shouldErr: true,
			err:       errors.ErrInvalidScopeType.WithArgs(123456.00),
		},

		{
			name: "valid paths claim",
			data: []byte(`{"paths": ["/dropbox/jsmith/README.md"]}`),
			claims: &UserClaims{
				Roles: []string{"anonymous", "guest"},
				AccessList: &AccessListClaim{
					Paths: map[string]interface{}{"/dropbox/jsmith/README.md": map[string]interface{}{}},
				},
			},
		},
		{
			name:      "invalid paths claim with numeric slice",
			data:      []byte(`{"paths": [123456]}`),
			shouldErr: true,
			err:       errors.ErrInvalidAccessListPath.WithArgs(123456.00),
		},

		{
			name: "valid org claim with string",
			data: []byte(`{"org": "foo bar"}`),
			claims: &UserClaims{
				Organizations: []string{"foo", "bar"},
				Roles:         []string{"anonymous", "guest"},
			},
		},
		{
			name: "valid org claim with slice",
			data: []byte(`{"org": ["foo","bar"]}`),
			claims: &UserClaims{
				Organizations: []string{"foo", "bar"},
				Roles:         []string{"anonymous", "guest"},
			},
		},
		{
			name:      "invalid org claim with numeric value",
			data:      []byte(`{"org": 123456}`),
			shouldErr: true,
			err:       errors.ErrInvalidOrgType.WithArgs(123456.00),
		},
		{
			name:      "invalid org claim with numeric slice",
			data:      []byte(`{"org":[123456, 234567]}`),
			shouldErr: true,
			err:       errors.ErrInvalidOrg.WithArgs(234567.00),
		},
		{
			name:      "invalid json map",
			data:      []byte(`{"org":`),
			shouldErr: true,
			err:       fmt.Errorf("unexpected end of JSON input"),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var msgs []string
			msgs = append(msgs, fmt.Sprintf("test name: %s", tc.name))
			claims, err := NewUserClaimsFromJSON(string(tc.data))
			if tests.EvalErrWithLog(t, err, "user map", tc.shouldErr, tc.err, msgs) {
				return
			}
			msgs = append(msgs, fmt.Sprintf("parsed claims: %v", claims.AsMap()))
			msgs = append(msgs, fmt.Sprintf("extracted key-values: %v", claims.ExtractKV()))
			tests.EvalObjectsWithLog(t, "response", tc.claims, claims, msgs)

		})
	}
}

func TestAppMetadataAuthorizationRoles(t *testing.T) {
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
			return nil, errors.ErrUnexpectedSigningMethod.WithArgs(token.Header["alg"])
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

func TestRealmAccessRoles(t *testing.T) {
	secret := "75f03764147c4d87b2f04fda89e331c808ab50a932914e758ae17c7847ef27fa"
	encodedToken := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjI1NDI3MTkzOTgsInN1YiI6ImdyZWVucGF1QG91dGxvb2suY29tIiwibmFtZSI6IkdyZWVuYmVyZywgUGF1bCIsImVtYWlsIjoiZ3JlZW5wYXVAb3V0bG9vay5jb20iLCJhcHBfbWV0YWRhdGEiOnsiYXV0aG9yaXphdGlvbiI6eyJyb2xlcyI6WyJhZG1pbiIsImVkaXRvciIsImd1ZXN0Il19fSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm1hcmtldGluZyIsImZpbmFuY2UiLCJ0cmFpbmluZyJdfSwib3JpZ2luIjoibG9jYWxob3N0In0.IiYC_7JCpZiKN7dvwXCLw94HvL8sMBqKACp6zthIXg8GyU-PXSleGnjc9wduBFqWfMtl5oP_JrJzCbsWiInghA"
	expectedRoles := []string{"admin", "editor", "guest", "marketing", "finance", "training"}

	t.Logf("token Secret: %s", secret)
	t.Logf("encoded Token: %s", encodedToken)

	token, err := jwtlib.Parse(encodedToken, func(token *jwtlib.Token) (interface{}, error) {
		if _, validMethod := token.Method.(*jwtlib.SigningMethodHMAC); !validMethod {
			return nil, errors.ErrUnexpectedSigningMethod.WithArgs(token.Header["alg"])
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

func TestAnonymousGuestRoles(t *testing.T) {
	secret := "75f03764147c4d87b2f04fda89e331c808ab50a932914e758ae17c7847ef27fa"
	encodedToken := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9." +
		"eyJleHAiOjI1NDI3MTkzOTgsInN1YiI6ImdyZWVucGF1QG91dGxvb2suY29tIiwibmFtZSI6IkdyZW" +
		"VuYmVyZywgUGF1bCIsImVtYWlsIjoiZ3JlZW5wYXVAb3V0bG9vay5jb20iLCJvcmlnaW4iOiJsb2Nh" +
		"bGhvc3QifQ." +
		"INRBEsx7b4sewCmNCQxRSN3Hk_sT5BMbjlq_iPdbvkYiWnORS93xYSAei78GWEMDepc6ECTSGhqVL-sDFCbPoA"
	expectedRoles := []string{"anonymous", "guest"}

	t.Logf("token Secret: %s", secret)
	t.Logf("encoded Token: %s", encodedToken)

	token, err := jwtlib.Parse(encodedToken, func(token *jwtlib.Token) (interface{}, error) {
		if _, validMethod := token.Method.(*jwtlib.SigningMethodHMAC); !validMethod {
			return nil, errors.ErrUnexpectedSigningMethod.WithArgs(token.Header["alg"])
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
