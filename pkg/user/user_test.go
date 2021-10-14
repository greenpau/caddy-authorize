// Copyright 2020 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package user

import (
	"encoding/json"
	"fmt"
	"github.com/greenpau/caddy-authorize/internal/tests"
	"github.com/greenpau/caddy-authorize/pkg/errors"
	"testing"
	"time"
)

func TestTokenValidity(t *testing.T) {
	testcases := []struct {
		name      string
		data      []byte
		shouldErr bool
		err       error
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
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var msgs []string
			msgs = append(msgs, fmt.Sprintf("test name: %s", tc.name))
			usr, err := NewUser(tc.data)
			if err == nil {
				msgs = append(msgs, fmt.Sprintf("parsed claims: %v", usr.AsMap()))
				err = usr.Claims.Valid()
			}
			if tests.EvalErrWithLog(t, err, "parse token", tc.shouldErr, tc.err, msgs) {
				return
			}
			wantHeaders := make(map[string]string)
			wantHeaders["foo"] = "bar"
			usr.SetRequestHeaders(wantHeaders)
			gotHeaders := usr.GetRequestHeaders()
			tests.EvalObjectsWithLog(t, "headers", wantHeaders, gotHeaders, msgs)

			wantIdentity := make(map[string]interface{})
			wantIdentity["foo"] = "bar"
			usr.SetRequestIdentity(wantIdentity)
			gotIdentity := usr.GetRequestIdentity()
			tests.EvalObjectsWithLog(t, "identity", wantIdentity, gotIdentity, msgs)
		})
	}
}

func TestNewClaimsFromMap(t *testing.T) {
	testcases := []struct {
		name      string
		data      interface{}
		claims    *Claims
		err       error
		shouldErr bool
	}{
		{
			name: "valid claims with metadata mfa claims",
			data: `{"name":"John Smith","metadata":{"mfa_required":true,"mfa_authenticated":false}}`,
			claims: &Claims{
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
			claims: &Claims{
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
			name:      "malformed json string",
			data:      `{"email": 123456`,
			shouldErr: true,
			err:       fmt.Errorf("unexpected end of JSON input"),
		},
		{
			name:      "user data is nil",
			data:      nil,
			shouldErr: true,
			err:       errors.ErrInvalidUserDataType,
		},
		{
			name: "valid claims with mail claim",
			data: []byte(`{"mail":"jsmith@contoso.com"}`),
			claims: &Claims{
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
			claims: &Claims{
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
			claims: &Claims{
				Roles:     []string{"anonymous", "guest"},
				ExpiresAt: 1613327613,
				IssuedAt:  1613324013,
				NotBefore: 1613324013,
			},
		},
		{
			name: "valid claims with exp, iat, nbf claim in json number",
			data: map[string]interface{}{
				"exp": json.Number("1613327613"),
				"iat": json.Number("1613324013"),
				"nbf": json.Number("1613324013"),
			},
			claims: &Claims{
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
			err:       errors.ErrInvalidClaimExpiresAt.WithArgs("1613327613"),
		},
		{
			name:      "invalid iat claim",
			data:      []byte(`{"iat": "1613327613"}`),
			shouldErr: true,
			err:       errors.ErrInvalidClaimIssuedAt.WithArgs("1613327613"),
		},
		{
			name:      "invalid nbf claim",
			data:      []byte(`{"nbf": "1613327613"}`),
			shouldErr: true,
			err:       errors.ErrInvalidClaimNotBefore.WithArgs("1613327613"),
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
			claims: &Claims{
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
			claims: &Claims{
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
			claims: &Claims{
				Roles: []string{"admin", "editor"},
			},
		},
		{
			name: "valid groups claim",
			data: []byte(`{"groups":["admin","editor"]}`),
			claims: &Claims{
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
			claims: &Claims{
				Name:  "jsmith@contoso.com John Smith",
				Roles: []string{"anonymous", "guest"},
			},
		},
		{
			name: "valid name claim with slice and email claim with the email from name claim",
			data: []byte(`{"name":["jsmith@contoso.com", "John Smith"],"mail":"jsmith@contoso.com"}`),
			claims: &Claims{
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
			claims: &Claims{
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
			claims: &Claims{
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
			claims: &Claims{
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
			claims: &Claims{
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
			claims: &Claims{
				Roles:  []string{"anonymous", "guest"},
				Scopes: []string{"repo", "public_repo"},
			},
		},
		{
			name: "valid scopes claim string value",
			data: []byte(`{"scopes": "repo public_repo"}`),
			claims: &Claims{
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
			claims: &Claims{
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
			claims: &Claims{
				Organizations: []string{"foo", "bar"},
				Roles:         []string{"anonymous", "guest"},
			},
		},
		{
			name: "valid org claim with slice",
			data: []byte(`{"org": ["foo","bar"]}`),
			claims: &Claims{
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
			usr, err := NewUser(tc.data)
			if tests.EvalErrWithLog(t, err, "user map", tc.shouldErr, tc.err, msgs) {
				return
			}
			msgs = append(msgs, fmt.Sprintf("parsed claims: %v", usr.AsMap()))
			msgs = append(msgs, fmt.Sprintf("extracted key-values: %v", usr.GetData()))
			tests.EvalObjectsWithLog(t, "response", tc.claims, usr.Claims, msgs)

		})
	}
}
