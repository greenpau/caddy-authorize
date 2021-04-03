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

package grantor

import (
	// "errors"
	"encoding/json"
	"github.com/google/go-cmp/cmp"
	jwtclaims "github.com/greenpau/caddy-auth-jwt/pkg/claims"
	jwterrors "github.com/greenpau/caddy-auth-jwt/pkg/errors"
	kms "github.com/greenpau/caddy-auth-jwt/pkg/kms"
	"os"
	"testing"
	"time"
)

func TestGrantor(t *testing.T) {
	baseDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	claims := &jwtclaims.UserClaims{
		ExpiresAt: time.Now().Add(time.Duration(900) * time.Second).Unix(),
		Name:      "Greenberg, Paul",
		Email:     "greenpau@outlook.com",
		Origin:    "localhost",
		Subject:   "greenpau@outlook.com",
		Roles:     []string{"anonymous"},
	}

	tests := []struct {
		name       string
		keymgrs    []string
		tokenNames []string
		signMethod string
		err        error
		shouldErr  bool
	}{
		{
			name:      "no config",
			shouldErr: true,
			err:       jwterrors.ErrTokenGrantorEmpty,
		},
		{
			name:       "single HS token",
			tokenNames: []string{"access_token"},
			keymgrs: []string{
				`{"token_secret": "e2c52192-261f-4e8f-ab83-c8eb928a8ddb"}`,
			},
		},
		{
			name:       "shared key and directory of private RSA keys",
			tokenNames: []string{"access_token", "jwt_access_token"},
			keymgrs: []string{
				`{"token_rsa_dir": "./../../testdata/rskeys"}`,
				`{"token_name": "jwt_access_token", "token_secret": "e2c52192-261f-4e8f-ab83-c8eb928a8ddb"}`,
			},
		},
		{
			name:       "directory of private RSA keys and private ECDSA key with default method",
			tokenNames: []string{"access_token"},
			keymgrs: []string{
				`{"token_ecdsa_file": "` + baseDir + `/../../testdata/ecdsakeys/test_1_pri.pem"}`,
				// `{"token_rsa_dir": "./../../testdata/rskeys"}`,
			},
		},
		{
			name:       "private ECDSA key with ES256",
			tokenNames: []string{"access_token"},
			keymgrs: []string{
				`{"token_ecdsa_file": "` + baseDir + `/../../testdata/ecdsakeys/test_2_pri.pem"}`,
			},
			signMethod: "ES256",
		},
		{
			name:       "private ECDSA key with ES384",
			tokenNames: []string{"access_token"},
			keymgrs: []string{
				`{"token_ecdsa_file": "` + baseDir + `/../../testdata/ecdsakeys/test_3_pri.pem"}`,
			},
			signMethod: "ES384",
		},
		{
			name:       "private ECDSA key with ES512",
			tokenNames: []string{"access_token"},
			keymgrs: []string{
				`{"token_ecdsa_file": "` + baseDir + `/../../testdata/ecdsakeys/test_4_pri.pem"}`,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var signedToken string
			g := NewTokenGrantor()
			for _, entry := range tc.keymgrs {
				keymgr := &kms.KeyManager{}
				if err := json.Unmarshal([]byte(entry), keymgr); err != nil {
					t.Fatalf("encountered error parsing config: %s", err)
				}
				if err := keymgr.Load(); err != nil {
					t.Fatalf("encountered error loading keys: %s", err)
				}
				g.AddKeyManager(keymgr)
			}
			if diff := cmp.Diff(tc.tokenNames, g.GetTokenNames()); diff != "" {
				t.Errorf("GetTokenNames() mismatch (-want +got):\n%s", diff)
			}
			err := g.Validate()
			if err == nil {
				if tc.signMethod == "" {
					signedToken, err = g.GrantToken(claims)
				} else {
					signedToken, err = g.GrantTokenWithMethod(tc.signMethod, claims)
				}
				if tc.shouldErr && err == nil {
					t.Fatalf("expected error, but got success")
				}
				if err == nil {
					t.Logf("Signed token: %s", signedToken)
				}
			}
			if !tc.shouldErr && err != nil {
				t.Fatalf("expected success, but got error: %s", err)
			}
			if tc.shouldErr {
				if err.Error() != tc.err.Error() {
					t.Fatalf("unexpected error, got: %v, expected: %v", err, tc.err)
				}
				t.Logf("received expected error: %v", err)
			}
		})
	}
}
