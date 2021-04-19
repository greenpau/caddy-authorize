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
	"fmt"
	"github.com/greenpau/caddy-auth-jwt/pkg/claims"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"github.com/greenpau/caddy-auth-jwt/pkg/kms"
	"github.com/greenpau/caddy-auth-jwt/pkg/tests"
	"os"
	"testing"
	"time"
)

func TestGrantor(t *testing.T) {
	baseDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	userClaims := &claims.UserClaims{
		ExpiresAt: time.Now().Add(time.Duration(900) * time.Second).Unix(),
		Name:      "Greenberg, Paul",
		Email:     "greenpau@outlook.com",
		Origin:    "localhost",
		Subject:   "greenpau@outlook.com",
		Roles:     []string{"anonymous"},
	}

	testcases := []struct {
		name              string
		tokenConfigs      []string
		claims            *claims.UserClaims
		signMethod        interface{}
		want              map[string]interface{}
		skipKeyManagerErr bool
		err               error
		shouldErr         bool
	}{
		{
			name:      "no config",
			shouldErr: true,
			err:       errors.ErrTokenGrantorNoSigningKeysFound,
		},
		{
			name: "bad config",
			tokenConfigs: []string{
				`{"token_secret"`,
			},
			shouldErr: true,
			err:       errors.ErrTokenConfigNewFailedUnmarshal.WithArgs("unexpected end of JSON input"),
		},
		{
			name: "single HS token",
			tokenConfigs: []string{
				`{"token_secret": "e2c52192-261f-4e8f-ab83-c8eb928a8ddb"}`,
			},
			claims: userClaims,
			want: map[string]interface{}{
				"token_names":       []string{"access_token"},
				"key_manager_count": 1,
			},
		},
		{
			name: "shared key and directory of private RSA keys",
			tokenConfigs: []string{
				`{"token_rsa_dir": "./../../testdata/rskeys"}`,
				`{"token_name": "jwt_access_token", "token_secret": "e2c52192-261f-4e8f-ab83-c8eb928a8ddb"}`,
			},
			claims: userClaims,
			want: map[string]interface{}{
				"token_names":       []string{"access_token", "jwt_access_token"},
				"key_manager_count": 4,
			},
		},
		{
			name: "directory of private RSA keys and private ECDSA key with default method",
			tokenConfigs: []string{
				`{"token_ecdsa_file": "` + baseDir + `/../../testdata/ecdsakeys/test_1_pri.pem"}`,
				// `{"token_rsa_dir": "./../../testdata/rskeys"}`,
			},
			claims: userClaims,
			want: map[string]interface{}{
				"token_names":       []string{"access_token"},
				"key_manager_count": 1,
			},
		},
		{
			name: "private ECDSA key with ES256",
			tokenConfigs: []string{
				`{"token_ecdsa_file": "` + baseDir + `/../../testdata/ecdsakeys/test_2_pri.pem"}`,
			},
			claims:     userClaims,
			signMethod: "ES256",
			want: map[string]interface{}{
				"token_names":       []string{"access_token"},
				"key_manager_count": 1,
			},
		},
		{
			name: "private ECDSA key with ES384",
			tokenConfigs: []string{
				`{"token_ecdsa_file": "` + baseDir + `/../../testdata/ecdsakeys/test_3_pri.pem"}`,
			},
			claims:     userClaims,
			signMethod: "ES384",
			want: map[string]interface{}{
				"token_names":       []string{"access_token"},
				"key_manager_count": 1,
			},
		},
		{
			name: "private ECDSA key with ES512",
			tokenConfigs: []string{
				`{"token_ecdsa_file": "` + baseDir + `/../../testdata/ecdsakeys/test_4_pri.pem"}`,
			},
			claims: userClaims,
			want: map[string]interface{}{
				"token_names":       []string{"access_token"},
				"key_manager_count": 1,
			},
		},
		{
			name: "with nil sign method",
			tokenConfigs: []string{
				`{"token_secret": "e2c52192-261f-4e8f-ab83-c8eb928a8ddb"}`,
			},
			claims:     userClaims,
			signMethod: nil,
			want: map[string]interface{}{
				"token_names":       []string{"access_token"},
				"key_manager_count": 1,
			},
		},
		{
			name: "grant with nil claims",
			tokenConfigs: []string{
				`{"token_secret": "e2c52192-261f-4e8f-ab83-c8eb928a8ddb"}`,
			},
			skipKeyManagerErr: true,
			shouldErr:         true,
			err:               errors.ErrTokenGrantorNoClaimsFound,
		},
		{
			name: "grant with empty method",
			tokenConfigs: []string{
				`{"token_secret": "e2c52192-261f-4e8f-ab83-c8eb928a8ddb"}`,
			},
			claims:     userClaims,
			signMethod: "",
			want: map[string]interface{}{
				"token_names":       []string{"access_token"},
				"key_manager_count": 1,
			},
		},
		{
			name: "grant with unsupported method",
			tokenConfigs: []string{
				`{"token_secret": "e2c52192-261f-4e8f-ab83-c8eb928a8ddb"}`,
			},
			claims:            userClaims,
			signMethod:        "ES1012",
			skipKeyManagerErr: true,
			shouldErr:         true,
			err:               errors.ErrTokenGrantorNoSigningKeysFound,
		},
		{
			name: "grant with uunsupported sign method",
			tokenConfigs: []string{
				`{"token_secret": "e2c52192-261f-4e8f-ab83-c8eb928a8ddb"}`,
			},
			claims:            userClaims,
			signMethod:        []string{"ES512"},
			skipKeyManagerErr: true,
			shouldErr:         true,
			err:               errors.ErrTokenGrantorNoSigningKeysFound,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// if tc.name != "shared key and directory of private RSA keys" {
			//	return
			// }
			var signedToken string
			g := NewTokenGrantor()
			for _, tokenConfig := range tc.tokenConfigs {
				km, err := kms.NewKeyManager(tokenConfig)
				if !tc.skipKeyManagerErr {
					if tests.EvalErr(t, err, "key manager", tc.shouldErr, tc.err) {
						return
					}
				}
				g.AddKeysFromKeyManager(km)
			}
			err := g.Validate()
			if !tc.skipKeyManagerErr {
				if tests.EvalErr(t, err, "validate key manager", tc.shouldErr, tc.err) {
					return
				}
			}

			var msgs []string
			msgs = append(msgs, fmt.Sprintf("test name: %s", tc.name))
			for _, entry := range tc.tokenConfigs {
				msgs = append(msgs, fmt.Sprintf("token config: %+v", entry))
			}
			msgs = append(msgs, fmt.Sprintf("sign method: %+v", tc.signMethod))

			signedToken, err = g.GrantToken(tc.signMethod, tc.claims)
			if tests.EvalErrWithLog(t, err, "grantor", tc.shouldErr, tc.err, msgs) {
				return
			}
			msgs = append(msgs, fmt.Sprintf("signed token: %s", signedToken))
			got := make(map[string]interface{})
			got["token_names"] = g.GetTokenNames()
			got["key_manager_count"] = len(g.keys)
			tests.EvalObjectsWithLog(t, "token names", tc.want, got, msgs)

		})
	}
}
