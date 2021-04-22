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

package kms

import (
	"fmt"
	jwtlib "github.com/dgrijalva/jwt-go"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"github.com/greenpau/caddy-auth-jwt/pkg/tests"
	"testing"
	"time"
)

type TestUserClaims struct {
	Roles         []string               `json:"roles,omitempty" xml:"roles" yaml:"roles,omitempty"`
	Role          string                 `json:"role,omitempty" xml:"role" yaml:"role,omitempty"`
	Groups        []string               `json:"groups,omitempty" xml:"groups" yaml:"groups,omitempty"`
	Group         string                 `json:"group,omitempty" xml:"group" yaml:"group,omitempty"`
	Organizations []string               `json:"org,omitempty" xml:"org" yaml:"org,omitempty"`
	Address       string                 `json:"addr,omitempty" xml:"addr" yaml:"addr,omitempty"`
	AppMetadata   map[string]interface{} `json:"app_metadata,omitempty" xml:"app_metadata" yaml:"app_metadata,omitempty"`
	jwtlib.StandardClaims
}

func TestKeystoreAdd(t *testing.T) {
	var testcases = []struct {
		name      string
		key       *Key
		batch     bool
		shouldErr bool
		err       error
	}{
		{
			name:      "add nil key",
			shouldErr: true,
			err:       errors.ErrKeystoreAddKeyNil,
		},
		{
			name:      "add nil key",
			batch:     true,
			shouldErr: true,
			err:       errors.ErrKeystoreAddKeyNil,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			ks := NewKeystore()
			if tc.batch {
				err = ks.AddKeys([]*Key{tc.key})
			} else {
				err = ks.AddKey(tc.key)
			}
			if tests.EvalErr(t, err, nil, tc.shouldErr, tc.err) {
				return
			}
		})
	}
}

func TestReadUserClaims(t *testing.T) {
	secret := "75f03764-147c-4d87-b2f0-4fda89e331c8"
	testcases := []struct {
		name      string
		claims    *TestUserClaims
		roles     []string
		addr      string
		err       error
		shouldErr bool
	}{
		{
			name: "user with roles claims and ip address",
			claims: &TestUserClaims{
				Roles: []string{"admin", "editor", "viewer"},
				StandardClaims: jwtlib.StandardClaims{
					ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
					IssuedAt:  time.Now().Add(10 * time.Minute * -1).Unix(),
					NotBefore: time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
					Subject:   "smithj@outlook.com",
				},
			},
			roles: []string{"admin", "editor", "viewer"},
			addr:  "127.0.0.1",
		},
		{
			name: "user with groups claims and ip address",
			claims: &TestUserClaims{
				Groups: []string{"admin", "editor", "viewer"},
				StandardClaims: jwtlib.StandardClaims{
					ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
					IssuedAt:  time.Now().Add(10 * time.Minute * -1).Unix(),
					NotBefore: time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
					Subject:   "smithj@outlook.com",
				},
			},
			roles: []string{"admin", "editor", "viewer"},
			addr:  "127.0.0.1",
		},
		{
			name: "user with role claim and ip address",
			claims: &TestUserClaims{
				Role:    "admin",
				Address: "192.168.1.1",
				StandardClaims: jwtlib.StandardClaims{
					ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
					IssuedAt:  time.Now().Add(10 * time.Minute * -1).Unix(),
					NotBefore: time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
					Subject:   "smithj@outlook.com",
				},
			},
			roles: []string{"admin"},
			addr:  "192.168.1.1",
		},
		{
			name: "user with group claim and ip address",
			claims: &TestUserClaims{
				Group:   "admin",
				Address: "192.168.1.1",
				StandardClaims: jwtlib.StandardClaims{
					ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
					IssuedAt:  time.Now().Add(10 * time.Minute * -1).Unix(),
					NotBefore: time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
					Subject:   "smithj@outlook.com",
				},
			},
			roles: []string{"admin"},
			addr:  "192.168.1.1",
		},
		{
			name: "user with expired token",
			claims: &TestUserClaims{
				Roles: []string{"admin", "editor", "viewer"},
				StandardClaims: jwtlib.StandardClaims{
					ExpiresAt: time.Now().Add(5 * time.Minute * -1).Unix(),
					IssuedAt:  time.Now().Add(10 * time.Minute * -1).Unix(),
					NotBefore: time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
					Subject:   "smithj@outlook.com",
				},
			},
			roles:     []string{"admin", "editor", "viewer"},
			addr:      "127.0.0.1",
			shouldErr: true,
			err:       errors.ErrKeystoreParseTokenFailed,
		},

		{
			name: "user with noy yet ready token",
			claims: &TestUserClaims{
				Roles: []string{"admin", "editor", "viewer"},
				AppMetadata: map[string]interface{}{
					"authorization": map[string]interface{}{
						"roles": []interface{}{
							1, 2, 3,
						},
					},
				},
				StandardClaims: jwtlib.StandardClaims{
					ExpiresAt: time.Now().Add(20 * time.Minute).Unix(),
					IssuedAt:  time.Now().Add(10 * time.Minute * -1).Unix(),
					NotBefore: time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
					Subject:   "smithj@outlook.com",
				},
			},
			roles:     []string{"admin", "editor", "viewer"},
			addr:      "127.0.0.1",
			shouldErr: true,
			err:       errors.ErrKeystoreParseTokenFailed,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var msgs []string
			msgs = append(msgs, fmt.Sprintf("test name: %s", tc.name))
			tokenConfig := `{"token_secret": "` + secret + `"}`
			ks := NewKeystore()
			km, _ := NewKeyManager(tokenConfig)
			verifyKeys := GetVerifyKeys([]*KeyManager{km})
			if err := ks.AddKeys(verifyKeys); err != nil {
				t.Fatalf("failed to load verification keys: %v", err)
			}
			sharedSecret := []byte(secret)
			token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, tc.claims)
			signedToken, err := token.SignedString(sharedSecret)
			if err != nil {
				t.Fatalf("failed signing claims: %s", err)
			}
			msgs = append(msgs, fmt.Sprintf("signed token: %s", signedToken))

			usr, err := ks.ParseToken(signedToken)
			if tests.EvalErrWithLog(t, err, "parse token", tc.shouldErr, tc.err, msgs) {
				return
			}

			msgs = append(msgs, fmt.Sprintf("parsed claims: %v", usr.Claims))
			msgs = append(msgs, fmt.Sprintf("roles: %v", usr.Claims.Roles))
			tests.EvalObjectsWithLog(t, "roles", tc.roles, usr.Claims.Roles, msgs)
		})
	}
}
