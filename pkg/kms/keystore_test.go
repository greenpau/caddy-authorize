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
	jwtlib "github.com/golang-jwt/jwt"
	"github.com/greenpau/caddy-auth-jwt/internal/tests"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"github.com/greenpau/caddy-auth-jwt/pkg/user"
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

func TestKeystoreOperators(t *testing.T) {
	testcases := []struct {
		name            string
		config          string
		signTokenName   string
		signAlgorithm   string
		verifyTokenName string
		sign            bool
		user            *user.User
		claims          *TestUserClaims
		roles           []string
		addr            string
		operatorErr     bool
		operatorSignErr bool
		err             error
		shouldErr       bool
	}{
		{
			name:   "user with roles claims and ip address",
			config: `crypto key sign-verify foobar`,
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
			name:   "user with groups claims and ip address",
			config: `crypto key sign-verify foobar`,
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
			name:   "user with role claim and ip address",
			config: `crypto key sign-verify foobar`,
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
			name:   "user with group claim and ip address",
			config: `crypto key sign-verify foobar`,
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
			name:   "user with expired token",
			config: `crypto key sign-verify foobar`,
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
			name:   "user with not yet ready token",
			config: `crypto key sign-verify foobar`,
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
		{
			name:      "nil keys",
			shouldErr: true,
			err:       errors.ErrCryptoKeyStoreAddKeyNil,
		},
		{
			name:            "token name mismatch",
			config:          `crypto key sign-verify foobar`,
			verifyTokenName: `foobar`,
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
			roles:     []string{"admin"},
			addr:      "192.168.1.1",
			shouldErr: true,
			err:       errors.ErrKeystoreParseTokenFailed,
		},
		{
			name:            "failed verification",
			config:          `crypto key sign-verify foobar`,
			sign:            true,
			signAlgorithm:   "HS512",
			verifyTokenName: `foobar`,
			user:            newTestUser(),
			operatorErr:     true,
			shouldErr:       true,
			err:             errors.ErrKeystoreParseTokenFailed,
		},
		{
			name:            "failed signing due to algo mismatch",
			config:          `crypto key sign-verify foobar`,
			sign:            true,
			signAlgorithm:   "RS512",
			verifyTokenName: `foobar`,
			user:            newTestUser(),
			operatorErr:     true,
			operatorSignErr: true,
			shouldErr:       true,
			err:             errors.ErrUnsupportedSigningMethod.WithArgs("RS512"),
		},
		{
			name:            "failed signing due to token name mismatch",
			config:          `crypto key sign-verify foobar`,
			sign:            true,
			signAlgorithm:   "RS512",
			signTokenName:   `foobar`,
			user:            newTestUser(),
			operatorErr:     true,
			operatorSignErr: true,
			shouldErr:       true,
			err:             errors.ErrCryptoKeyStoreSignTokenFailed,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var signedToken string
			var msgs []string
			var keys []*CryptoKey
			msgs = append(msgs, fmt.Sprintf("test name: %s", tc.name))
			if tc.config != "" {
				configs, err := ParseCryptoKeyConfigs(tc.config)
				if err != nil {
					t.Fatalf("failed parsing configs: %v", err)
				}
				keys, err = GetKeysFromConfigs(configs)
				if err != nil {
					t.Fatalf("failed getting keys from configs: %v", err)
				}
			} else {
				keys = []*CryptoKey{nil}
			}

			ks := NewCryptoKeyStore()
			if err := ks.AddKeys(keys); err != nil {
				if !tc.operatorErr {
					if tests.EvalErrWithLog(t, err, "add keys", tc.shouldErr, tc.err, msgs) {
						return
					}
					t.Fatalf("failed adding keys to crypto key store: %v", err)
				}
			}

			privKey := keys[0]
			// pubKey := keys[0]
			// if err := ks.SignToken(privKey.Sign.Token.Name, privKey.Sign.Token.DefaultMethod, usr); err != nil {
			//   t.Fatal(err)
			// }
			if tc.signTokenName == "" {
				tc.signTokenName = privKey.Sign.Token.Name
			}

			if tc.sign {
				err := ks.SignToken(tc.signTokenName, tc.signAlgorithm, tc.user)
				if tc.operatorSignErr {
					if tests.EvalErrWithLog(t, err, "sign token", tc.shouldErr, tc.err, msgs) {
						return
					}
				}
			} else {
				token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS512, tc.claims)
				var err error
				signedToken, err = token.SignedString(privKey.Sign.Secret)
				if err != nil {
					t.Fatalf("failed signing claims: %s", err)
				}
			}

			msgs = append(msgs, fmt.Sprintf("signed token: %s", signedToken))

			if tc.verifyTokenName == "" {
				tc.verifyTokenName = privKey.Sign.Token.Name
			}
			usr, err := ks.ParseToken(tc.verifyTokenName, signedToken)
			if tests.EvalErrWithLog(t, err, "parse token", tc.shouldErr, tc.err, msgs) {
				return
			}

			msgs = append(msgs, fmt.Sprintf("parsed claims: %v", usr.Claims))
			msgs = append(msgs, fmt.Sprintf("roles: %v", usr.Claims.Roles))
			if len(tc.roles) > 0 {
				tests.EvalObjectsWithLog(t, "roles", tc.roles, usr.Claims.Roles, msgs)
			}
		})
	}
}

func TestCryptoKeyStoreAutoGenerate(t *testing.T) {
	var testcases = []struct {
		name      string
		tag       string
		algorithm string
		shouldErr bool
		err       error
	}{
		{
			name:      "generate es512 key pair",
			tag:       "default",
			algorithm: "ES512",
			// shouldErr: true,
			//err:       fmt.Errorf(`kms: file "foo" is not supported due to extension type`),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("algorithm: %s", tc.algorithm))
			ks := NewCryptoKeyStore()
			err := ks.AutoGenerate(tc.tag, tc.algorithm)
			if tests.EvalErrWithLog(t, err, nil, tc.shouldErr, tc.err, msgs) {
				return
			}
		})
	}
}
