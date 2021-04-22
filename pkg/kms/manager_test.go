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
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"github.com/greenpau/caddy-auth-jwt/pkg/tests"
	"os"
	"testing"
)

func TestAddKeyManagerKey(t *testing.T) {
	var testcases = []struct {
		name      string
		kid       string
		initKey   bool
		shouldErr bool
		err       error
	}{
		{
			name:    "empty kid",
			initKey: true,
		},
		{
			name:      "nil key",
			kid:       "foo",
			shouldErr: true,
			err:       errors.ErrKeyManagerAddKeyNil,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var key *Key
			km := &KeyManager{}
			km.keys = make(map[string]*Key)
			if tc.initKey {
				key = newKey()
			}
			err := km.addKey(tc.kid, key)

			if tests.EvalErr(t, err, km, tc.shouldErr, tc.err) {
				return
			}
		})
	}
}

func TestNewKeyManager(t *testing.T) {
	dirCWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	var testcases = []struct {
		name       string
		config     interface{}
		skipConfig bool
		overwrites map[string]interface{}
		want       map[string]interface{}
		shouldErr  bool
		err        error
	}{
		{
			name: "private ECDSA key",
			config: `{
				"token_ecdsa_file": "` + dirCWD + `/../../testdata/ecdsakeys/test_1_pri.pem"
			}`,
			want: map[string]interface{}{
				"keys": map[string]string{
					"0": "*ecdsa.PrivateKey",
				},
				"origin":                       "config",
				"sign_token_default_method":    "ES256",
				"sign_token_preferred_methods": []string{"ES256"},
				"sign_token_capable":           true,
				"type":                         "ecdsa",
			},
			shouldErr: false,
		},
		{
			name: "private ECDSA key with origin overwrite",
			config: `{
                "token_ecdsa_file": "` + dirCWD + `/../../testdata/ecdsakeys/test_1_pri.pem"
            }`,
			want: map[string]interface{}{
				"keys": map[string]string{
					"0": "*ecdsa.PrivateKey",
				},
				"origin":                       "unknown",
				"sign_token_default_method":    "ES256",
				"sign_token_preferred_methods": []string{"ES256"},
				"sign_token_capable":           true,
				"type":                         "ecdsa",
			},
			overwrites: map[string]interface{}{
				"origin": "",
			},
			shouldErr: false,
		},
		{
			name:       "key not found",
			skipConfig: true,
			shouldErr:  true,
			err:        errors.ErrEncryptionKeysNotFound,
		},
		{
			name:      "token config with bad type",
			config:    123,
			shouldErr: true,
			err:       errors.ErrKeyManagerCryptoKeyConfigInvalidType.WithArgs(123),
		},
		{
			name:      "token config with malformed json",
			config:    `{"foobar`,
			shouldErr: true,
			err:       errors.ErrCryptoKeyConfigNewFailedUnmarshal.WithArgs("unexpected end of JSON input"),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var km *KeyManager
			var err error
			if tc.skipConfig {
				km, err = NewKeyManager(nil)
			} else {
				km, err = NewKeyManager(tc.config)
			}
			if tests.EvalErr(t, err, km, tc.shouldErr, tc.err) {
				return
			}
			if tc.overwrites != nil {
				// Overwrite some values of key manager for testing purposes.
				for k, v := range tc.overwrites {
					switch k {
					case "origin":
						km.keyOrigin = v.(string)
					}
				}
			}

			var signTokenDefaultMethod string
			var signTokenPreferredMethods []string
			var signTokenCapable bool

			got := make(map[string]interface{})
			_, keys := km.GetKeys()
			if keys != nil {
				gotKeys := make(map[string]string)
				for kid, key := range keys {
					if key.Sign.Token.Capable {
						gotKeys[kid] = fmt.Sprintf("%T", key.Sign.Secret)
						signTokenCapable = true
						signTokenPreferredMethods = key.Sign.Token.PreferredMethods
						signTokenDefaultMethod = key.Sign.Token.DefaultMethod
					} else {
						gotKeys[kid] = fmt.Sprintf("%T", key.Verify.Secret)
					}
				}
				got["keys"] = gotKeys
			}
			got["origin"] = km.GetOrigin()
			got["type"] = km.GetType()
			got["sign_token_default_method"] = signTokenDefaultMethod
			got["sign_token_capable"] = signTokenCapable
			got["sign_token_preferred_methods"] = signTokenPreferredMethods
			tests.EvalObjects(t, "output", tc.want, got)
		})
	}
}
