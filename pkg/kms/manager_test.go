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

func TestNewKeyManager(t *testing.T) {
	dirCWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	var testcases = []struct {
		name       string
		config     string
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
			name:      "key not found",
			shouldErr: true,
			err:       errors.ErrEncryptionKeysNotFound,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var km *KeyManager
			var err error
			if tc.config == "" {
				km, err = NewKeyManager(nil)
			} else {
				tokenConfig, err := NewTokenConfig(tc.config)
				if err != nil {
					t.Fatal(err)
				}
				km, err = NewKeyManager(tokenConfig)
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

			got := make(map[string]interface{})
			_, keys := km.GetKeys()
			if keys != nil {
				gotKeys := make(map[string]string)
				for kid, key := range keys {
					gotKeys[kid] = fmt.Sprintf("%T", key.Secret)
				}
				got["keys"] = gotKeys
			}
			got["origin"] = km.GetOrigin()
			got["type"] = km.GetType()
			got["sign_token_default_method"] = km.Sign.Token.DefaultMethod
			got["sign_token_capable"] = km.Sign.Token.Capable
			got["sign_token_preferred_methods"] = km.Sign.Token.PreferredMethods
			tests.EvalObjects(t, "output", tc.want, got)
		})
	}
}
