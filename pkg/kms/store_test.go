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
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"github.com/greenpau/caddy-auth-jwt/pkg/tests"
	"testing"
)

func TestKeystoreAdd(t *testing.T) {
	var testcases = []struct {
		name string
		key  *Key
		// expOutput map[string]string
		shouldErr bool
		err       error
	}{
		{
			name:      "add nil key",
			shouldErr: true,
			err:       errors.ErrKeystoreAddKeyNil,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ks := NewKeystore()
			err := ks.Add(tc.key)
			if tests.EvalErr(t, err, nil, tc.shouldErr, tc.err) {
				return
			}
		})
	}
}

/*
func TestKeystoreAdd(t *testing.T) {
	dirCWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	var testcases = []struct {
		name      string
		configs   []string
		expOutput map[string]string
		shouldErr bool
		err       error
	}{
		{
			name:      "add nil key",
			shouldErr: true,
			err:       errors.ErrEncryptionKeysNotFound,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var keyManagers []*KeyManager
			var err error
			if len(tc.configs) > 0 {
				tokenConfig := NewTokenConfig()
				if err = json.Unmarshal([]byte(tc.config), tokenConfig); err != nil {
					t.Fatal(err)
				}
				km, err = NewKeyManager(tokenConfig)
			} else {
				km, err = NewKeyManager(nil)
				keyManager
			}

			if tests.EvalErr(t, err, km, tc.shouldErr, tc.err) {
				return
			}

			var mm map[string]string
			_, keys := km.GetKeys()
			if keys != nil {
				mm = make(map[string]string)
			}
			for kid, key := range keys {
				mm[kid] = fmt.Sprintf("%T", key.Secret)
			}
			tests.EvalObjects(t, "output", tc.expOutput, mm)
		})
	}
}
*/
