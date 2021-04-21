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
	jwtlib "github.com/dgrijalva/jwt-go"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"github.com/greenpau/caddy-auth-jwt/pkg/user"
)

// Keystore constains keys assembled for a specific purpose, i.e. signing or
// validation.
type Keystore struct {
	keys []*Key
}

// NewKeystore returns a new instance of Keystore
func NewKeystore() *Keystore {
	ks := &Keystore{
		keys: []*Key{},
	}
	return ks
}

// AddKeys adds a key to keystore.
func (ks *Keystore) AddKeys(keys []*Key) error {
	for _, k := range keys {
		if err := ks.AddKey(k); err != nil {
			return err
		}
	}
	return nil
}

// AddKey adds a key to keystore.
func (ks *Keystore) AddKey(k *Key) error {
	if k == nil {
		return errors.ErrKeystoreAddKeyNil
	}
	ks.keys = append(ks.keys, k)
	return nil
}

// ParseToken parses JWT token and returns User instance.
func (ks *Keystore) ParseToken(s string) (*user.User, error) {
	for _, k := range ks.keys {
		token, err := jwtlib.Parse(s, k.ProvideKey)
		if err != nil {
			continue
		}
		if !token.Valid {
			continue
		}
		userData := make(map[string]interface{})
		for k, v := range token.Claims.(jwtlib.MapClaims) {
			userData[k] = v
		}
		usr, err := user.NewUser(userData)
		if err != nil {
			continue
		}
		return usr, nil
	}
	return nil, errors.ErrKeystoreParseTokenFailed
}
