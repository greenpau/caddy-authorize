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
	"github.com/greenpau/caddy-auth-jwt/pkg/claims"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
)

// Keystore constains keys assembled for a specific purpose, i.e. signing or
// validation.
type Keystore struct {
	keys []*Key
}

// Key contains a valid encryption key.
type Key struct {
	Name   string
	ID     string
	Type   string
	Source string
	Path   string
	Data   string
	Sign   *KeyOp
	Verify *KeyOp
	Secret interface{}
}

// KeyOp are the operations supported by the key.
type KeyOp struct {
	Token struct {
		Methods          map[string]interface{}
		PreferredMethods []string
		DefaultMethod    string
		Capable          bool
	}
	Capable bool
}

func newKeyOp() *KeyOp {
	op := &KeyOp{}
	op.Token.Methods = make(map[string]interface{})
	return op
}

func newKey() *Key {
	k := &Key{}
	k.Sign = newKeyOp()
	k.Verify = newKeyOp()
	return k
}

// ProvideKey returns the appropriate encrypton key.
func (k *Key) ProvideKey(token *jwtlib.Token) (interface{}, error) {
	if _, validMethod := token.Method.(*jwtlib.SigningMethodHMAC); !validMethod {
		return nil, errors.ErrUnexpectedSigningMethod.WithArgs("HS", token.Header["alg"])
	}
	return k.Secret, nil
}

// NewKeystore returns a new instance of Keystore
func NewKeystore() *Keystore {
	ks := &Keystore{
		keys: []*Key{},
	}
	return ks
}

// Add adds a key to keystore.
func (ks *Keystore) Add(k *Key) error {
	if k == nil {
		return errors.ErrKeystoreAddKeyNil
	}
	ks.keys = append(ks.keys, k)
	return nil
}

// ParseToken parses JWT token and returns user claims.
func (ks *Keystore) ParseToken(s string) (*claims.UserClaims, error) {
	// TODO(greenpau): Private Key vs. Public Key
	for _, k := range ks.keys {
		token, err := jwtlib.Parse(s, k.ProvideKey)
		if err != nil {
			continue
		}
		if !token.Valid {
			continue
		}
		return claims.ParseClaims(token)
	}
	return nil, errors.ErrKeystoreAddKeyNil
}
