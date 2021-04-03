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

package backends

import (
	jwtlib "github.com/dgrijalva/jwt-go"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
)

// TokenBackend is the interface to provide key material.
type TokenBackend interface {
	ProvideKey(token *jwtlib.Token) (interface{}, error)
}

// SecretKeyTokenBackend hold symentric keys from HS family.
type SecretKeyTokenBackend struct {
	secret []byte
}

// NewSecretKeyTokenBackend returns SecretKeyTokenBackend instance.
func NewSecretKeyTokenBackend(m map[string]interface{}) (*SecretKeyTokenBackend, error) {
	if m == nil {
		return nil, errors.ErrInvalidSecret.WithArgs("key is nil")
	}
	key, found := m["0"]
	if !found {
		return nil, errors.ErrInvalidSecret.WithArgs("no key found")
	}
	s, ok := key.(string)
	if !ok {
		return nil, errors.ErrInvalidSecret.WithArgs("key is not string")
	}
	if s == "" {
		return nil, errors.ErrInvalidSecret.WithArgs("key is empty")
	}
	if len(s) < 16 {
		return nil, errors.ErrInvalidSecretLength
	}
	b := &SecretKeyTokenBackend{
		secret: []byte(s),
	}
	return b, nil
}

// ProvideKey provides key material from SecretKeyTokenBackend.
func (b *SecretKeyTokenBackend) ProvideKey(token *jwtlib.Token) (interface{}, error) {
	if _, validMethod := token.Method.(*jwtlib.SigningMethodHMAC); !validMethod {
		return nil, errors.ErrUnexpectedSigningMethod.WithArgs("HS", token.Header["alg"])
	}
	return b.secret, nil
}
