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
	"crypto/rsa"

	jwtlib "github.com/dgrijalva/jwt-go"
	jwterrors "github.com/greenpau/caddy-auth-jwt/pkg/errors"
)

var defaultKeyID = "0"

// RSAKeyTokenBackend hold asymentric keys from RS family.
type RSAKeyTokenBackend struct {
	secrets map[string]interface{}
}

// NewRSAKeyTokenBackend returns RSKeyTokenBackend instance.
func NewRSAKeyTokenBackend(k map[string]interface{}) *RSAKeyTokenBackend {
	b := &RSAKeyTokenBackend{
		secrets: k,
	}
	return b
}

// ProvideKey provides key material from RSKeyTokenBackend.
func (b *RSAKeyTokenBackend) ProvideKey(token *jwtlib.Token) (interface{}, error) {
	if _, validMethod := token.Method.(*jwtlib.SigningMethodRSA); !validMethod {
		return nil, jwterrors.ErrUnexpectedSigningMethod.WithArgs("RS", token.Header["alg"])
	}

	// check if we have a "kid" in the header we can use...
	if kid, ok := token.Header["kid"].(string); ok {
		if val, ok := b.secrets[kid]; ok {
			switch key := val.(type) {
			case *rsa.PrivateKey:
				return &key.PublicKey, nil
			case *rsa.PublicKey:
				return key, nil
			default:
				return nil, jwterrors.ErrUnsupportedRSAKeyType.WithArgs(val)
			}
		}
		return nil, jwterrors.ErrUnexpectedKID
	}

	// no kid, then we should have a "0", as that's the default value
	if val, ok := b.secrets[defaultKeyID]; ok {
		switch key := val.(type) {
		case *rsa.PrivateKey:
			return &key.PublicKey, nil
		case *rsa.PublicKey:
			return key, nil
		default:
			return nil, jwterrors.ErrUnsupportedRSAKeyType.WithArgs(val)
		}
	}

	return nil, jwterrors.ErrNoRSAKeyFound
}
