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
	// "crypto/ecdsa"
	// "crypto/rsa"
	jwtlib "github.com/dgrijalva/jwt-go"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"strings"
)

// CanSignToken returns trus if key manager is capable of using the requested
// method for signing.
func (km *KeyManager) CanSignToken(method interface{}) (string, bool) {
	if !km.Sign.Token.Capable {
		return "", false
	}
	if method == nil {
		return km.Sign.Token.DefaultMethod, true
	}
	m := method.(string)
	m = strings.ToUpper(m)
	// Check cached requests.
	if _, exists := km.keyCache[m]; exists {
		return m, true
	}
	// Check for supported signing method.
	for _, key := range km.keys {
		if !key.Sign.Token.Capable {
			continue
		}
		if _, exists := key.Sign.Token.Methods[m]; exists {
			return m, true
		}
	}
	return "", false
}

// SignToken signs data using the requested method and returns it as string.
func (km *KeyManager) SignToken(signMethod, data interface{}) (string, error) {
	if !km.Sign.Token.Capable {
		return "", errors.ErrSigningKeyNotFound.WithArgs(signMethod)
	}
	response, err := km.sign(signMethod, data)
	if err != nil {
		return "", err
	}
	return response.(string), nil
}

// Sign signs data using the requested method.
func (km *KeyManager) sign(signMethod, data interface{}) (interface{}, error) {
	var method string
	if signMethod == nil {
		if km.Sign.Token.DefaultMethod == "" {
			return nil, errors.ErrInvalidSigningMethod
		}
		method = km.Sign.Token.DefaultMethod
	} else {
		method = signMethod.(string)
	}

	for _, key := range km.keys {
		if !key.Sign.Token.Capable {
			continue
		}
		if _, supported := key.Sign.Token.Methods[method]; !supported {
			continue
		}
		response, err := km.signClaims(method, key, data)
		if err != nil {
			continue
		}
		return response, err
	}
	return nil, errors.ErrDataSigningFailed.WithArgs(method, "all keys failed")
}

func (km *KeyManager) signClaims(method string, key *Key, data interface{}) (interface{}, error) {
	if key == nil {
		return nil, errors.ErrDataSigningFailed.WithArgs(method, "key is nil")
	}
	signMethod := jwtlib.GetSigningMethod(method)
	signer := jwtlib.NewWithClaims(signMethod, data.(jwtlib.Claims))
	if key.ID != "" && key.ID != defaultKeyID {
		signer.Header["kid"] = key.ID
	}
	signedData, err := signer.SignedString(key.Secret)
	if err != nil {
		return nil, errors.ErrDataSigningFailed.WithArgs(method, err)
	}
	return signedData, nil
}
