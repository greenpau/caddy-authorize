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
	"crypto/ecdsa"
	"crypto/rsa"
	jwtlib "github.com/dgrijalva/jwt-go"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"strings"
)

type cachedKeyManagerEntry struct {
	Method string
	Header map[string]string
	Secret interface{}
}

// SetSigningMethod sets preferred signing method.
func (km *KeyManager) SetSigningMethod(s string) error {
	s = strings.ToUpper(s)
	if _, exists := SigningMethods[s]; !exists {
		return errors.ErrInvalidSigningMethod
	}
	km.TokenSignMethod = s
	km.defaultSignMethod = s
	return nil
}

// CanSign returns trus if key manager is capable of using the requested
// method for signing.
func (km *KeyManager) CanSign(method interface{}) (string, bool) {
	if method != nil {
		m := method.(string)
		m = strings.ToUpper(m)
		// Check cached requests.
		if _, exists := km.keyCache[m]; exists {
			return m, true
		}
		// Check for supported signing method.
		if _, exists := SigningMethods[m]; !exists {
			return "UNKNOWN", false
		}
		return m, true
	}
	if km.defaultSignMethod != "" {
		return km.defaultSignMethod, true
	}
	switch km.GetKeyType() {
	case "hmac":
		return "HS512", true
	case "rsa":
		return "RS512", true
	case "ecdsa":
		return "ES512", true
	}
	return "UNKNOWN", false
}

// SignToken signs data using the requested method and returns it as string.
func (km *KeyManager) SignToken(signMethod, data interface{}) (string, error) {
	response, err := km.Sign(signMethod, data)
	if err != nil {
		return "", err
	}
	return response.(string), nil
}

// Sign signs data using the requested method.
func (km *KeyManager) Sign(signMethod, data interface{}) (interface{}, error) {
	var method string
	if signMethod == nil {
		m, ok := km.CanSign(signMethod)
		if !ok {
			return nil, errors.ErrInvalidSigningMethod
		}
		method = m
	} else {
		method = signMethod.(string)
	}

	var secret interface{}
	if _, exists := SigningMethods[method]; !exists {
		return nil, errors.ErrInvalidSigningMethod
	}

	if entry, exists := km.keyCache[method]; exists {
		return km.signClaims(entry, data)
	}

	var response interface{}
	var err error

	// signer.Header["typ"] = method
	switch GetSigningMethodAlias(method) {
	case "hmac":
		secret = []byte(km.keys[defaultKeyID].(string))
		entry := &cachedKeyManagerEntry{
			Secret: secret,
			Method: method,
		}
		return km.signClaims(entry, data)
	case "rsa":
		// The RS keys are capable of encrypting RS256, RS384, RS512.
		for kid, key := range km.keys {
			if _, found := key.(*rsa.PrivateKey); !found {
				continue
			}
			entry := &cachedKeyManagerEntry{
				Header: map[string]string{
					"kid": kid,
				},
				Secret: key,
				Method: method,
			}
			response, err = km.signClaims(entry, data)
			if err != nil {
				continue
			}
			return response, nil
		}
	case "ecdsa":
		// The ECDSA keys are capable of encrypting according to their curves.
		privateKeys := make(map[string]string)
		for kid, key := range km.keys {
			if _, found := key.(*ecdsa.PrivateKey); !found {
				continue
			}
			privateKey := key.(*ecdsa.PrivateKey)
			privateKeyCurve := privateKey.Curve.Params()
			if privateKeyCurve == nil {
				continue
			}
			switch privateKeyCurve.Name {
			case "P-256":
				privateKeys[kid] = "ES256"
			case "P-384":
				privateKeys[kid] = "ES384"
			case "P-521":
				privateKeys[kid] = "ES512"
			default:
				continue
			}
			if privateKeys[kid] != method {
				continue
			}
			entry := &cachedKeyManagerEntry{
				Header: map[string]string{
					"kid": kid,
				},
				Secret: privateKey,
				Method: method,
			}
			response, err = km.signClaims(entry, data)
			if err != nil {
				continue
			}
			return response, nil
		}
		for _, methodName := range []string{"ES512", "ES384", "ES256"} {
			for kid, keyMethodName := range privateKeys {
				if methodName != keyMethodName {
					continue
				}
				entry := &cachedKeyManagerEntry{
					Header: map[string]string{
						"kid": kid,
					},
					Secret: km.keys[kid],
					Method: methodName,
				}
				response, err = km.signClaims(entry, data)
				if err != nil {
					continue
				}
				return response, nil
			}
		}

	}
	return nil, errors.ErrSigningKeyNotFound.WithArgs(method)
}

func (km *KeyManager) signClaims(key *cachedKeyManagerEntry, data interface{}) (interface{}, error) {
	signMethod := jwtlib.GetSigningMethod(key.Method)
	signer := jwtlib.NewWithClaims(signMethod, data.(jwtlib.Claims))
	if key.Header != nil {
		for k, v := range key.Header {
			signer.Header[k] = v
		}
	}
	signedData, err := signer.SignedString(key.Secret)
	if err != nil {
		return nil, errors.ErrDataSigningFailed.WithArgs(key.Method, err)
	}
	km.keyCache[key.Method] = key
	km.defaultSignMethod = key.Method
	return signedData, nil
}
