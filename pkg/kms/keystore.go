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

// CryptoKeyStore constains keys assembled for a specific purpose, i.e. signing or
// validation.
type CryptoKeyStore struct {
	keys       []*CryptoKey
	signKeys   []*CryptoKey
	verifyKeys []*CryptoKey
}

// NewCryptoKeyStore returns a new instance of CryptoKeyStore
func NewCryptoKeyStore() *CryptoKeyStore {
	ks := &CryptoKeyStore{}
	return ks
}

// AddKeys adds CryptoKey instances to CryptoKeyStore.
func (ks *CryptoKeyStore) AddKeys(keys []*CryptoKey) error {
	for _, k := range keys {
		if err := ks.AddKey(k); err != nil {
			return err
		}
	}
	return nil
}

// AddKey adds CryptoKey instance to CryptoKeyStore.
func (ks *CryptoKeyStore) AddKey(k *CryptoKey) error {
	if k == nil {
		return errors.ErrCryptoKeyStoreAddKeyNil
	}
	if k.Sign.Capable {
		ks.signKeys = append(ks.signKeys, k)
	}
	if k.Verify.Capable {
		ks.verifyKeys = append(ks.verifyKeys, k)
	}
	ks.keys = append(ks.keys, k)
	return nil
}

// ParseToken parses JWT token and returns User instance.
func (ks *CryptoKeyStore) ParseToken(tokenName, token string) (*user.User, error) {
	for _, k := range ks.verifyKeys {
		if tokenName != k.Verify.Token.Name {
			continue
		}
		parsedToken, err := jwtlib.Parse(token, k.ProvideKey)
		if err != nil {
			continue
		}
		userData := make(map[string]interface{})
		for k, v := range parsedToken.Claims.(jwtlib.MapClaims) {
			userData[k] = v
		}
		usr, err := user.NewUser(userData)
		if err != nil {
			continue
		}
		return usr, nil
	}
	return nil, errors.ErrCryptoKeyStoreParseTokenFailed
}

// SignToken signs user claims and add signed token to user identity.
func (ks *CryptoKeyStore) SignToken(tokenName, signMethod interface{}, usr *user.User) error {
	for _, k := range ks.signKeys {
		if tokenName != k.Sign.Token.Name {
			continue
		}
		response, err := k.sign(signMethod, *usr.Claims)
		if err != nil {
			return err
		}
		usr.Token = response.(string)
		return nil
	}
	return errors.ErrCryptoKeyStoreSignTokenFailed
}
