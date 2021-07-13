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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	jwtlib "github.com/golang-jwt/jwt"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"github.com/greenpau/caddy-auth-jwt/pkg/shared"
	"github.com/greenpau/caddy-auth-jwt/pkg/user"
	"go.uber.org/zap"
	"strings"
)

var (
	reservedTokenNames = map[string]bool{
		"access_token":     true,
		"jwt_access_token": true,
		"bearer":           true,
	}
)

// CryptoKeyStore constains keys assembled for a specific purpose, i.e. signing or
// validation.
type CryptoKeyStore struct {
	keys       []*CryptoKey
	signKeys   []*CryptoKey
	verifyKeys []*CryptoKey
	logger     *zap.Logger
}

// NewCryptoKeyStore returns a new instance of CryptoKeyStore
func NewCryptoKeyStore() *CryptoKeyStore {
	ks := &CryptoKeyStore{}
	return ks
}

// SetLogger adds a logger to CryptoKeyStore.
func (ks *CryptoKeyStore) SetLogger(logger *zap.Logger) {
	ks.logger = logger
}

// AutoGenerate auto-generates public-private key pair capable of both
// signing and verifying tokens.
func (ks *CryptoKeyStore) AutoGenerate(tag, algo string) error {
	var generated bool
	var kb string
	cfg := &CryptoKeyConfig{
		ID:            "0",
		Usage:         "sign-verify",
		TokenName:     "access_token",
		Source:        "config",
		TokenLifetime: 900,
		parsed:        true,
	}

	if len(ks.keys) > 0 {
		return errors.ErrCryptoKeyStoreAutoGenerateNotAvailable
	}

	for i := 1; i < 5; i++ {
		switch algo {
		case "ES512":
			c := elliptic.P521()
			priv, err := ecdsa.GenerateKey(c, rand.Reader)
			if err != nil {
				break
			}
			if !c.IsOnCurve(priv.PublicKey.X, priv.PublicKey.Y) {
				break
			}
			derBytes, err := x509.MarshalECPrivateKey(priv)
			if err != nil {
				break
			}
			pemBytes := pem.EncodeToMemory(
				&pem.Block{
					Type:  "EC PRIVATE KEY",
					Bytes: derBytes,
				},
			)
			if pemBytes == nil {
				break
			}
			kb = string(pemBytes)
			generated = true

		default:
			return errors.ErrCryptoKeyStoreAutoGenerateAlgo.WithArgs(algo)
		}
	}

	if !generated {
		return errors.ErrCryptoKeyStoreAutoGenerateFailed.WithArgs("failed")
	}

	if err := shared.Buffer.Add(tag, kb); err != nil {
		if err.Error() != "not empty" {
			return errors.ErrCryptoKeyStoreAutoGenerateFailed.WithArgs(err)
		}
		kb, err = shared.Buffer.Get(tag)
		if err != nil {
			return errors.ErrCryptoKeyStoreAutoGenerateFailed.WithArgs(err)
		}
	}
	key, err := extractKey([]byte(kb), cfg)
	if err != nil {
		return errors.ErrCryptoKeyStoreAutoGenerateFailed.WithArgs(err)
	}

	key.enableUsage()
	ks.keys = append(ks.keys, key)
	ks.signKeys = append(ks.signKeys, key)
	ks.verifyKeys = append(ks.verifyKeys, key)
	return nil
}

// GetKeys returns CryptoKey instances from CryptoKeyStore.
func (ks *CryptoKeyStore) GetKeys() []*CryptoKey {
	return ks.keys
}

// GetSignKeys returns CryptoKey instances with key signing capabilities
// from CryptoKeyStore.
func (ks *CryptoKeyStore) GetSignKeys() []*CryptoKey {
	return ks.signKeys
}

// GetVerifyKeys returns CryptoKey instances with key verification capabilities
// from CryptoKeyStore.
func (ks *CryptoKeyStore) GetVerifyKeys() []*CryptoKey {
	return ks.verifyKeys
}

// AddKeysWithConfigs adds CryptoKey instances by providing their
// configurations to CryptoKeyStore.
func (ks *CryptoKeyStore) AddKeysWithConfigs(cfgs []*CryptoKeyConfig) error {
	keys, err := GetKeysFromConfigs(cfgs)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if err := ks.AddKey(k); err != nil {
			return err
		}
	}
	return nil
}

// HasVerifyKeys returns true if CryptoKeyStore has key verification
// capabilities.
func (ks *CryptoKeyStore) HasVerifyKeys() error {
	if len(ks.verifyKeys) > 0 {
		return nil
	}
	return errors.ErrCryptoKeyStoreNoVerifyKeysFound
}

// HasSignKeys returns true if CryptoKeyStore has key signing
// capabilities.
func (ks *CryptoKeyStore) HasSignKeys() error {
	if len(ks.signKeys) > 0 {
		return nil
	}
	return errors.ErrCryptoKeyStoreNoSignKeysFound
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
	if k.Sign != nil {
		if k.Sign.Capable {
			ks.signKeys = append(ks.signKeys, k)
		}
	}
	if k.Verify != nil {
		if k.Verify.Capable {
			ks.verifyKeys = append(ks.verifyKeys, k)
		}
	}
	if k.Verify == nil && k.Sign == nil {
		return errors.ErrCryptoKeyStoreAddKeyNil
	}
	ks.keys = append(ks.keys, k)
	return nil
}

// ParseToken parses JWT token and returns User instance.
func (ks *CryptoKeyStore) ParseToken(tokenName, token string) (*user.User, error) {
	var issuerURL string
	for _, k := range ks.verifyKeys {
		if _, exists := reservedTokenNames[tokenName]; !exists {
			if tokenName != k.Verify.Token.Name {
				continue
			}
		}
		parsedToken, err := jwtlib.Parse(token, k.ProvideKey)
		if err != nil {
			if strings.Contains(err.Error(), "is expired") {
				for k, v := range parsedToken.Claims.(jwtlib.MapClaims) {
					if k == "iss" {
						issuerURL = v.(string)
					}
				}
			}
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
	if issuerURL != "" {
		usr := &user.User{}
		usr.Authenticator.URL = issuerURL
		return usr, errors.ErrCryptoKeyStoreParseTokenFailed
	}
	return nil, errors.ErrCryptoKeyStoreParseTokenFailed
}

// SignToken signs user claims and add signed token to user identity.
func (ks *CryptoKeyStore) SignToken(tokenName, signMethod interface{}, usr *user.User) error {
	for _, k := range ks.signKeys {
		if tokenName != nil {
			if tokenName.(string) != k.Sign.Token.Name {
				continue
			}
		}
		response, err := k.sign(signMethod, *usr.Claims)
		if err != nil {
			return err
		}
		usr.Token = response.(string)
		usr.TokenName = k.Sign.Token.Name
		return nil
	}
	return errors.ErrCryptoKeyStoreSignTokenFailed
}

// GetTokenLifetime returns lifetime for a signed token.
func (ks *CryptoKeyStore) GetTokenLifetime(tokenName, signMethod interface{}) int {
	for _, k := range ks.signKeys {
		if tokenName != nil {
			if tokenName.(string) != k.Sign.Token.Name {
				continue
			}
		}
		return k.Sign.Token.MaxLifetime
	}
	return 900
}
