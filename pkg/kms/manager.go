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
)

// KeyManager manages encryption keys.
type KeyManager struct {
	// The source of token configuration, config or environment variables.
	cryptoKeyConfig *CryptoKeyConfig
	keyOrigin       string
	keyType         string
	// The map containing key material, e.g. *rsa.PrivateKey, *rsa.PublicKey,
	// *ecdsa.PrivateKey, etc.
	keys     map[string]*Key
	keyCount int
	//Sign     *KeyOp
	//Verify   *KeyOp
	// Indicates whether the key material loading has happened.
	loaded bool
	err    error
}

// NewKeyManager returns an instance of KeyManager.
func NewKeyManager(config interface{}) (*KeyManager, error) {
	var tc *CryptoKeyConfig
	if config != nil {
		switch v := config.(type) {
		case *CryptoKeyConfig:
			tc = v
		case string:
			cryptoKeyConfig, err := NewCryptoKeyConfig(v)
			if err != nil {
				return nil, err
			}
			tc = cryptoKeyConfig
		default:
			return nil, errors.ErrKeyManagerCryptoKeyConfigInvalidType.WithArgs(v)
		}
	}

	km := &KeyManager{
		cryptoKeyConfig: tc,
		keys:            make(map[string]*Key),
	}
	if err := km.loadKeys(); err != nil {
		km.loaded = true
		km.err = err
		return nil, err
	}

	km.loaded = true
	return km, nil
}

// GetOrigin returns the origin of the token, i.e. config or env.
func (km *KeyManager) GetOrigin() string {
	if km.keyOrigin == "" {
		return "unknown"
	}
	return km.keyOrigin
}

// GetKeys returns a map with keys.
func (km *KeyManager) GetKeys() (string, map[string]*Key) {
	return km.keyType, km.keys
}

// addKey adds crypto key to KeyManager.
func (km *KeyManager) addKey(kid string, k *Key) error {
	if kid == "" {
		kid = "0"
	}
	if k == nil {
		return errors.ErrKeyManagerAddKeyNil
	}
	km.keyOrigin = k.Source
	km.keyType = k.Type
	km.keys[kid] = k
	km.keyCount++
	return nil
}

// GetType returns key manager supported type.
func (km *KeyManager) GetType() string {
	return km.keyType
}
