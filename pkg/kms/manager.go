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
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
)

var (
	defaultKeyID             = "0"
	defaultTokenName         = "access_token"
	defaultTokenLifetime int = 900
)

// EnvTokenRSADir the env variable used to indicate a directory
const EnvTokenRSADir = "JWT_RSA_DIR"

// EnvTokenRSAFile then env variable (or prefix) used to indicate a file containing a RS key
const EnvTokenRSAFile = "JWT_RSA_FILE"

// EnvTokenRSAKey the env variable (or prefix) used to indicte a RS key
const EnvTokenRSAKey = "JWT_RSA_KEY"

// EnvTokenECDSADir the env variable used to indicate a directory containing ECDSA keys.
const EnvTokenECDSADir = "JWT_ECDSA_DIR"

// EnvTokenECDSAFile then env variable (or prefix) used to indicate a file containing ECDSA key.
const EnvTokenECDSAFile = "JWT_ECDSA_FILE"

// EnvTokenECDSAKey the env variable (or prefix) used to indicate ECDSA key.
const EnvTokenECDSAKey = "JWT_ECDSA_KEY"

// EnvTokenSecret the env variable used to indicate shared secret key.
const EnvTokenSecret = "JWT_TOKEN_SECRET"

// EnvTokenLifetime the env variable used to set default token lifetime.
const EnvTokenLifetime = "JWT_TOKEN_LIFETIME"

// EnvTokenName the env variable used to set default token name.
const EnvTokenName = "JWT_TOKEN_NAME"

// KeyManager is common token-related configuration settings.
// The setting are used by TokenProvider and TokenValidator.
type KeyManager struct {
	TokenSignMethod string `json:"token_sign_method,omitempty" xml:"token_sign_method,omitempty" yaml:"token_sign_method,omitempty"`
	TokenName       string `json:"token_name,omitempty" xml:"token_name" yaml:"token_name"`
	// The expiration time of a token in seconds
	TokenLifetime int      `json:"token_lifetime,omitempty" xml:"token_lifetime" yaml:"token_lifetime"`
	EvalExpr      []string `json:"token_eval_expr,omitempty" xml:"token_eval_expr" yaml:"token_eval_expr"`

	HMACSignMethodConfig
	RSASignMethodConfig
	ECDSASignMethodConfig

	// The source of token configuration, config or environment variables.
	tokenOrigin string
	keyType     string
	// The map containing key material, e.g. *rsa.PrivateKey, *rsa.PublicKey,
	// *ecdsa.PrivateKey, etc.
	keys              map[string]interface{}
	keyCount          int
	keyCache          map[string]*cachedKeyManagerEntry
	defaultSignMethod string
	// Indicates whether the key material loading has happened.
	loaded bool
	err    error
}

// HMACSignMethodConfig holds configuration for signing messages by means of a shared key.
type HMACSignMethodConfig struct {
	TokenSecret string `json:"token_secret,omitempty" xml:"token_secret" yaml:"token_secret"`
}

// RSASignMethodConfig holds data for RSA keys that can be used to sign and verify JWT tokens
// TokenRSDirectory is a directory that is like:
//
// <kid>'s can only contain ascii letters/numbers and underscores. (otherwise they are not loaded)
//
// <dirname>
//    +-- <kid_1>
//          +-- private.key
//    +-- <kid_2>
//          +-- public.key
//    +-- kid_3.key
//    +-- kid_4.key
//    +-- kid.5.key
// The above directory will result in a TokenRSKeys that looks like:
//
// TokenRSKeys{
//     "kid_1_private": "---- RSA PRIVATE KEY ---- ...",
//     "kid_2_public": "---- RSA PUBLIC KEY ---- ...",
//     "kid_3": "---- RSA PRIVATE KEY ---- ...",
//     "kid_4": "---- RSA PUBLIC KEY ---- ...",
//     // there is no "kid.5" becuase the "." is invalid.
// }
//
// There only needs to be public keys loaded for verification. If you're using the Grantor method then
// you need to load a PrivateKey so that keys can be signed.
//
// The TokenRS fields translate to the following config values:
//
// "token_rs_dir": "<path to dir>"
// "token_rs_files": {"<kid>": "<path to file>", ...}
// "token_rs_keys": {"<kid>": "<key PEM value>", ...}
//
// there are two special config values:
//
// "token_rs_file": "<path to file>"
// "token_rs_key": "<key PEM value>"
//
// The above two variables map to a <kid> of "0", these are always evaluated first so they can be overwritten if
// a <kid> of "0" is used explictly
//
// The TokenRS fields translate to the following enviornment variables:
//
// JWT_RS_DIR="<path to dir>"
// JWT_RS_FILE_<kid>="<path to file>"
// JWT_RS_KEY_<kid>="<key PEM value>"
//
// there are two special environment variables:
//
// JWT_RS_FILE="<path to file>"
// JWT_RS_KEY="<key PEM value>"
//
// The above two variables map to a <kid> of "0", these are always evaluated first so they can be overwritten if
// a <kid> of "0" is used explictly
//
// Enviroment variable KID's get lowercased. All other KID's are left untouched.

// RSASignMethodConfig defines configuration unique to RSA keys.
type RSASignMethodConfig struct {
	// TokenRSDir holds the absolute path to where a nested directory of key paths are, otherwise the name of the file
	// is used as the kid and the values are parse into TokenRSKeys
	TokenRSADir string `json:"token_rsa_dir,omitempty" xml:"token_rsa_dir" yaml:"token_rsa_dir"`

	// TokenRSFiles holds a map of <kid> to filename. These files should hold the public or private key. They are parsed to TokenRSKeys values
	TokenRSAFiles map[string]string `json:"token_rsa_files,omitempty" xml:"token_rsa_files" yaml:"token_rsa_files"`

	// TokenRSKeys holds a map of <kid> to the key PEM value
	TokenRSAKeys map[string]string `json:"token_rsa_keys,omitempty" xml:"token_rsa_keys" yaml:"token_rsa_keys"`

	// Special (see the comment above to see how they work)

	TokenRSAFile string `json:"token_rsa_file,omitempty" xml:"token_rsa_file" yaml:"token_rsa_file"`
	TokenRSAKey  string `json:"token_rsa_key,omitempty" xml:"token_rsa_key" yaml:"token_rsa_key"`
}

// ECDSASignMethodConfig defines configuration unique to ECDSA keys.
type ECDSASignMethodConfig struct {
	TokenECDSADir   string            `json:"token_ecdsa_dir,omitempty" xml:"token_ecdsa_dir" yaml:"token_ecdsa_dir"`
	TokenECDSAFiles map[string]string `json:"token_ecdsa_files,omitempty" xml:"token_ecdsa_files" yaml:"token_ecdsa_files"`
	TokenECDSAKeys  map[string]string `json:"token_ecdsa_keys,omitempty" xml:"token_ecdsa_keys" yaml:"token_ecdsa_keys"`
	TokenECDSAFile  string            `json:"token_ecdsa_file,omitempty" xml:"token_ecdsa_file" yaml:"token_ecdsa_file"`
	TokenECDSAKey   string            `json:"token_ecdsa_key,omitempty" xml:"token_ecdsa_key" yaml:"token_ecdsa_key"`
}

// HasRSAKeys returns true if the configuration has RSA encryption keys and files
func (km *KeyManager) HasRSAKeys() bool {
	if km.TokenRSADir != "" {
		return true
	}
	if km.TokenRSAFile != "" {
		return true
	}
	if km.TokenRSAKey != "" {
		return true
	}
	if km.TokenRSAFiles != nil {
		return true
	}
	if km.TokenRSAKeys != nil {
		return true
	}
	return false
}

// HasECDSAKeys returns true if the configuration has ECDSA encryption keys and files
func (km *KeyManager) HasECDSAKeys() bool {
	if km.TokenECDSADir != "" {
		return true
	}
	if km.TokenECDSAFile != "" {
		return true
	}
	if km.TokenECDSAKey != "" {
		return true
	}
	if km.TokenECDSAFiles != nil {
		return true
	}
	if km.TokenECDSAKeys != nil {
		return true
	}
	return false
}

// NewKeyManager returns an instance of KeyManager.
func NewKeyManager() *KeyManager {
	return &KeyManager{
		keyCache: make(map[string]*cachedKeyManagerEntry),
		keys:     make(map[string]interface{}),
	}
}

// GetOrigin returns the origin of the token, i.e. config or env.
func (km *KeyManager) GetOrigin() string {
	if km.tokenOrigin == "" {
		return "unknown"
	}
	return km.tokenOrigin
}

// SetOrigin sets token origin, i.e. config or env.
func (km *KeyManager) SetOrigin(name string) error {
	switch name {
	case "config", "env":
	case "empty":
		return errors.ErrEmptyTokenConfigOrigin
	default:
		return errors.ErrUnsupportedTokenConfigOrigin.WithArgs(name)
	}
	km.tokenOrigin = name
	return nil
}

// GetKeys returns a map with keys.
func (km *KeyManager) GetKeys() (string, map[string]interface{}) {
	return km.keyType, km.keys
}

// AddPublicKey adds RSA public key to the map of RSA keys.
func (km *KeyManager) AddPublicKey(keyID string, keyMaterial interface{}) error {
	if keyID == "" {
		return errors.ErrKeyIDNotFound
	}

	if km.keys == nil {
		km.keys = make(map[string]interface{})
	}

	switch kt := keyMaterial.(type) {
	case *rsa.PrivateKey:
		privkey := keyMaterial.(*rsa.PrivateKey)
		km.keys[keyID] = &privkey.PublicKey
		if _, exists := km.keys[defaultKeyID]; !exists {
			km.keys[defaultKeyID] = &privkey.PublicKey
		}
	case *ecdsa.PrivateKey:
		privkey := keyMaterial.(*ecdsa.PrivateKey)
		km.keys[keyID] = &privkey.PublicKey
		if _, exists := km.keys[defaultKeyID]; !exists {
			km.keys[defaultKeyID] = &privkey.PublicKey
		}
	case *rsa.PublicKey, *ecdsa.PublicKey:
		km.keys[keyID] = keyMaterial
	default:
		return errors.ErrUnsupportedKeyType.WithArgs(kt, keyID)
	}
	return nil
}

// GetSigningKey returns the first singing key it finds.
func (km *KeyManager) GetSigningKey() (interface{}, string, error) {
	if km.keys == nil {
		return nil, "", errors.ErrPrivateKeysNotFound
	}
	switch km.keyType {
	case "hmac":
		return km.keys[defaultKeyID], "", nil
	case "rsa", "ecdsa":
		for keyID, k := range km.keys {
			if keyID == defaultKeyID {
				continue
			}
			switch k.(type) {
			case *rsa.PrivateKey:
				return k, keyID, nil
			case *ecdsa.PrivateKey:
				return k, keyID, nil
			}
		}
		for keyID, k := range km.keys {
			if keyID != defaultKeyID {
				continue
			}
			switch k.(type) {
			case *rsa.PrivateKey:
				return k, keyID, nil
			case *ecdsa.PrivateKey:
				return k, keyID, nil
			}
		}
		switch km.keyType {
		case "ecdsa":
			return nil, "", errors.ErrECDSAKeysNotFound
		case "rsa":
			return nil, "", errors.ErrRSAKeysNotFound
		}
		return nil, "", errors.ErrPrivateKeysNotFound
	}
	return nil, "", errors.ErrPrivateKeysNotFound
}

// GetPrivateKey returns the first private key it finds.
func (km *KeyManager) GetPrivateKey() (interface{}, string, error) {
	if km.keys == nil {
		return nil, "", errors.ErrPrivateKeysNotFound
	}

	for keyID, k := range km.keys {
		if keyID == defaultKeyID {
			continue
		}
		switch k.(type) {
		case *rsa.PrivateKey:
			return k, keyID, nil
		case *ecdsa.PrivateKey:
			return k, keyID, nil
		}
	}
	switch km.keyType {
	case "ecdsa":
		return nil, "", errors.ErrECDSAKeysNotFound
	case "rsa":
		return nil, "", errors.ErrRSAKeysNotFound
	}
	return nil, "", errors.ErrPrivateKeysNotFound
}

// AddKey adds token key.
func (km *KeyManager) AddKey(k string, pk interface{}) error {
	if pk == nil {
		return errors.ErrKeyNil
	}
	if km.keys == nil {
		km.keys = make(map[string]interface{})
	}
	keyType, err := km.getKeyType(pk)
	if err != nil {
		return err
	}
	if km.keyType == "" {
		km.keyType = keyType
	}
	if km.keyType != keyType {
		return errors.ErrMixedConfigKeyType.WithArgs(km.keyType, keyType)
	}
	if km.keyType == "hmac" && pk.(string) == "" {
		return errors.ErrEmptySecret
	}
	if _, exists := km.keys[k]; exists {
		return errors.ErrKeyOverwriteFailed.WithArgs(k)
	}
	km.keys[k] = pk
	km.keyCount++
	return nil
}

func (km *KeyManager) getKeyType(k interface{}) (string, error) {
	var kt string
	switch k.(type) {
	case string:
		kt = "hmac"
	case *rsa.PrivateKey:
		kt = "rsa"
	case *rsa.PublicKey:
		kt = "rsa"
	case *ecdsa.PrivateKey:
		kt = "ecdsa"
	case *ecdsa.PublicKey:
		kt = "ecdsa"
	default:
		return "", errors.ErrUnsupportedConfigKeyType.WithArgs(k)
	}
	return kt, nil
}

// GetKeyType returns key manager supported type.
func (km *KeyManager) GetKeyType() string {
	return km.keyType
}

func (km *KeyManager) operational() bool {
	if km.err != nil {
		return false
	}
	if km.loaded {
		return true
	}
	return false
}

// Load loads keys from configuration and environment variables.
func (km *KeyManager) Load() error {
	if km.err != nil {
		return km.err
	}
	if km.loaded {
		return nil
	}
	if km.keyCache == nil {
		km.keyCache = make(map[string]*cachedKeyManagerEntry)
	}
	if km.keys == nil {
		km.keys = make(map[string]interface{})
	}
	err := km.discover()
	if err != nil {
		km.loaded = true
		km.err = err
		return err
	}
	km.loaded = true
	return nil
}
