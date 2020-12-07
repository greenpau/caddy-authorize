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

package config

import (
	"crypto/rsa"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
)

var defaultKeyID = "0"

// CommonTokenConfig is common token-related configuration settings.
// The setting are used by TokenProvider and TokenValidator.
type CommonTokenConfig struct {
	TokenSignMethod string `json:"token_sign_method,omitempty" xml:"token_sign_method,omitempty" yaml:"token_sign_method,omitempty"`
	TokenName       string `json:"token_name,omitempty" xml:"token_name" yaml:"token_name"`
	TokenOrigin     string `json:"token_origin,omitempty" xml:"token_origin" yaml:"token_origin"`
	// The expiration time of a token in seconds
	TokenLifetime      int    `json:"token_lifetime,omitempty" xml:"token_lifetime" yaml:"token_lifetime"`
	TokenSigningMethod string `json:"token_signing_method,omitempty" xml:"token_signing_method" yaml:"token_signing_method"`

	HMACSignMethodConfig
	RSASignMethodConfig

	tokenKeys map[string]interface{} // the value must be a *rsa.PrivateKey or *rsa.PublicKey
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

// EnvTokenRSADir the env variable used to indicate a directory
const EnvTokenRSADir = "JWT_RSA_DIR"

// EnvTokenRSAFile then env variable (or prefix) used to indicate a file containing a RS key
const EnvTokenRSAFile = "JWT_RSA_FILE"

// EnvTokenRSAKey the env variable (or prefix) used to indicte a RS key
const EnvTokenRSAKey = "JWT_RSA_KEY"

// EnvTokenSecret the env variable used to indicate shared secret key
const EnvTokenSecret = "JWT_TOKEN_SECRET"

// HasRSAKeys returns true if the configuration has RSA encryption keys and files
func (c *CommonTokenConfig) HasRSAKeys() bool {
	if c.TokenRSADir != "" {
		return true
	}
	if c.TokenRSAFile != "" {
		return true
	}
	if c.TokenRSAKey != "" {
		return true
	}
	if c.TokenRSAFiles != nil {
		return true
	}
	if c.TokenRSAKeys != nil {
		return true
	}
	return false
}

// NewCommonTokenConfig returns an instance of CommonTokenConfig.
func NewCommonTokenConfig() *CommonTokenConfig {
	return &CommonTokenConfig{
		TokenName:     "access_token",
		TokenLifetime: 900,
	}
}

// GetKeys returns a map with RSA keys.
func (c *CommonTokenConfig) GetKeys() map[string]interface{} {
	return c.tokenKeys
}

// AddRSAPublicKey adds RSA public key to the map of RSA keys.
func (c *CommonTokenConfig) AddRSAPublicKey(keyID string, keyMaterial interface{}) error {
	if keyID == "" {
		return errors.ErrKeyIDNotFound
	}

	if c.tokenKeys == nil {
		c.tokenKeys = make(map[string]interface{})
	}

	switch kt := keyMaterial.(type) {
	case *rsa.PrivateKey:
		privkey := keyMaterial.(*rsa.PrivateKey)
		c.tokenKeys[keyID] = &privkey.PublicKey
		if _, exists := c.tokenKeys[defaultKeyID]; !exists {
			c.tokenKeys[defaultKeyID] = &privkey.PublicKey
		}
	case *rsa.PublicKey:
		c.tokenKeys[keyID] = keyMaterial
	default:
		return errors.ErrUnsupportedKeyType.WithArgs(kt, keyID)
	}

	return nil
}

// GetPrivateKey returns the first RSA private key it finds.
func (c *CommonTokenConfig) GetPrivateKey() (*rsa.PrivateKey, string, error) {
	if c.tokenKeys == nil {
		return nil, "", errors.ErrRSAKeysNotFound
	}
	for keyID, k := range c.tokenKeys {
		if keyID == defaultKeyID {
			continue
		}
		switch k.(type) {
		case *rsa.PrivateKey:
			return k.(*rsa.PrivateKey), keyID, nil
		}
	}
	return nil, "", errors.ErrRSAKeysNotFound
}

// AddTokenKey adds token key.
func (c *CommonTokenConfig) AddTokenKey(k string, pk interface{}) {
	if c.tokenKeys == nil {
		c.tokenKeys = make(map[string]interface{})
	}
	c.tokenKeys[k] = pk
}

// GetTokenKeys returns token keys.
func (c *CommonTokenConfig) GetTokenKeys() map[string]interface{} {
	return c.tokenKeys
}
