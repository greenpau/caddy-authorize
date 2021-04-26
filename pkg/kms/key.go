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
	"bytes"
	"fmt"
	jwtlib "github.com/dgrijalva/jwt-go"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"github.com/greenpau/caddy-auth-jwt/pkg/user"
	"strings"

	"crypto/ecdsa"
	"crypto/rsa"
	//   "crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	//  "os"
	"path/filepath"
	//  "sort"
	//  "strconv"
	//  "strings"
)

// CryptoKey contains a crypto graphic key and associated metadata.
type CryptoKey struct {
	Config *CryptoKeyConfig
	Sign   *CryptoKeyOperator
	Verify *CryptoKeyOperator
}

// CryptoKeyTokenOperator represents CryptoKeyOperator token operator.
type CryptoKeyTokenOperator struct {
	ID               string
	Name             string
	MaxLifetime      int
	Methods          map[string]interface{}
	PreferredMethods []string
	DefaultMethod    string
	Capable          bool
	injectKeyID      bool
}

// CryptoKeyOperator represents CryptoKey operator.
type CryptoKeyOperator struct {
	Token   *CryptoKeyTokenOperator
	Secret  interface{}
	Capable bool
}

func newCryptoKeyTokenOperator() *CryptoKeyTokenOperator {
	op := &CryptoKeyTokenOperator{}
	op.Methods = make(map[string]interface{})
	return op
}

func newCryptoKeyOperator() *CryptoKeyOperator {
	op := &CryptoKeyOperator{}
	op.Token = newCryptoKeyTokenOperator()
	return op
}

func newCryptoKey() *CryptoKey {
	k := &CryptoKey{}
	k.Sign = newCryptoKeyOperator()
	k.Verify = newCryptoKeyOperator()
	return k
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
}

// KeyOp are the operations supported by the key.
type KeyOp struct {
	Token struct {
		Name             string
		MaxLifetime      int
		Methods          map[string]interface{}
		PreferredMethods []string
		DefaultMethod    string
		Capable          bool
		injectKeyID      bool
	}
	Secret  interface{}
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

// ProvideKey returns the appropriate encryption key.
func (k *Key) ProvideKey(token *jwtlib.Token) (interface{}, error) {
	if _, validMethod := token.Method.(*jwtlib.SigningMethodHMAC); !validMethod {
		return nil, errors.ErrUnexpectedSigningMethod.WithArgs("HS", token.Header["alg"])
	}
	/*
				if _, validMethod := token.Method.(*jwtlib.SigningMethodRSA); !validMethod {
					return nil, errors.ErrUnexpectedSigningMethod.WithArgs("RS", token.Header["alg"])
				}
				        if _, validMethod := token.Method.(*jwtlib.SigningMethodECDSA); !validMethod {
		            return nil, errors.ErrUnexpectedSigningMethod.WithArgs("ES", token.Header["alg"])
		        }
	*/
	return k.Verify.Secret, nil
}

// SignToken signs data using the requested method and returns it as string.
func (k *Key) SignToken(signMethod interface{}, usr *user.User) error {
	if !k.Sign.Token.Capable {
		return errors.ErrSigningKeyNotFound.WithArgs(signMethod)
	}
	response, err := k.sign(signMethod, *usr.Claims)
	if err != nil {
		return err
	}
	usr.Token = response.(string)
	return nil
}

func (k *Key) sign(signMethod, data interface{}) (interface{}, error) {
	var method string
	if signMethod == nil {
		if k.Sign.Token.DefaultMethod == "" {
			return nil, errors.ErrInvalidSigningMethod
		}
		method = k.Sign.Token.DefaultMethod
	} else {
		method = signMethod.(string)
		if _, supported := k.Sign.Token.Methods[method]; !supported {
			return nil, errors.ErrUnsupportedSigningMethod.WithArgs(method)
		}
	}
	sm := jwtlib.GetSigningMethod(method)
	signer := jwtlib.NewWithClaims(sm, data.(jwtlib.Claims))
	if k.Sign.Token.injectKeyID {
		signer.Header["kid"] = k.ID
	}
	signedData, err := signer.SignedString(k.Sign.Secret)
	if err != nil {
		return nil, errors.ErrDataSigningFailed.WithArgs(method, err)
	}
	return signedData, nil
}

// GetVerifyKeys returns verification keys from multiple key managers.
func GetVerifyKeys(kms []*KeyManager) []*Key {
	var verifyKeys []*Key
	for _, km := range kms {
		_, keys := km.GetKeys()
		for _, k := range keys {
			if k.Verify == nil {
				continue
			}
			if !k.Verify.Token.Capable {
				continue
			}
			if k.Verify.Token.Name == "" {
				continue
			}
			if k.Verify.Token.MaxLifetime == 0 {
				continue
			}
			verifyKeys = append(verifyKeys, k)
		}
	}
	return verifyKeys
}

// GetSignKeys returns signing keys from multiple key managers.
func GetSignKeys(kms []*KeyManager) []*Key {
	var signKeys []*Key
	for _, km := range kms {
		if km == nil {
			continue
		}
		_, keys := km.GetKeys()
		for _, k := range keys {
			if k.Sign == nil {
				continue
			}
			if !k.Sign.Token.Capable {
				continue
			}
			if k.Sign.Token.Name == "" {
				continue
			}
			if k.Sign.Token.MaxLifetime == 0 {
				continue
			}
			signKeys = append(signKeys, k)
		}
	}
	return signKeys
}

// GetKeysFromConfigs loads keys from one or more key configs.
func GetKeysFromConfigs(cfgs []*CryptoKeyConfig) ([]*CryptoKey, error) {
	var keys []*CryptoKey
	for _, cfg := range cfgs {
		k, err := GetKeysFromConfig(cfg)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k...)
	}
	return keys, nil
}

// GetKeysFromConfig loads keys from a single key config.
func GetKeysFromConfig(cfg *CryptoKeyConfig) ([]*CryptoKey, error) {
	var keys []*CryptoKey
	switch cfg.Source {
	case "config":
		switch {
		case cfg.Algorithm == "hmac":
			// Discovered shared key
			k := newCryptoKey()
			k.Config = cfg
			keys = append(keys, k)
		case cfg.FilePath != "":
			fileKeys, err := extractKeysFromFile(cfg.FilePath, cfg)
			if err != nil {
				return nil, err
			}
			keys = append(keys, fileKeys...)
		// case cfg.DirPath != "":
		default:
			return nil, fmt.Errorf("unsupported config")
		}
	case "env":
		switch {
		case cfg.EnvVarType == "key":
			if strings.HasPrefix(cfg.EnvVarValue, "-----") {
				// Discovered symmetric key
				k, err := extractKey([]byte(cfg.EnvVarValue), cfg)
				if err != nil {
					return nil, err
				}
				keys = append(keys, k)
				break
			}
			// Discovered shared key
			k := newCryptoKey()
			k.Config = cfg
			k.Config.Algorithm = "hmac"
			k.Config.Secret = k.Config.EnvVarValue
			keys = append(keys, k)
		// case cfg.EnvVarType == "file":
		// case cfg.EnvVarType == "directory":
		default:
			return nil, fmt.Errorf("unsupported env config type %s", cfg.EnvVarType)
		}
	}

	for _, k := range keys {
		switch k.Config.Algorithm {
		case "hmac":
			k.Sign.Capable = true
			k.Verify.Capable = true
			k.Sign.Secret = []byte(k.Config.Secret)
			k.Verify.Secret = []byte(k.Config.Secret)
		case "rsa", "ecdsa":
		default:
			return nil, fmt.Errorf("unsupported config algorithm %s", k.Config.Algorithm)
		}
		k.enableUsage()
	}
	return keys, nil
}

func (k *CryptoKey) enableUsage() {
	methods := getMethodsPerAlgo(k.Config.Algorithm)
	if k.Sign.Capable {
		k.Sign.Token.ID = k.Config.ID
		k.Sign.Token.Capable = true
		if len(k.Sign.Token.PreferredMethods) == 0 {
			k.Sign.Token.PreferredMethods = methods
		}
		for _, m := range k.Sign.Token.PreferredMethods {
			k.Sign.Token.Methods[m] = true
		}
		k.Sign.Token.Name = k.Config.TokenName
		k.Sign.Token.MaxLifetime = k.Config.TokenLifetime
		k.Sign.Token.DefaultMethod = k.Sign.Token.PreferredMethods[0]
		if k.Config.ID != defaultKeyID && k.Config.ID != "" {
			k.Sign.Token.injectKeyID = true
		}
	}
	if k.Verify.Capable {
		k.Verify.Token.ID = k.Config.ID
		k.Verify.Token.Capable = true
		if len(k.Verify.Token.PreferredMethods) == 0 {
			k.Verify.Token.PreferredMethods = methods
		}
		for _, m := range k.Verify.Token.PreferredMethods {
			k.Verify.Token.Methods[m] = true
		}
		k.Verify.Token.Name = k.Config.TokenName
		k.Verify.Token.MaxLifetime = k.Config.TokenLifetime
		k.Verify.Token.DefaultMethod = k.Verify.Token.PreferredMethods[0]
	}
}

// SignToken signs data using the requested method and returns it as string.
func (k *CryptoKey) SignToken(signMethod interface{}, usr *user.User) error {
	if !k.Sign.Token.Capable {
		return errors.ErrSigningKeyNotFound.WithArgs(signMethod)
	}
	response, err := k.sign(signMethod, *usr.Claims)
	if err != nil {
		return err
	}
	usr.Token = response.(string)
	return nil
}

func (k *CryptoKey) sign(signMethod, data interface{}) (interface{}, error) {
	var method string
	if signMethod == nil {
		if k.Sign.Token.DefaultMethod == "" {
			return nil, errors.ErrInvalidSigningMethod
		}
		method = k.Sign.Token.DefaultMethod
	} else {
		method = signMethod.(string)
		if _, supported := k.Sign.Token.Methods[method]; !supported {
			return nil, errors.ErrUnsupportedSigningMethod.WithArgs(method)
		}
	}
	sm := jwtlib.GetSigningMethod(method)
	signer := jwtlib.NewWithClaims(sm, data.(jwtlib.Claims))
	if k.Sign.Token.injectKeyID {
		signer.Header["kid"] = k.Sign.Token.ID
	}
	signedData, err := signer.SignedString(k.Sign.Secret)
	if err != nil {
		return nil, errors.ErrDataSigningFailed.WithArgs(method, err)
	}
	return signedData, nil
}

// ProvideKey returns the appropriate encryption key.
func (k *CryptoKey) ProvideKey(token *jwtlib.Token) (interface{}, error) {
	switch k.Config.Algorithm {
	case "hmac":
		if _, validMethod := token.Method.(*jwtlib.SigningMethodHMAC); !validMethod {
			return nil, errors.ErrUnexpectedSigningMethod.WithArgs("HS", token.Header["alg"])
		}
	case "rsa":
		if _, validMethod := token.Method.(*jwtlib.SigningMethodRSA); !validMethod {
			return nil, errors.ErrUnexpectedSigningMethod.WithArgs("RS", token.Header["alg"])
		}
	case "ecdsa":
		if _, validMethod := token.Method.(*jwtlib.SigningMethodECDSA); !validMethod {
			return nil, errors.ErrUnexpectedSigningMethod.WithArgs("ES", token.Header["alg"])
		}
	}
	return k.Verify.Secret, nil
}

func extractKeysFromFile(fp string, cfg *CryptoKeyConfig) ([]*CryptoKey, error) {
	var keys []*CryptoKey
	ext := filepath.Ext(fp)
	switch ext {
	case ".pem", ".key":
	default:
		return nil, errors.ErrCryptoKeyConfigFileNotSupported.WithArgs(fp)
	}
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, errors.ErrCryptoKeyConfigReadFile.WithArgs(fp, err)
	}
	key, err := extractKey(b, cfg)
	if err != nil {
		return nil, errors.ErrCryptoKeyConfigReadFile.WithArgs(fp, err)
	}
	keys = append(keys, key)
	if len(keys) == 0 {
		return nil, errors.ErrCryptoKeyConfigFileKeyNotFound.WithArgs(fp)
	}
	return keys, nil
}

func extractKey(kb []byte, cfg *CryptoKeyConfig) (*CryptoKey, error) {
	var curveName string
	k := newCryptoKey()
	kcfg := *cfg
	k.Config = &kcfg

	if !bytes.Contains(kb, []byte("---BEGIN")) || !bytes.Contains(kb, []byte("---END")) {
		return nil, errors.ErrNotPEMEncodedKey
	}
	var block *pem.Block
	if block, _ = pem.Decode(kb); block == nil {
		return nil, errors.ErrNotPEMEncodedKey
	}

	switch {
	case bytes.Contains(kb, []byte("RSA PRIVATE KEY")):
		k.Config.Algorithm = "rsa"
		privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		k.Sign.Capable = true
		k.Sign.Secret = privKey

		k.Verify.Capable = true
		k.Verify.Secret = privKey.Public()
	case bytes.Contains(kb, []byte("EC PRIVATE KEY")):
		k.Config.Algorithm = "ecdsa"
		privKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		k.Sign.Capable = true
		k.Sign.Secret = privKey
		curve := privKey.Curve.Params()
		if curve == nil {
			return nil, errors.ErrNoECDSACurveParamsFound
		}
		curveName = curve.Name
	case bytes.Contains(kb, []byte("PRIVATE KEY")):
		privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		switch privKey := privKey.(type) {
		case *rsa.PrivateKey:
			k.Config.Algorithm = "rsa"
			k.Sign.Capable = true
			k.Sign.Secret = privKey
		case *ecdsa.PrivateKey:
			k.Config.Algorithm = "ecdsa"
			k.Sign.Capable = true
			k.Sign.Secret = privKey
			curve := privKey.Curve.Params()
			if curve == nil {
				return nil, errors.ErrNoECDSACurveParamsFound
			}
			curveName = curve.Name
		default:
			// case ed25519.PrivateKey
			return nil, errors.ErrCryptoKeyConfigUnsupportedPrivateKeyAlgo.WithArgs(privKey)
		}
	case bytes.Contains(kb, []byte("RSA PUBLIC KEY")):
		pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		k.Config.Algorithm = "rsa"
		k.Verify.Capable = true
		k.Verify.Secret = pubKey
	case bytes.Contains(kb, []byte("PUBLIC KEY")):
		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		k.Verify.Capable = true
		switch pubKey := pubKey.(type) {
		case *rsa.PublicKey:
			k.Config.Algorithm = "rsa"
			k.Verify.Secret = pubKey
		case *ecdsa.PublicKey:
			k.Config.Algorithm = "ecdsa"
			k.Verify.Secret = pubKey
			curve := pubKey.Curve.Params()
			if curve == nil {
				return nil, errors.ErrNoECDSACurveParamsFound
			}
			curveName = curve.Name
		default:
			// case *dsa.PublicKey
			// case ed25519.PublicKey
			return nil, errors.ErrCryptoKeyConfigUnsupportedPublicKeyAlgo.WithArgs(pubKey)
		}
	default:
		return nil, errors.ErrNotPEMEncodedKey
	}

	if k.Config.Algorithm == "ecdsa" {
		// See https://golang.org/src/crypto/elliptic/elliptic.go.
		var method string
		switch curveName {
		case "P-256":
			method = "ES256"
		case "P-384":
			method = "ES384"
		case "P-521":
			method = "ES512"
		case "":
			return nil, errors.ErrEmptyECDSACurve
		default:
			return nil, errors.ErrUnsupportedECDSACurve.WithArgs(curveName)
		}
		if k.Sign.Capable {
			k.Sign.Token.PreferredMethods = []string{method}
		}
		if k.Verify.Capable {
			k.Verify.Token.PreferredMethods = []string{method}
		}
	}
	return k, nil
}
