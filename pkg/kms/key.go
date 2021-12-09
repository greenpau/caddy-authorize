// Copyright 2020 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	jwtlib "github.com/golang-jwt/jwt/v4"
	"github.com/greenpau/caddy-authorize/pkg/errors"
	"github.com/greenpau/caddy-authorize/pkg/user"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// CryptoKey contains a crypto graphic key and associated metadata.
type CryptoKey struct {
	Config *CryptoKeyConfig   `json:"config,omitempty" xml:"config,omitempty" yaml:"config,omitempty"`
	Sign   *CryptoKeyOperator `json:"sign,omitempty" xml:"sign,omitempty" yaml:"sign,omitempty"`
	Verify *CryptoKeyOperator `json:"verify,omitempty" xml:"verify,omitempty" yaml:"verify,omitempty"`
}

// CryptoKeyTokenOperator represents CryptoKeyOperator token operator.
type CryptoKeyTokenOperator struct {
	ID               string                 `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	Name             string                 `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	MaxLifetime      int                    `json:"max_lifetime,omitempty" xml:"max_lifetime,omitempty" yaml:"max_lifetime,omitempty"`
	Methods          map[string]interface{} `json:"methods,omitempty" xml:"methods,omitempty" yaml:"methods,omitempty"`
	PreferredMethods []string               `json:"preferred_methods,omitempty" xml:"preferred_methods,omitempty" yaml:"preferred_methods,omitempty"`
	DefaultMethod    string                 `json:"default_method,omitempty" xml:"default_method,omitempty" yaml:"default_method,omitempty"`
	Capable          bool                   `json:"capable,omitempty" xml:"capable,omitempty" yaml:"capable,omitempty"`
	injectKeyID      bool
}

// CryptoKeyOperator represents CryptoKey operator.
type CryptoKeyOperator struct {
	Token   *CryptoKeyTokenOperator `json:"token,omitempty" xml:"token,omitempty" yaml:"token,omitempty"`
	Secret  interface{}             `json:"secret,omitempty" xml:"secret,omitempty" yaml:"secret,omitempty"`
	Capable bool                    `json:"capable,omitempty" xml:"capable,omitempty" yaml:"capable,omitempty"`
}

// NewCryptoKeyTokenOperator returns an instance of CryptoKeyTokenOperator.
func NewCryptoKeyTokenOperator() *CryptoKeyTokenOperator {
	op := &CryptoKeyTokenOperator{}
	op.Methods = make(map[string]interface{})
	return op
}

// NewCryptoKeyOperator returns an instance of CryptoKeyOperator.
func NewCryptoKeyOperator() *CryptoKeyOperator {
	op := &CryptoKeyOperator{}
	op.Token = NewCryptoKeyTokenOperator()
	return op
}

func newCryptoKey() *CryptoKey {
	k := &CryptoKey{}
	k.Sign = NewCryptoKeyOperator()
	k.Verify = NewCryptoKeyOperator()
	return k
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
		case cfg.DirPath != "":
			dirKeys, err := extractKeysFromDir(cfg.DirPath, cfg)
			if err != nil {
				return nil, err
			}
			keys = append(keys, dirKeys...)
		default:
			return nil, fmt.Errorf("unsupported config")
		}
	case "env":
		switch {
		case cfg.EnvVarType == "key":
			if strings.HasPrefix(cfg.EnvVarValue, "---") {
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
		case cfg.EnvVarType == "file":
			fileKeys, err := extractKeysFromFile(cfg.EnvVarValue, cfg)
			if err != nil {
				return nil, err
			}
			keys = append(keys, fileKeys...)
		case cfg.EnvVarType == "directory":
			dirKeys, err := extractKeysFromDir(cfg.EnvVarValue, cfg)
			if err != nil {
				return nil, err
			}
			keys = append(keys, dirKeys...)
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
	response, err := k.sign(signMethod, usr.AsMap())
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

	header := map[string]interface{}{"typ": "JWT", "alg": method}
	if k.Sign.Token.injectKeyID {
		header["kid"] = k.Sign.Token.ID
	}
	jh, err := json.Marshal(header)
	if err != nil {
		return nil, errors.ErrDataSigningFailed.WithArgs(method, err)
	}
	jb, err := json.Marshal(data)
	if err != nil {
		return nil, errors.ErrDataSigningFailed.WithArgs(method, err)
	}
	s := base64.RawURLEncoding.EncodeToString(jh) + "." + base64.RawURLEncoding.EncodeToString(jb)

	switch signingMethods[method] {
	case "hmac":
		return k.signHMAC(method, s)
	case "rsa":
		return k.signRSA(method, s)
	case "ecdsa":
		return k.signECDSA(method, s)
	}

	/*
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
	*/
	return nil, errors.ErrDataSigningFailed.WithArgs(method, "unsupported method")
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

func extractBytesFromFile(fp string) ([]byte, error) {
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
	return b, nil
}

func extractKeysFromFile(fp string, cfg *CryptoKeyConfig) ([]*CryptoKey, error) {
	var keys []*CryptoKey
	b, err := extractBytesFromFile(fp)
	if err != nil {
		return nil, err
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
		switch k.Config.Usage {
		case "sign":
		default:
			k.Verify.Capable = true
			k.Verify.Secret = privKey.Public()
		}
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
		switch k.Config.Usage {
		case "sign":
		default:
			k.Verify.Capable = true
			k.Verify.Secret = privKey.Public()
		}
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
			switch k.Config.Usage {
			case "sign":
			default:
				k.Verify.Capable = true
				k.Verify.Secret = privKey.Public()
			}
		case *ecdsa.PrivateKey:
			k.Config.Algorithm = "ecdsa"
			k.Sign.Capable = true
			k.Sign.Secret = privKey
			curve := privKey.Curve.Params()
			if curve == nil {
				return nil, errors.ErrNoECDSACurveParamsFound
			}
			curveName = curve.Name
			switch k.Config.Usage {
			case "sign":
			default:
				k.Verify.Capable = true
				k.Verify.Secret = privKey.Public()
			}
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

func extractKeysFromDir(dirPath string, cfg *CryptoKeyConfig) ([]*CryptoKey, error) {
	var dirKeys []*CryptoKey
	err := filepath.Walk(dirPath, func(fp string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		ext := filepath.Ext(fp)
		switch ext {
		case ".pem", ".key":
		default:
			return nil
		}

		kcfg := *cfg
		ncfg := &kcfg
		kid := filepath.Base(fp)
		kid = strings.TrimSuffix(kid, ext)
		kid = normalizeKeyID(kid)

		ncfg.ID = kid
		ncfg.FilePath = fp

		keys, err := extractKeysFromFile(fp, ncfg)
		if err != nil {
			return err
		}
		dirKeys = append(dirKeys, keys...)
		return nil
	})
	if err != nil {
		return nil, errors.ErrWalkDir.WithArgs(err)
	}
	if len(dirKeys) == 0 {
		return nil, errors.ErrWalkDir.WithArgs("no crypto keys found")
	}
	return dirKeys, nil
}

func normalizeKeyID(s string) string {
	b := []byte{}
	for _, c := range []byte(s) {
		if ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') || c == '_' || c == '-' {
			b = append(b, c)
		}
	}
	return strings.ToLower(string(b))
}

func (k *CryptoKey) signECDSA(method, data string) (interface{}, error) {
	var h crypto.Hash
	var cb int
	switch method {
	case "ES256":
		h = crypto.SHA256
		cb = 256
	case "ES384":
		h = crypto.SHA384
		cb = 384
	case "ES512":
		h = crypto.SHA512
		cb = 521
	default:
		return nil, errors.ErrDataSigningFailed.WithArgs("ECDSA", "unsupported method")
	}
	if !h.Available() {
		return nil, errors.ErrDataSigningFailed.WithArgs("ECDSA", "unavailable method")
	}
	hf := h.New()
	hf.Write([]byte(data))

	pk := k.Sign.Secret.(*ecdsa.PrivateKey)
	if cb != pk.Curve.Params().BitSize {
		return nil, errors.ErrDataSigningFailed.WithArgs("ECDSA", "curve bitsize mismatch")
	}

	r, s, err := ecdsa.Sign(rand.Reader, pk, hf.Sum(nil))
	if err != nil {
		return nil, errors.ErrDataSigningFailed.WithArgs("ECDSA", err)
	}

	sz := cb / 8
	if cb%8 > 0 {
		sz++
	}

	b := make([]byte, 2*sz)
	r.FillBytes(b[0:sz])
	s.FillBytes(b[sz:])
	return data + "." + base64.RawURLEncoding.EncodeToString(b), nil
}

func (k *CryptoKey) signRSA(method, data string) (interface{}, error) {
	var h crypto.Hash
	switch method {
	case "RS256":
		h = crypto.SHA256
	case "RS384":
		h = crypto.SHA384
	case "RS512":
		h = crypto.SHA512
	default:
		return nil, errors.ErrDataSigningFailed.WithArgs("RSA", "unsupported method")
	}
	if !h.Available() {
		return nil, errors.ErrDataSigningFailed.WithArgs("RSA", "unavailable method")
	}
	hf := h.New()
	hf.Write([]byte(data))

	pk := k.Sign.Secret.(*rsa.PrivateKey)
	b, err := rsa.SignPKCS1v15(rand.Reader, pk, h, hf.Sum(nil))
	if err != nil {
		return nil, errors.ErrDataSigningFailed.WithArgs("RSA", err)
	}
	return data + "." + base64.RawURLEncoding.EncodeToString(b), nil
}

func (k *CryptoKey) signHMAC(method, data string) (interface{}, error) {
	var h crypto.Hash
	switch method {
	case "HS256":
		h = crypto.SHA256
	case "HS384":
		h = crypto.SHA384
	case "HS512":
		h = crypto.SHA512
	default:
		return nil, errors.ErrDataSigningFailed.WithArgs("HMAC", "unsupported method")
	}
	if !h.Available() {
		return nil, errors.ErrDataSigningFailed.WithArgs("HMAC", "unavailable method")
	}
	pk := k.Sign.Secret.([]byte)
	hf := hmac.New(h.New, pk)
	hf.Write([]byte(data))
	return data + "." + base64.RawURLEncoding.EncodeToString(hf.Sum(nil)), nil
}
