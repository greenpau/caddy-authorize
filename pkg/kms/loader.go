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
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	jwtlib "github.com/dgrijalva/jwt-go"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
)

type loader struct {
	Keys     []*Key
	Name     string
	Lifetime int
	// Used environment variables
	vars []string
}

func newLoader() *loader {
	return &loader{
		vars: []string{
			EnvTokenRSADir,
			EnvTokenRSAFile,
			EnvTokenRSAKey,
			EnvTokenECDSADir,
			EnvTokenECDSAFile,
			EnvTokenECDSAKey,
		},
	}
}

func parseECDSAPrivateKey(s string) (*ecdsa.PrivateKey, error) {
	var block *pem.Block
	block, _ = pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.ErrNotPEMEncodedKey
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func parseECDSAPublicKey(s string) (*ecdsa.PublicKey, error) {
	var block *pem.Block
	block, _ = pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.ErrNotPEMEncodedKey
	}
	pk, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pk.(type) {
	case *ecdsa.PublicKey:
		return pk.(*ecdsa.PublicKey), nil
	default:
		return nil, errors.ErrNotECDSAPublicKeyType.WithArgs(pk)
	}
}

func (ldr *loader) loadConfig(cfg *CryptoKeyConfig) error {
	// HMAC Key
	if cfg.Secret != "" {
		ldr.addKey(defaultKeyID, "config", "hmac", cfg.Secret)
	}
	// RSA Keys
	if cfg.RSADir != "" {
		if err := ldr.extractFromDir("config", "rsa", cfg.RSADir); err != nil {
			return err
		}
	}
	for kid, fp := range cfg.RSAFiles {
		if err := ldr.extractFromFile("config", "rsa", kid, fp); err != nil {
			return err
		}
	}
	if cfg.RSAFile != "" {
		if err := ldr.extractFromFile("config", "rsa", defaultKeyID, cfg.RSAFile); err != nil {
			return err
		}
	}
	for kid, secret := range cfg.RSAKeys {
		ldr.addKey(kid, "config", "rsa", secret)
	}
	if cfg.RSAKey != "" {
		ldr.addKey(defaultKeyID, "config", "rsa", cfg.RSAKey)
	}
	// ECDSA Keys
	if cfg.ECDSADir != "" {
		if err := ldr.extractFromDir("config", "ecdsa", cfg.ECDSADir); err != nil {
			return err
		}
	}
	for kid, fp := range cfg.ECDSAFiles {
		if err := ldr.extractFromFile("config", "ecdsa", kid, fp); err != nil {
			return err
		}
	}
	if cfg.ECDSAFile != "" {
		if err := ldr.extractFromFile("config", "ecdsa", defaultKeyID, cfg.ECDSAFile); err != nil {
			return err
		}
	}
	for kid, secret := range cfg.ECDSAKeys {
		ldr.addKey(kid, "config", "ecdsa", secret)
	}
	if cfg.ECDSAKey != "" {
		ldr.addKey(defaultKeyID, "config", "ecdsa", cfg.ECDSAKey)
	}
	return nil
}

func (ldr *loader) loadEnv() error {
	// Extract default token lifetime.
	tokenLifetimeEnv := os.Getenv(EnvTokenLifetime)
	if tokenLifetimeEnv != "" {
		i, err := strconv.Atoi(tokenLifetimeEnv)
		if err != nil {
			return errors.ErrParseEnvVar.WithArgs(EnvTokenLifetime, err)
		}
		ldr.Lifetime = i
	}
	// Extract default token name.
	tokenNameEnv := os.Getenv(EnvTokenName)
	if tokenNameEnv != "" {
		ldr.Name = tokenNameEnv
	}

	// Extract keys.
	for _, envKV := range os.Environ() {
		kv := strings.SplitN(envKV, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.TrimSpace(kv[0])
		v := strings.TrimSpace(kv[1])
		if v == "" {
			continue
		}
		switch {
		case k == EnvTokenSecret:
			ldr.addKey(defaultKeyID, "env", "hmac", v)
		case k == EnvTokenRSADir:
			if err := ldr.extractFromDir("env", "rsa", v); err != nil {
				return err
			}
		case strings.HasPrefix(k, EnvTokenRSAFile):
			if err := ldr.extractFromFile("env", "rsa", k, v); err != nil {
				return err
			}
		case strings.HasPrefix(k, EnvTokenRSAKey):
			ldr.addKey(k, "env", "rsa", v)
		case k == EnvTokenECDSADir:
			if err := ldr.extractFromDir("env", "ecdsa", v); err != nil {
				return err
			}
		case strings.HasPrefix(k, EnvTokenECDSAFile):
			if err := ldr.extractFromFile("env", "ecdsa", k, v); err != nil {
				return err
			}
		case strings.HasPrefix(k, EnvTokenECDSAKey):
			ldr.addKey(k, "env", "ecdsa", v)
		}
	}
	return nil
}

func (ldr *loader) extractFromDir(src, keyType, dirPath string) error {
	if err := filepath.Walk(dirPath, func(fp string, fi os.FileInfo, err error) error {
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
		b, err := ioutil.ReadFile(fp)
		if err != nil {
			return errors.ErrReadPEMFile.WithArgs("dir", err)
		}
		kid := filepath.Base(fp)
		kid = strings.TrimSuffix(kid, ext)
		kid = normalizeKid(kid)
		ldr.addKey(kid, src, keyType, string(b), fp)
		return nil
	}); err != nil {
		return errors.ErrWalkDir.WithArgs(err)
	}
	return nil
}

func (ldr *loader) extractFromFile(src, keyType, kid, fp string) error {
	ext := filepath.Ext(fp)
	switch ext {
	case ".pem", ".key":
	default:
		return nil
	}
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return errors.ErrReadPEMFile.WithArgs("file", err)
	}
	if src == "config" || kid == defaultKeyID {
		ldr.addKey(kid, src, keyType, string(b), fp)
		return nil
	}
	for _, v := range ldr.vars {
		if !strings.HasPrefix(kid, v) {
			continue
		}
		ldr.addKey(kid, src, keyType, string(b), fp)
		return nil
	}
	kid = filepath.Base(fp)
	kid = strings.TrimSuffix(kid, ext)
	kid = normalizeKid(kid)
	ldr.addKey(kid, src, keyType, string(b), fp)
	return nil
}

func normalizeKid(s string) string {
	b := []byte{}
	for _, c := range []byte(s) {
		if ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') || c == '_' || c == '-' {
			b = append(b, c)
		}
	}
	return strings.ToLower(string(b))
}

func (ldr *loader) addKey(args ...string) {
	k := newKey()
	for i, v := range args {
		switch i {
		case 0:
			k.ID = strings.TrimSpace(v)
		case 1:
			k.Source = v
		case 2:
			k.Type = v
		case 3:
			k.Data = v
		case 4:
			k.Path = v
		}
	}
	// if k.ID == "" {
	//	k.ID = defaultKeyID
	//}
	for _, v := range ldr.vars {
		if !strings.HasPrefix(k.ID, v) {
			continue
		}
		k.ID = strings.TrimPrefix(k.ID, v)
		k.ID = strings.TrimLeft(k.ID, "_-")
		k.ID = normalizeKid(k.ID)
		break
	}
	if k.Name == "" {
		k.Name = ldr.Name
	}
	if k.ID == "" {
		k.ID = defaultKeyID
	}
	ldr.Keys = append(ldr.Keys, k)
}

func (ldr *loader) extract() (map[string]*Key, error) {
	var keySource string
	keys := make(map[string]*Key)
	keyTypes := make(map[string]bool)
	for _, k := range ldr.Keys {
		keyTypes[k.Type] = true
		keySource = k.Source
	}
	if len(keyTypes) == 0 {
		return nil, errors.ErrEncryptionKeysNotFound
	}
	keyTypeArr := []string{}
	for k := range keyTypes {
		keyTypeArr = append(keyTypeArr, k)
	}
	if len(keyTypes) > 1 {
		sort.Strings(keyTypeArr)
		return nil, errors.ErrMixedAlgorithms.WithArgs(keySource, keyTypeArr)
	}

	algo := keyTypeArr[0]
	supportedMethods := getMethodsPerAlgo(algo)
	for _, k := range ldr.Keys {
		if _, exists := keys[k.ID]; exists {
			return nil, errors.ErrFoundDuplicateKeyID.WithArgs(k.ID, algo, keySource)
		}
		switch algo {
		case "rsa":
			if strings.Contains(k.Data, "PRIVATE") {
				pk, err := jwtlib.ParseRSAPrivateKeyFromPEM([]byte(k.Data))
				if err != nil {
					return nil, errors.ErrParsePrivateRSAKey.WithArgs(err)
				}
				k.Sign.Secret = pk
				k.Sign.Token.Capable = true
				k.Sign.Token.PreferredMethods = supportedMethods
			} else {
				pk, err := jwtlib.ParseRSAPublicKeyFromPEM([]byte(k.Data))
				if err != nil {
					return nil, errors.ErrParsePublicRSAKey.WithArgs(err)
				}
				k.Verify.Secret = pk
			}
			k.Verify.Token.Capable = true
			k.Verify.Token.PreferredMethods = supportedMethods
			for _, m := range supportedMethods {
				if k.Sign.Token.Capable {
					k.Sign.Token.Methods[m] = true
				}
				k.Verify.Token.Methods[m] = true
			}
		case "ecdsa":
			// See https://golang.org/pkg/crypto/elliptic/
			var curve *elliptic.CurveParams
			var private bool
			var supportedMethod string
			if strings.Contains(k.Data, "PRIVATE") {
				pk, err := parseECDSAPrivateKey(k.Data)
				if err != nil {
					return nil, errors.ErrParsePrivateECDSAKey.WithArgs(err)
				}
				k.Sign.Secret = pk
				private = true
				curve = pk.Curve.Params()
			} else {
				// pk, err := jwtlib.ParseECPublicKeyFromPEM([]byte(k.Data))
				pk, err := parseECDSAPublicKey(k.Data)
				if err != nil {
					return nil, errors.ErrParsePublicECDSAKey.WithArgs(err)
				}
				k.Verify.Secret = pk
				curve = pk.Curve.Params()
			}
			if curve == nil {
				return nil, errors.ErrNoECDSACurveParamsFound
			}

			switch curve.Name {
			case "P-256":
				supportedMethod = "ES256"
			case "P-384":
				supportedMethod = "ES384"
			case "P-521":
				supportedMethod = "ES512"
			case "":
				return nil, errors.ErrEmptyECDSACurve
			default:
				return nil, errors.ErrUnsupportedECDSACurve.WithArgs(curve.Name)
			}
			if private {
				k.Sign.Token.Capable = true
				k.Sign.Token.PreferredMethods = []string{supportedMethod}
				k.Sign.Token.Methods[supportedMethod] = true
			}
			k.Verify.Token.Capable = true
			k.Verify.Token.PreferredMethods = []string{supportedMethod}
			k.Verify.Token.Methods[supportedMethod] = true
		case "hmac":
			k.Data = strings.TrimSpace(k.Data)
			if k.Data == "" {
				return nil, errors.ErrEmptySecret
			}
			k.Sign.Token.Capable = true
			k.Sign.Token.PreferredMethods = supportedMethods
			k.Verify.Token.Capable = true
			k.Verify.Token.PreferredMethods = supportedMethods
			for _, m := range supportedMethods {
				k.Sign.Token.Methods[m] = nil
				k.Verify.Token.Methods[m] = nil
			}
			k.Sign.Secret = []byte(k.Data)
			k.Verify.Secret = []byte(k.Data)
		}
		if k.Verify.Token.Capable {
			k.Verify.Capable = true
			k.Verify.Token.DefaultMethod = k.Verify.Token.PreferredMethods[0]
		}
		if k.Sign.Token.Capable {
			k.Sign.Capable = true
			k.Sign.Token.DefaultMethod = k.Sign.Token.PreferredMethods[0]
		}
		keys[k.ID] = k
	}
	if len(keys) == 0 {
		return nil, errors.ErrEncryptionKeysNotFound
	}
	return keys, nil
}

func (km *KeyManager) loadKeys() error {
	if km.err != nil {
		return km.err
	}
	if km.loaded {
		return nil
	}

	loader := newLoader()
	if km.cryptoKeyConfig != nil {
		km.keyOrigin = "config"
		if err := loader.loadConfig(km.cryptoKeyConfig); err != nil {
			return err
		}
	} else {
		km.keyOrigin = "env"
		cryptoKeyConfig, err := NewCryptoKeyConfig()
		if err != nil {
			return err
		}
		km.cryptoKeyConfig = cryptoKeyConfig
		if err := loader.loadEnv(); err != nil {
			return err
		}
	}

	// Iterate over the found keys and check for conflicts.

	// Set default token lifetime.
	if loader.Lifetime > 0 {
		km.cryptoKeyConfig.Lifetime = loader.Lifetime
	}
	if km.cryptoKeyConfig.Lifetime == 0 {
		km.cryptoKeyConfig.Lifetime = defaultTokenLifetime
	}

	// Set default token name.
	switch {
	case km.cryptoKeyConfig.Name == "":
		if loader.Name != "" {
			km.cryptoKeyConfig.Name = loader.Name
			break
		}
		km.cryptoKeyConfig.Name = defaultTokenName
	}

	keys, err := loader.extract()
	if err != nil {
		return err
	}

	if len(keys) == 0 {
		return errors.ErrEncryptionKeysNotFound
	}

	for kid, key := range keys {
		key.Name = km.cryptoKeyConfig.Name
		key.Sign.Token.Name = km.cryptoKeyConfig.Name
		key.Verify.Token.Name = km.cryptoKeyConfig.Name
		key.Sign.Token.MaxLifetime = km.cryptoKeyConfig.Lifetime
		key.Verify.Token.MaxLifetime = km.cryptoKeyConfig.Lifetime
		if kid != defaultKeyID && kid != "" {
			key.Sign.Token.injectKeyID = true
			key.Verify.Token.injectKeyID = true
		}
		if err := km.addKey(kid, key); err != nil {
			return err
		}
	}
	return nil
}
