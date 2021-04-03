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
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	jwtlib "github.com/dgrijalva/jwt-go"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
)

type kmsLoader struct {
	conf      *KeyManager
	_dir      string
	_files    map[string]string
	_keys     map[string]string
	_keyType  string
	_keyTypes map[string]bool
	_lifetime int
	_name     string
}

func (l *kmsLoader) parseECDSAPrivateKey(s string) (*ecdsa.PrivateKey, error) {
	var key interface{}
	var err error
	var block *pem.Block
	if block, _ = pem.Decode([]byte(s)); block == nil {
		return nil, errors.ErrPayloadNotPEMEncoded
	}
	key, err = x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	var pkey *ecdsa.PrivateKey
	var ok bool
	if pkey, ok = key.(*ecdsa.PrivateKey); !ok {
		return nil, errors.ErrNotECDSAPrivateKey
	}

	return pkey, nil
}

func (l *kmsLoader) checkTypes(s string) error {
	var arr []string
	if len(l._keyTypes) == 0 {
		return nil
	}
	for k := range l._keyTypes {
		arr = append(arr, k)
	}
	if len(arr) > 1 {
		return errors.ErrMixedAlgorithms.WithArgs(s + " for " + strings.Join(arr, ", "))
	}
	l._keyType = arr[0]
	return nil
}

func (l *kmsLoader) config() error {
	var rsaConfigFound, ecdsaConfigFound bool

	// Shared secret
	if l.conf.TokenSecret != "" {
		l._keyTypes["hmac"] = true
		l._keys[defaultKeyID] = l.conf.TokenSecret
	}

	// RSA Keys
	if l.conf.TokenRSADir != "" {
		l._dir = l.conf.TokenRSADir
		rsaConfigFound = true
	}
	for k, v := range l.conf.TokenRSAFiles {
		l._files[k] = v
		rsaConfigFound = true
	}
	for k, v := range l.conf.TokenRSAKeys {
		l._keys[k] = v
		rsaConfigFound = true
	}
	if l.conf.TokenRSAFile != "" {
		if _, ok := l._files[defaultKeyID]; !ok {
			l._files[defaultKeyID] = l.conf.TokenRSAFile // <- overwrite explict key
			rsaConfigFound = true
		}
	}
	if l.conf.TokenRSAKey != "" {
		if _, ok := l._keys[defaultKeyID]; !ok {
			l._keys[defaultKeyID] = l.conf.TokenRSAKey // <- overwrite explict key
			rsaConfigFound = true
		}
	}

	// ECDSA Keys
	if l.conf.TokenECDSADir != "" {
		l._dir = l.conf.TokenECDSADir
		ecdsaConfigFound = true
	}
	for k, v := range l.conf.TokenECDSAFiles {
		l._files[k] = v
		ecdsaConfigFound = true
	}
	for k, v := range l.conf.TokenECDSAKeys {
		l._keys[k] = v
		ecdsaConfigFound = true
	}
	if l.conf.TokenECDSAFile != "" {
		if _, ok := l._files[defaultKeyID]; !ok {
			l._files[defaultKeyID] = l.conf.TokenECDSAFile // <- overwrite explict key
			ecdsaConfigFound = true
		}
	}
	if l.conf.TokenECDSAKey != "" {
		if _, ok := l._keys[defaultKeyID]; !ok {
			l._keys[defaultKeyID] = l.conf.TokenECDSAKey // <- overwrite explict key
			ecdsaConfigFound = true
		}
	}

	if rsaConfigFound {
		l._keyTypes["rsa"] = true
	}
	if ecdsaConfigFound {
		l._keyTypes["ecdsa"] = true
	}

	if err := l.checkTypes("config"); err != nil {
		return err
	}

	return nil
}

func (l *kmsLoader) env() error {
	var rsaConfigFound, ecdsaConfigFound bool

	// Extract default token lifetime.
	tokenLifetimeEnv := os.Getenv(EnvTokenLifetime)
	if tokenLifetimeEnv != "" {
		i, err := strconv.Atoi(tokenLifetimeEnv)
		if err != nil {
			return errors.ErrParseEnvVar.WithArgs(EnvTokenLifetime, err)
		}
		l._lifetime = i
	}

	// Extract default token name.
	tokenNameEnv := os.Getenv(EnvTokenName)
	if tokenNameEnv != "" {
		l._name = tokenNameEnv
	}

	rsaEnvDir := os.Getenv(EnvTokenRSADir)
	if rsaEnvDir != "" {
		l._dir = rsaEnvDir
		rsaConfigFound = true
	}

	ecdsaEnvDir := os.Getenv(EnvTokenECDSADir)
	if ecdsaEnvDir != "" {
		l._dir = ecdsaEnvDir
		ecdsaConfigFound = true
	}

	for _, envKV := range os.Environ() {
		kv := strings.SplitN(envKV, "=", 2)
		if len(kv) == 2 {
			switch {
			case strings.HasPrefix(kv[0], EnvTokenSecret):
				l._keyTypes["hmac"] = true
				l._keys[defaultKeyID] = kv[1]
			case strings.HasPrefix(kv[0], EnvTokenRSAFile):
				k := strings.TrimPrefix(kv[0], EnvTokenRSAFile)
				rsaConfigFound = true
				if len(k) == 0 {
					if _, ok := l._files[defaultKeyID]; ok {
						continue // don't overwrite an explict key
					}
					k = defaultKeyID
				}
				l._files[strings.ToLower(strings.TrimLeft(k, "_"))] = kv[1]
			case strings.HasPrefix(kv[0], EnvTokenRSAKey):
				k := strings.TrimPrefix(kv[0], EnvTokenRSAKey)
				rsaConfigFound = true
				if len(k) == 0 {
					if _, ok := l._keys[defaultKeyID]; ok {
						continue // don't overwrite an explict key
					}
					k = defaultKeyID
				}
				l._keys[strings.ToLower(strings.TrimLeft(k, "_"))] = kv[1]
			case strings.HasPrefix(kv[0], EnvTokenECDSAFile):
				k := strings.TrimPrefix(kv[0], EnvTokenECDSAFile)
				ecdsaConfigFound = true
				if len(k) == 0 {
					if _, ok := l._files[defaultKeyID]; ok {
						continue // don't overwrite an explict key
					}
					k = defaultKeyID
				}
				l._files[strings.ToLower(strings.TrimLeft(k, "_"))] = kv[1]
			case strings.HasPrefix(kv[0], EnvTokenECDSAKey):
				k := strings.TrimPrefix(kv[0], EnvTokenECDSAKey)
				ecdsaConfigFound = true
				if len(k) == 0 {
					if _, ok := l._keys[defaultKeyID]; ok {
						continue // don't overwrite an explict key
					}
					k = defaultKeyID
				}
				l._keys[strings.ToLower(strings.TrimLeft(k, "_"))] = kv[1]
			}
		}
	}

	if rsaConfigFound {
		l._keyTypes["rsa"] = true
	}
	if ecdsaConfigFound {
		l._keyTypes["ecdsa"] = true
	}

	if err := l.checkTypes("env"); err != nil {
		return err
	}

	return nil
}

func (l *kmsLoader) directory() (found bool, err error) {
	slash := string(filepath.Separator)
	if len(l._dir) == 0 {
		return found, err
	}
	err = filepath.Walk(l._dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}

		absDir, err := filepath.Abs(l._dir)
		if err != nil {
			absDir = l._dir // just fall back to the value we had before
		}
		absPath, err := filepath.Abs(path)
		if err != nil {
			absPath = path
		}
		kid := strings.TrimPrefix(absPath, absDir)
		kid = strings.TrimSuffix(kid, ".key")
		kid = strings.TrimSuffix(kid, ".pem")
		kid = strings.Replace(kid, slash, "_", -1)
		kid = strings.Trim(kid, "_")
		kid = normalizeKid(kid)
		if _, ok := l._keys[kid]; !ok {
			b, err := ioutil.ReadFile(path)
			if err != nil {
				return errors.ErrReadPEMFile.WithArgs("dir", err)
			}
			l._keys[kid] = string(b)
		}
		return nil
	})
	if err != nil {
		return false, errors.ErrWalkDir.WithArgs(err)
	}
	found = true
	return found, err
}

func (l *kmsLoader) file() (found bool, err error) {
	if len(l._files) == 0 {
		return found, err
	}
	for kid, filePath := range l._files {
		if _, kidFound := l._keys[kid]; kidFound {
			continue
		}
		b, err := ioutil.ReadFile(filePath)
		if err != nil {
			return false, errors.ErrReadPEMFile.WithArgs("file", err)
		}
		l._keys[kid] = string(b)
	}
	found = true
	return found, err
}

func (l *kmsLoader) key() (found bool, err error) {
	if len(l._keys) > 0 {
		found = len(l._files) == 0
	}
	return found, err
}

func (km *KeyManager) discover() error {
	keyMaterialSources := []string{"key", "file", "dir"}
	tokenSources := []string{"env", "config"}
	loader := &kmsLoader{
		conf:      km,
		_keys:     make(map[string]string),
		_files:    make(map[string]string),
		_keyTypes: make(map[string]bool),
	}

	// configOriginFn maps configuration origin names with the corresponding
	// loading function.
	configOriginFn := map[string]func() error{
		"config": loader.config,
		"env":    loader.env,
	}

	// keyMaterialSourceExtractionFn maps key material sources with the
	// corresponding key material extraction function.
	keyMaterialSourceExtractionFn := map[string]func() (bool, error){
		"key":  loader.key,
		"file": loader.file,
		"dir":  loader.directory,
	}

	// Iterate over default configuration origin names, e.g. env or config,
	// determine the appropriate loader function for a particular origin,
	// and invoke it.
	for _, configOrigin := range tokenSources {
		fn, exists := configOriginFn[configOrigin]
		if !exists {
			return errors.ErrUnknownConfigSource
		}
		if err := fn(); err != nil {
			return err
		}
	}

	switch {
	case km.TokenLifetime == 0:
		if loader._lifetime > 0 {
			km.TokenLifetime = loader._lifetime
			break
		}
		km.TokenLifetime = defaultTokenLifetime
	}

	switch {
	case km.TokenName == "":
		if loader._name != "" {
			km.TokenName = loader._name
			break
		}
		km.TokenName = defaultTokenName
	}

	// Iterate over default key material sources, e.g. key, file, and dir,
	// and run the corresponding key material extraction function.
	for _, keyMaterialSource := range keyMaterialSources {
		fn, exists := keyMaterialSourceExtractionFn[keyMaterialSource]
		if !exists {
			return errors.ErrUnknownConfigSource
		}
		found, err := fn()
		if err != nil {
			return err
		}
		if found {
			break
		}
	}

	if err := loader.checkTypes("prikeys"); err != nil {
		return err
	}

	// First, run through the existing keys and determine the ones that
	// are private.
	for k, v := range loader._keys {
		if loader._keyType == "hmac" {
			break
		}
		if !strings.Contains(v, "PRIVATE") {
			continue
		}
		switch {
		case loader._keyType == "rsa":
			pk, err := jwtlib.ParseRSAPrivateKeyFromPEM([]byte(v))
			if err != nil {
				return errors.ErrParsePrivateRSAKey.WithArgs(err)
			}
			if err := km.AddKey(k, pk); err != nil {
				return err
			}
		case loader._keyType == "ecdsa":
			pk, err := loader.parseECDSAPrivateKey(v)
			if err != nil {
				return errors.ErrParsePrivateECDSAKey.WithArgs(err)
			}
			if err := km.AddKey(k, pk); err != nil {
				return err
			}
		}
	}

	// Second, determine the key type for the public key.
	if err := loader.checkTypes("pubkeys"); err != nil {
		return err
	}

	// Finally, parse public keys
	for k, v := range loader._keys {
		if loader._keyType == "hmac" {
			break
		}
		if strings.Contains(v, "PRIVATE") {
			continue
		}
		switch {
		case strings.Contains(v, "BEGIN PUBLIC KEY"):
			switch loader._keyType {
			case "rsa":
				pk, err := jwtlib.ParseRSAPublicKeyFromPEM([]byte(v))
				if err != nil {
					return errors.ErrParsePublicRSAKey.WithArgs(err)
				}
				if err := km.AddKey(k, pk); err != nil {
					return err
				}
			case "ecdsa":
				pk, err := jwtlib.ParseECPublicKeyFromPEM([]byte(v))
				if err != nil {
					return errors.ErrParsePublicECDSAKey.WithArgs(err)
				}
				if err := km.AddKey(k, pk); err != nil {
					return err
				}
			}
		}
	}

	if loader._keyType == "hmac" {
		if err := km.AddKey(defaultKeyID, loader._keys[defaultKeyID]); err != nil {
			return err
		}
	}

	if km.keyCount == 0 {
		return errors.ErrEncryptionKeysNotFound
	}
	return nil
}

func normalizeKid(s string) string {
	b := []byte{}
	for _, c := range []byte(s) {
		if ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') ||
			('0' <= c && c <= '9') || c == '_' {
			b = append(b, c)
		}
	}
	return string(b)
}
