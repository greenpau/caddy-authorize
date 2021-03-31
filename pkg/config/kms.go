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
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	jwtlib "github.com/dgrijalva/jwt-go"
	jwterrors "github.com/greenpau/caddy-auth-jwt/pkg/errors"
)

type kmsLoader struct {
	conf      *CommonTokenConfig
	_dir      string
	_files    map[string]string
	_keys     map[string]string
	_keyType  string
	_keyTypes map[string]bool
}

func (l *kmsLoader) parseECDSAPrivateKey(s string) (*ecdsa.PrivateKey, error) {
	var key interface{}
	var err error
	var block *pem.Block
	if block, _ = pem.Decode([]byte(s)); block == nil {
		return nil, jwterrors.ErrPayloadNotPEMEncoded
	}
	key, err = x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	var pkey *ecdsa.PrivateKey
	var ok bool
	if pkey, ok = key.(*ecdsa.PrivateKey); !ok {
		return nil, jwterrors.ErrNotECDSAPrivateKey
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
		return jwterrors.ErrMixedAlgorithms.WithArgs(s + " for " + strings.Join(arr, ", "))
	}
	l._keyType = arr[0]
	return nil
}

func (l *kmsLoader) config() error {
	var rsaConfigFound, ecdsaConfigFound bool

	// Shared secret
	if l.conf.TokenSecret != "" {
		l._keyTypes["secret"] = true
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
				l.conf.TokenSecret = kv[1]
				l._keyTypes["secret"] = true
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
		key := strings.TrimPrefix(absPath, absDir)
		key = strings.TrimSuffix(key, ".key")
		key = strings.TrimSuffix(key, ".pem")
		key = strings.Replace(key, slash, "_", -1)
		key = strings.Trim(key, "_")
		for i := 0; i < len(key); i++ {
			c := key[i]
			switch {
			case c == 95, // make sure we only have chars [0-9a-zA-Z_]
				c >= 48 && c <= 57,
				c >= 65 && c <= 90,
				c >= 97 && c <= 122:
				continue
			}
			return nil
		}

		if _, ok := l._keys[key]; !ok {
			b, err := ioutil.ReadFile(path)
			if err != nil {
				return jwterrors.ErrReadPEMFile.WithArgs("dir", err)
			}

			l._keys[key] = string(b)
		}
		return nil
	})
	if err != nil {
		return false, jwterrors.ErrWalkDir.WithArgs(err)
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
			return false, jwterrors.ErrReadPEMFile.WithArgs("file", err)
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

func (config *CommonTokenConfig) load() error {
	keyMaterialSources := []string{"key", "file", "dir"}
	tokenSources := []string{"env", "config"}
	loader := &kmsLoader{
		conf:      config,
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
			return jwterrors.ErrUnknownConfigSource
		}
		if err := fn(); err != nil {
			return err
		}
	}

	// Iterate over default key material sources, e.g. key, file, and dir,
	// and run the corresponding key material extraction function.
	for _, keyMaterialSource := range keyMaterialSources {
		fn, exists := keyMaterialSourceExtractionFn[keyMaterialSource]
		if !exists {
			return jwterrors.ErrUnknownConfigSource
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
		if !strings.Contains(v, "PRIVATE") {
			continue
		}
		switch {
		case loader._keyType == "rsa":
			pk, err := jwtlib.ParseRSAPrivateKeyFromPEM([]byte(v))
			if err != nil {
				return fmt.Errorf("error parsing RSA private key: %s", err)
			}
			if err := config.AddKey(k, pk); err != nil {
				return err
			}
		case loader._keyType == "ecdsa":
			pk, err := loader.parseECDSAPrivateKey(v)
			if err != nil {
				return fmt.Errorf("error parsing ECDSA private key: %s, %s", err, v)
			}
			if err := config.AddKey(k, pk); err != nil {
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
		if strings.Contains(v, "PRIVATE") {
			continue
		}
		switch {
		case strings.Contains(v, "BEGIN PUBLIC KEY"):
			switch loader._keyType {
			case "rsa":
				pk, err := jwtlib.ParseRSAPublicKeyFromPEM([]byte(v))
				if err != nil {
					return fmt.Errorf("error parsing RSA public key: %s", err)
				}
				if err := config.AddKey(k, pk); err != nil {
					return err
				}
			case "ecdsa":
				pk, err := jwtlib.ParseECPublicKeyFromPEM([]byte(v))
				if err != nil {
					return fmt.Errorf("error parsing ECDSA public key: %s", err)
				}
				if err := config.AddKey(k, pk); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("unknown key material: %s, %s", k, v)
		}
	}

	if len(loader._keys) == 0 {
		if config.TokenSecret != "" {
			if err := config.AddKey("secret", config.TokenSecret); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("no encryption keys found")
		}
	}

	return nil
}
