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

package validator

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	jwtlib "github.com/dgrijalva/jwt-go"
	//"go.uber.org/zap"
	jwtconfig "github.com/greenpau/caddy-auth-jwt/pkg/config"
	jwterrors "github.com/greenpau/caddy-auth-jwt/pkg/errors"
)

var defaultKeyID = "0"

// rsaSource is what source will override the other
var rsaSource = []string{"key", "file", "dir"}

// rsaConfigSource is where config options will look
var rsaConfigSource = []string{"env", "config"} // this is how tokenSecret works

type kmsLoader struct {
	conf          *jwtconfig.CommonTokenConfig
	_dir          string
	_files, _keys map[string]string
}

func (l *kmsLoader) config() {
	configDir := l.conf.TokenRSADir
	if configDir != "" {
		l._dir = configDir
	}

	for k, v := range l.conf.TokenRSAFiles {
		l._files[k] = v
	}
	for k, v := range l.conf.TokenRSAKeys {
		l._keys[k] = v
	}

	if l.conf.TokenRSAFile != "" {
		if _, ok := l._files[defaultKeyID]; !ok {
			l._files[defaultKeyID] = l.conf.TokenRSAFile // <- overwrite explict key
		}
	}
	if l.conf.TokenRSAKey != "" {
		if _, ok := l._keys[defaultKeyID]; !ok {
			l._keys[defaultKeyID] = l.conf.TokenRSAKey // <- overwrite explict key
		}
	}
}

func (l *kmsLoader) env() {
	envDir := os.Getenv(jwtconfig.EnvTokenRSADir)
	if envDir != "" {
		l._dir = envDir
	}

	for _, envKV := range os.Environ() {
		kv := strings.SplitN(envKV, "=", 2)
		if len(kv) == 2 {
			switch {
			case strings.HasPrefix(kv[0], jwtconfig.EnvTokenRSAFile):
				k := strings.TrimPrefix(kv[0], jwtconfig.EnvTokenRSAFile)
				if len(k) == 0 {
					if _, ok := l._files[defaultKeyID]; ok {
						continue // don't overwrite an explict key
					}
					k = defaultKeyID
				}
				l._files[strings.ToLower(strings.TrimLeft(k, "_"))] = kv[1]
			case strings.HasPrefix(kv[0], jwtconfig.EnvTokenRSAKey):
				k := strings.TrimPrefix(kv[0], jwtconfig.EnvTokenRSAKey)
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
}

func (l *kmsLoader) directory() (done bool, err error) {
	slash := string(filepath.Separator)
	if len(l._dir) > 0 {
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
		done = true // we have success
	}
	return done, err
}

func (l *kmsLoader) file() (done bool, err error) {
	if len(l._files) > 0 {
		for kid, filePath := range l._files {
			if _, ok := l._keys[kid]; !ok {
				b, err := ioutil.ReadFile(filePath)
				if err != nil {
					return false, jwterrors.ErrReadPEMFile.WithArgs("file", err)
				}

				l._keys[kid] = string(b)
			}
		}
		done = true // success
	}
	return done, err
}

func (l *kmsLoader) key() (done bool, err error) {
	if len(l._keys) > 0 {
		done = len(l._files) == 0
	}
	return done, err
}

// LoadEncryptionKeys loads keys for the RSA encryption based on the order determined
// by rsaSource and rsaConfigSource
func LoadEncryptionKeys(config *jwtconfig.CommonTokenConfig) error {
	loader := &kmsLoader{
		conf: config,
		// log:    logger,
		_keys:  make(map[string]string),
		_files: make(map[string]string),
	}

	// cs is the configSource
	cs := map[string]func(){
		"config": loader.config,
		"env":    loader.env,
	}

	// ss is the sourceSource
	ss := map[string]func() (bool, error){
		"dir":  loader.directory,
		"file": loader.file,
		"key":  loader.key,
	}

	for _, configSrc := range rsaConfigSource {
		fn, exists := cs[configSrc]
		if !exists {
			return jwterrors.ErrUnknownConfigSource
		}
		fn()
	}

	for _, src := range rsaSource {
		fn, exists := ss[src]
		if !exists {
			return jwterrors.ErrUnknownConfigSource
		}
		done, err := fn()
		if err != nil {
			return err
		}
		if done {
			break
		}
	}

	var rtnErr error
	for k, v := range loader._keys {
		//loader.log.Info("RSA key processing...", zap.String("name", k))

		switch {
		case strings.Contains(v, "BEGIN RSA PRIVATE"):
			pk, err := jwtlib.ParseRSAPrivateKeyFromPEM([]byte(v))
			if err != nil {
				rtnErr = fmt.Errorf("%v %w", rtnErr, err) // wraps error
				continue
			}
			config.AddTokenKey(k, pk)
			//loader.log.Info("RSA private key added", zap.String("name", k))
		case strings.Contains(v, "BEGIN PUBLIC KEY"):
			pk, err := jwtlib.ParseRSAPublicKeyFromPEM([]byte(v))
			if err != nil {
				rtnErr = fmt.Errorf("%v %w", rtnErr, err) // wraps error
				continue
			}
			config.AddTokenKey(k, pk)
			//loader.log.Info("RS public key added", zap.String("name", k))
		}
	}

	return rtnErr
}
