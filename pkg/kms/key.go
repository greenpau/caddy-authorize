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
	jwtlib "github.com/dgrijalva/jwt-go"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
)

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
func (k *Key) SignToken(signMethod, data interface{}) (string, error) {
	if !k.Sign.Token.Capable {
		return "", errors.ErrSigningKeyNotFound.WithArgs(signMethod)
	}
	response, err := k.sign(signMethod, data)
	if err != nil {
		return "", err
	}
	return response.(string), nil
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
