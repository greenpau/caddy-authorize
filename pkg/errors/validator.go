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

package errors

// Token Validator Errors
const (
	ErrValidatorCryptoKeyStoreNoKeys       StandardError = "token validator: no keys found when adding to keystore"
	ErrValidatorCryptoKeyStoreNoVerifyKeys StandardError = "token validator: no verification keys found when adding to keystore"
	ErrValidatorInvalidToken               StandardError = "token validator: invalid token: %v"
	ErrInvalidSourcePriority               StandardError = "token validator: invalid token source priority"
	ErrInvalidSourceName                   StandardError = "token validator: invalid token source name: %s"
	ErrDuplicateSourceName                 StandardError = "token validator: duplicate token source name: %s"
	ErrTokenNamesNotFound                  StandardError = "token validator: allowed token names not provided"
	ErrEmptyTokenName                      StandardError = "token validator: a token name is empty"
	ErrDuplicateTokenName                  StandardError = "token validator: duplicate allowed token name: %s"
	ErrTokenValidatorOptionsNotFound       StandardError = "token validator: options not found"
)
