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

package errors

// Key Management System Errors
const (
	// CryptoKeyConfig
	ErrCryptoKeyConfigNewInvalidArgs            StandardError = "kms: invalid token config arguments: %v"
	ErrCryptoKeyConfigNewArgTypeInvalid         StandardError = "kms: invalid token config argument type: %T"
	ErrCryptoKeyConfigNewFailedUnmarshal        StandardError = "kms: failed unmarshal token config: %v"
	ErrCryptoKeyConfigNewEmptyArg               StandardError = "kms: emtpy token config arguments"
	ErrCryptoKeyConfigMultipleDefaultKeys       StandardError = "kms: token config contains multiple default keys"
	ErrCryptoKeyConfigReadFile                  StandardError = "kms: failed to open file %q referenced in token config: %v"
	ErrCryptoKeyConfigFileNotSupported          StandardError = "kms: file %q is not supported due to extension type"
	ErrCryptoKeyConfigFileKeyNotFound           StandardError = "kms: file %q has no keys"
	ErrCryptoKeyConfigUnsupportedPrivateKeyAlgo StandardError = "unsupported private key algo %T"
	ErrCryptoKeyConfigUnsupportedPublicKeyAlgo  StandardError = "unsupported public key algo %T"

	// KeyManager
	ErrKeyManagerAddKeyNil                  StandardError = "kms: failed adding nil key to key manager"
	ErrKeyManagerCryptoKeyConfigInvalidType StandardError = "kms: failed key manager with invalid token config type: %T"
	// Keystore
	ErrKeystoreAddKeyNil              StandardError = "keystore: failed adding nil key to keystore"
	ErrKeystoreParseTokenFailed       StandardError = "keystore: failed to parse token"
	ErrCryptoKeyStoreAddKeyNil        StandardError = "keystore: failed adding nil key to keystore"
	ErrCryptoKeyStoreParseTokenFailed StandardError = "keystore: failed to parse token"
	ErrCryptoKeyStoreSignTokenFailed  StandardError = "keystore: failed to sign token"
	// Signing
	ErrUnsupportedSigningMethod StandardError = "kms: grantor does not support %s token signing method"
)
