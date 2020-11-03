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

// Errors associated with backend package.
const (
	ErrInvalidSecretLength StandardError = "secrets less than 16 characters in length are not allowed"
	ErrUnexpectedKID       StandardError = "the kid specified in the header was not found"
	ErrNoRSAKeyFound       StandardError = "no RSA key found"

	ErrUnexpectedSigningMethod StandardError = "signing method mismatch: %v (expected) vs. %v (received)"
)
