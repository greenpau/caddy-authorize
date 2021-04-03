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
	"strings"
)

// SigningMethods are supported JWT token signing methods.
var SigningMethods = map[string]string{
	"HS256": "hmac",
	"HS384": "hmac",
	"HS512": "hmac",
	"RS256": "rsa",
	"RS384": "rsa",
	"RS512": "rsa",
	"ES256": "ecdsa",
	"ES384": "ecdsa",
	"ES512": "ecdsa",
}

// GetSigningMethodAlias returns alias for the provided signing method.
func GetSigningMethodAlias(s string) string {
	s = strings.ToUpper(s)
	if v, exists := SigningMethods[s]; exists {
		arr := strings.SplitN(v, ",", 2)
		return strings.TrimSpace(arr[0])
	}
	return "unknown"
}
