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
	"github.com/greenpau/caddy-auth-jwt/pkg/tests"
	"testing"
)

func TestGetSigningMethodAlias(t *testing.T) {
	var testcases = []struct {
		name  string
		input string
		want  string
	}{
		{name: "HS256", want: "hmac"},
		{name: "HS384", want: "hmac"},
		{name: "HS512", want: "hmac"},
		{name: "RS256", want: "rsa"},
		{name: "RS384", want: "rsa"},
		{name: "RS512", want: "rsa"},
		{name: "ES256", want: "ecdsa"},
		{name: "ES384", want: "ecdsa"},
		{name: "ES512", want: "ecdsa"},
		{name: "TBD", want: "unknown"},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var input, want, got string
			input = tc.input
			if input == "" {
				input = tc.name
			}
			want = tc.want
			if want == "" {
				want = input
			}
			got = getSigningMethodAlias(input)
			tests.EvalObjects(t, "output", want, got)
		})
	}
}
