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

package grantor

import (
	"errors"
	jwterrors "github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"testing"
)

// TestGrantorError tests using errors as values
func TestGrantorError(t *testing.T) {
	g := NewTokenGrantor()
	err := g.Validate()

	if err == nil {
		t.Fatal("expected error")
	}

	// confirm we can check for the proper error
	if !errors.Is(err, jwterrors.ErrEmptySecret) {
		t.Fatalf("expected: %q got: %q", jwterrors.ErrEmptySecret, err)
	}

	// confirm that any error is not matching
	if errors.Is(err, jwterrors.ErrNoClaims) {
		t.Fatalf("expected: %q got: %q", jwterrors.ErrNoClaims, err)
	}

	// show that we can check for an error that has dynamic content
	_, err = g.GrantToken("apple", nil)
	if errors.Is(err, jwterrors.ErrUnsupportedSigningMethod) {
		if err.Error() != "grantor does not support apple token signing method" {
			t.Fatalf("expected: %q (filled in) got: %q", jwterrors.ErrUnsupportedSigningMethod, err.Error())
		}
	}
}
