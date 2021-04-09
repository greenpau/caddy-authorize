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

package acl

import (
	"github.com/greenpau/caddy-auth-jwt/pkg/tests"
	"testing"
)

func TestMatchPathBasedACL(t *testing.T) {
	testcases := []struct {
		name            string
		pattern         string
		matchedPaths    []string
		mismatchedPaths []string
	}{
		{
			name:    "match path based acl with max depth",
			pattern: "/*/media/**",
			matchedPaths: []string{
				"/app/media/icon.png",
				"/app/media/icon~png",
				"/app/media/assets/icon.png",
				"/app/media/assets/images/icon.png",
			},
			mismatchedPaths: []string{
				"/app/assets/media/icon.png",
				"/app/assets/media/assets/icon.png",
				"/app/assets/media/assets/images/icon.png",
				"/media/icon.png",
			},
		},
		{
			name:    "match path based acl with limited depth",
			pattern: "/*/media/*",
			matchedPaths: []string{
				"/app/media/icon.png",
				"/app/media/icon~png",
			},
			mismatchedPaths: []string{
				"/app/media/assets/images/icon.png",
				"/app/media/assets/icon.png",
				"/app/assets/media/icon.png",
				"/app/assets/media/assets/icon.png",
				"/app/assets/media/assets/images/icon.png",
				"/media/icon.png",
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			want := make(map[string]interface{})
			got := make(map[string]interface{})
			for _, p := range tc.matchedPaths {
				want[p] = true
				got[p] = MatchPathBasedACL(tc.pattern, p)
			}
			for _, p := range tc.mismatchedPaths {
				want[p] = false
				got[p] = MatchPathBasedACL(tc.pattern, p)
			}
			tests.EvalObjects(t, "output", want, got)
		})
	}
}
