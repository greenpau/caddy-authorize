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
	"regexp"
	"strings"
)

var pathACLPatterns map[string]*regexp.Regexp

func init() {
	pathACLPatterns = make(map[string]*regexp.Regexp)
}

// MatchPathBasedACL matches pattern in a URI.
func MatchPathBasedACL(pattern, uri string) bool {
	// First, handle the case where there are no wildcards
	if pattern == "" {
		return false
	}
	if !strings.Contains(pattern, "*") {
		if pattern == uri {
			return true
		}
		return false
	}

	// Next, handle the case where wildcards are present
	var regex *regexp.Regexp
	var found bool

	// Check cached entries
	regex, found = pathACLPatterns[pattern]
	if !found {
		// advPattern = strings.ReplaceAll(pattern, "/", "\\/")
		advPattern := strings.ReplaceAll(pattern, "**", "[a-zA-Z0-9_/.~-]+")
		advPattern = strings.ReplaceAll(advPattern, "*", "[a-zA-Z0-9_.~-]+")
		advPattern = "^" + advPattern + "$"
		r, err := regexp.Compile(advPattern)
		if err != nil {
			pathACLPatterns[pattern] = nil
			return false
		}
		pathACLPatterns[pattern] = r
		regex = r
	}
	if regex == nil {
		return false
	}

	return regex.MatchString(uri)
}
