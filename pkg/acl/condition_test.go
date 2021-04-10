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
	"context"
	"fmt"
	"github.com/greenpau/caddy-auth-jwt/pkg/tests"
	"reflect"
	"strings"
	"testing"
)

func TestNewAclRuleCondition(t *testing.T) {
	var testcases = []struct {
		name      string
		condition string
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name:      "exact match a list of strings input against a list of strings in roles field",
			condition: `exact match roles barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondExactMatchListStrInput",
				"field_name":     "roles",
			},
		}, {
			name:      "default match a list of strings input against a list of strings in roles field",
			condition: ` match roles barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondExactMatchListStrInput",
				"field_name":     "roles",
			},
		}, {
			name:      "exact match a list of strings input against a string condition in roles field",
			condition: `exact match roles foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondExactMatchListStrInput",
				"field_name":     "roles",
			},
		}, {
			name:      "default match a list of strings input against a string condition in roles field",
			condition: ` match roles foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondExactMatchListStrInput",
				"field_name":     "roles",
			},
		}, {
			name:      "partial match a list of strings input against a list of strings in roles field",
			condition: `partial match roles barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondPartialMatchListStrInput",
				"field_name":     "roles",
			},
		}, {
			name:      "partial match a list of strings input against a string condition in roles field",
			condition: `partial match roles foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondPartialMatchListStrInput",
				"field_name":     "roles",
			},
		}, {
			name:      "prefix match a list of strings input against a list of strings in roles field",
			condition: `prefix match roles barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondPrefixMatchListStrInput",
				"field_name":     "roles",
			},
		}, {
			name:      "prefix match a list of strings input against a string condition in roles field",
			condition: `prefix match roles foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondPrefixMatchListStrInput",
				"field_name":     "roles",
			},
		}, {
			name:      "suffix match a list of strings input against a list of strings in roles field",
			condition: `suffix match roles barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondSuffixMatchListStrInput",
				"field_name":     "roles",
			},
		}, {
			name:      "suffix match a list of strings input against a string condition in roles field",
			condition: `suffix match roles foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondSuffixMatchListStrInput",
				"field_name":     "roles",
			},
		}, {
			name:      "regex match a list of strings input against a list of strings in roles field",
			condition: `regex match roles barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondRegexMatchListStrInput",
				"field_name":     "roles",
			},
		}, {
			name:      "failed regex match a list of strings input against a list of strings in roles field",
			condition: `regex match roles barfoo (foobar|raboff`,
			shouldErr: true,
			err:       fmt.Errorf("error parsing regexp: missing closing ): `(foobar|raboff`"),
		}, {
			name:      "regex match a list of strings input against a string condition in roles field",
			condition: `regex match roles foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondRegexMatchListStrInput",
				"field_name":     "roles",
			},
		}, {
			name:      "failed regex match a list of strings input against a string condition in roles field",
			condition: `regex match roles foobar|raboff)`,
			shouldErr: true,
			err:       fmt.Errorf("error parsing regexp: unexpected ): `foobar|raboff)`"),
		}, {
			name:      "always match a list of strings input against a list of strings in roles field",
			condition: `always match roles barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondAlwaysMatchListStrInput",
				"field_name":     "roles",
			},
		}, {
			name:      "always match a list of strings input against a string condition in roles field",
			condition: `always match roles foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondAlwaysMatchListStrInput",
				"field_name":     "roles",
			},
		}, {
			name:      "exact match an input string against a list of strings in email field",
			condition: `exact match email barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondExactMatchStrInput",
				"field_name":     "email",
			},
		}, {
			name:      "default match an input string against a list of strings in email field",
			condition: ` match email barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondExactMatchStrInput",
				"field_name":     "email",
			},
		}, {
			name:      "exact match an input string against a string condition in email field",
			condition: `exact match email foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondExactMatchStrInput",
				"field_name":     "email",
			},
		}, {
			name:      "default match an input string against a string condition in email field",
			condition: ` match email foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondExactMatchStrInput",
				"field_name":     "email",
			},
		}, {
			name:      "partial match an input string against a list of strings in email field",
			condition: `partial match email barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondPartialMatchStrInput",
				"field_name":     "email",
			},
		}, {
			name:      "partial match an input string against a string condition in email field",
			condition: `partial match email foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondPartialMatchStrInput",
				"field_name":     "email",
			},
		}, {
			name:      "prefix match an input string against a list of strings in email field",
			condition: `prefix match email barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondPrefixMatchStrInput",
				"field_name":     "email",
			},
		}, {
			name:      "prefix match an input string against a string condition in email field",
			condition: `prefix match email foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondPrefixMatchStrInput",
				"field_name":     "email",
			},
		}, {
			name:      "suffix match an input string against a list of strings in email field",
			condition: `suffix match email barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondSuffixMatchStrInput",
				"field_name":     "email",
			},
		}, {
			name:      "suffix match an input string against a string condition in email field",
			condition: `suffix match email foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondSuffixMatchStrInput",
				"field_name":     "email",
			},
		}, {
			name:      "regex match an input string against a list of strings in email field",
			condition: `regex match email barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondRegexMatchStrInput",
				"field_name":     "email",
			},
		}, {
			name:      "failed regex match an input string against a list of strings in email field",
			condition: `regex match email barfoo (foobar|raboff`,
			shouldErr: true,
			err:       fmt.Errorf("error parsing regexp: missing closing ): `(foobar|raboff`"),
		}, {
			name:      "regex match an input string against a string condition in email field",
			condition: `regex match email foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondRegexMatchStrInput",
				"field_name":     "email",
			},
		}, {
			name:      "failed regex match an input string against a string condition in email field",
			condition: `regex match email foobar|raboff)`,
			shouldErr: true,
			err:       fmt.Errorf("error parsing regexp: unexpected ): `foobar|raboff)`"),
		}, {
			name:      "always match an input string against a list of strings in email field",
			condition: `always match email barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondAlwaysMatchStrInput",
				"field_name":     "email",
			},
		}, {
			name:      "always match an input string against a string condition in email field",
			condition: `always match email foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondAlwaysMatchStrInput",
				"field_name":     "email",
			},
		}, {
			name:      "exact match an input string against a list of strings in origin field",
			condition: `exact match origin barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondExactMatchStrInput",
				"field_name":     "origin",
			},
		}, {
			name:      "default match an input string against a list of strings in origin field",
			condition: ` match origin barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondExactMatchStrInput",
				"field_name":     "origin",
			},
		}, {
			name:      "exact match an input string against a string condition in origin field",
			condition: `exact match origin foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondExactMatchStrInput",
				"field_name":     "origin",
			},
		}, {
			name:      "default match an input string against a string condition in origin field",
			condition: ` match origin foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondExactMatchStrInput",
				"field_name":     "origin",
			},
		}, {
			name:      "partial match an input string against a list of strings in origin field",
			condition: `partial match origin barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondPartialMatchStrInput",
				"field_name":     "origin",
			},
		}, {
			name:      "partial match an input string against a string condition in origin field",
			condition: `partial match origin foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondPartialMatchStrInput",
				"field_name":     "origin",
			},
		}, {
			name:      "prefix match an input string against a list of strings in origin field",
			condition: `prefix match origin barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondPrefixMatchStrInput",
				"field_name":     "origin",
			},
		}, {
			name:      "prefix match an input string against a string condition in origin field",
			condition: `prefix match origin foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondPrefixMatchStrInput",
				"field_name":     "origin",
			},
		}, {
			name:      "suffix match an input string against a list of strings in origin field",
			condition: `suffix match origin barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondSuffixMatchStrInput",
				"field_name":     "origin",
			},
		}, {
			name:      "suffix match an input string against a string condition in origin field",
			condition: `suffix match origin foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondSuffixMatchStrInput",
				"field_name":     "origin",
			},
		}, {
			name:      "regex match an input string against a list of strings in origin field",
			condition: `regex match origin barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondRegexMatchStrInput",
				"field_name":     "origin",
			},
		}, {
			name:      "failed regex match an input string against a list of strings in origin field",
			condition: `regex match origin barfoo (foobar|raboff`,
			shouldErr: true,
			err:       fmt.Errorf("error parsing regexp: missing closing ): `(foobar|raboff`"),
		}, {
			name:      "regex match an input string against a string condition in origin field",
			condition: `regex match origin foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondRegexMatchStrInput",
				"field_name":     "origin",
			},
		}, {
			name:      "failed regex match an input string against a string condition in origin field",
			condition: `regex match origin foobar|raboff)`,
			shouldErr: true,
			err:       fmt.Errorf("error parsing regexp: unexpected ): `foobar|raboff)`"),
		}, {
			name:      "always match an input string against a list of strings in origin field",
			condition: `always match origin barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondAlwaysMatchStrInput",
				"field_name":     "origin",
			},
		}, {
			name:      "always match an input string against a string condition in origin field",
			condition: `always match origin foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondAlwaysMatchStrInput",
				"field_name":     "origin",
			},
		}, {
			name:      "exact match an input string against a list of strings in name field",
			condition: `exact match name barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondExactMatchStrInput",
				"field_name":     "name",
			},
		}, {
			name:      "default match an input string against a list of strings in name field",
			condition: ` match name barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondExactMatchStrInput",
				"field_name":     "name",
			},
		}, {
			name:      "exact match an input string against a string condition in name field",
			condition: `exact match name foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondExactMatchStrInput",
				"field_name":     "name",
			},
		}, {
			name:      "default match an input string against a string condition in name field",
			condition: ` match name foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondExactMatchStrInput",
				"field_name":     "name",
			},
		}, {
			name:      "partial match an input string against a list of strings in name field",
			condition: `partial match name barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondPartialMatchStrInput",
				"field_name":     "name",
			},
		}, {
			name:      "partial match an input string against a string condition in name field",
			condition: `partial match name foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondPartialMatchStrInput",
				"field_name":     "name",
			},
		}, {
			name:      "prefix match an input string against a list of strings in name field",
			condition: `prefix match name barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondPrefixMatchStrInput",
				"field_name":     "name",
			},
		}, {
			name:      "prefix match an input string against a string condition in name field",
			condition: `prefix match name foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondPrefixMatchStrInput",
				"field_name":     "name",
			},
		}, {
			name:      "suffix match an input string against a list of strings in name field",
			condition: `suffix match name barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondSuffixMatchStrInput",
				"field_name":     "name",
			},
		}, {
			name:      "suffix match an input string against a string condition in name field",
			condition: `suffix match name foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondSuffixMatchStrInput",
				"field_name":     "name",
			},
		}, {
			name:      "regex match an input string against a list of strings in name field",
			condition: `regex match name barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondRegexMatchStrInput",
				"field_name":     "name",
			},
		}, {
			name:      "failed regex match an input string against a list of strings in name field",
			condition: `regex match name barfoo (foobar|raboff`,
			shouldErr: true,
			err:       fmt.Errorf("error parsing regexp: missing closing ): `(foobar|raboff`"),
		}, {
			name:      "regex match an input string against a string condition in name field",
			condition: `regex match name foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondRegexMatchStrInput",
				"field_name":     "name",
			},
		}, {
			name:      "failed regex match an input string against a string condition in name field",
			condition: `regex match name foobar|raboff)`,
			shouldErr: true,
			err:       fmt.Errorf("error parsing regexp: unexpected ): `foobar|raboff)`"),
		}, {
			name:      "always match an input string against a list of strings in name field",
			condition: `always match name barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondAlwaysMatchStrInput",
				"field_name":     "name",
			},
		}, {
			name:      "always match an input string against a string condition in name field",
			condition: `always match name foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondAlwaysMatchStrInput",
				"field_name":     "name",
			},
		}, {
			name:      "exact match a list of strings input against a list of strings in aud field",
			condition: `exact match aud barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondExactMatchListStrInput",
				"field_name":     "aud",
			},
		}, {
			name:      "default match a list of strings input against a list of strings in aud field",
			condition: ` match aud barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondExactMatchListStrInput",
				"field_name":     "aud",
			},
		}, {
			name:      "exact match a list of strings input against a string condition in aud field",
			condition: `exact match aud foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondExactMatchListStrInput",
				"field_name":     "aud",
			},
		}, {
			name:      "default match a list of strings input against a string condition in aud field",
			condition: ` match aud foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondExactMatchListStrInput",
				"field_name":     "aud",
			},
		}, {
			name:      "partial match a list of strings input against a list of strings in aud field",
			condition: `partial match aud barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondPartialMatchListStrInput",
				"field_name":     "aud",
			},
		}, {
			name:      "partial match a list of strings input against a string condition in aud field",
			condition: `partial match aud foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondPartialMatchListStrInput",
				"field_name":     "aud",
			},
		}, {
			name:      "prefix match a list of strings input against a list of strings in aud field",
			condition: `prefix match aud barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondPrefixMatchListStrInput",
				"field_name":     "aud",
			},
		}, {
			name:      "prefix match a list of strings input against a string condition in aud field",
			condition: `prefix match aud foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondPrefixMatchListStrInput",
				"field_name":     "aud",
			},
		}, {
			name:      "suffix match a list of strings input against a list of strings in aud field",
			condition: `suffix match aud barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondSuffixMatchListStrInput",
				"field_name":     "aud",
			},
		}, {
			name:      "suffix match a list of strings input against a string condition in aud field",
			condition: `suffix match aud foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondSuffixMatchListStrInput",
				"field_name":     "aud",
			},
		}, {
			name:      "regex match a list of strings input against a list of strings in aud field",
			condition: `regex match aud barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondRegexMatchListStrInput",
				"field_name":     "aud",
			},
		}, {
			name:      "failed regex match a list of strings input against a list of strings in aud field",
			condition: `regex match aud barfoo (foobar|raboff`,
			shouldErr: true,
			err:       fmt.Errorf("error parsing regexp: missing closing ): `(foobar|raboff`"),
		}, {
			name:      "regex match a list of strings input against a string condition in aud field",
			condition: `regex match aud foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondRegexMatchListStrInput",
				"field_name":     "aud",
			},
		}, {
			name:      "failed regex match a list of strings input against a string condition in aud field",
			condition: `regex match aud foobar|raboff)`,
			shouldErr: true,
			err:       fmt.Errorf("error parsing regexp: unexpected ): `foobar|raboff)`"),
		}, {
			name:      "always match a list of strings input against a list of strings in aud field",
			condition: `always match aud barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondAlwaysMatchListStrInput",
				"field_name":     "aud",
			},
		}, {
			name:      "always match a list of strings input against a string condition in aud field",
			condition: `always match aud foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondAlwaysMatchListStrInput",
				"field_name":     "aud",
			},
		}, {
			name:      "exact match a list of strings input against a list of strings in scopes field",
			condition: `exact match scopes barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondExactMatchListStrInput",
				"field_name":     "scopes",
			},
		}, {
			name:      "default match a list of strings input against a list of strings in scopes field",
			condition: ` match scopes barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondExactMatchListStrInput",
				"field_name":     "scopes",
			},
		}, {
			name:      "exact match a list of strings input against a string condition in scopes field",
			condition: `exact match scopes foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondExactMatchListStrInput",
				"field_name":     "scopes",
			},
		}, {
			name:      "default match a list of strings input against a string condition in scopes field",
			condition: ` match scopes foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondExactMatchListStrInput",
				"field_name":     "scopes",
			},
		}, {
			name:      "partial match a list of strings input against a list of strings in scopes field",
			condition: `partial match scopes barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondPartialMatchListStrInput",
				"field_name":     "scopes",
			},
		}, {
			name:      "partial match a list of strings input against a string condition in scopes field",
			condition: `partial match scopes foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondPartialMatchListStrInput",
				"field_name":     "scopes",
			},
		}, {
			name:      "prefix match a list of strings input against a list of strings in scopes field",
			condition: `prefix match scopes barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondPrefixMatchListStrInput",
				"field_name":     "scopes",
			},
		}, {
			name:      "prefix match a list of strings input against a string condition in scopes field",
			condition: `prefix match scopes foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondPrefixMatchListStrInput",
				"field_name":     "scopes",
			},
		}, {
			name:      "suffix match a list of strings input against a list of strings in scopes field",
			condition: `suffix match scopes barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondSuffixMatchListStrInput",
				"field_name":     "scopes",
			},
		}, {
			name:      "suffix match a list of strings input against a string condition in scopes field",
			condition: `suffix match scopes foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondSuffixMatchListStrInput",
				"field_name":     "scopes",
			},
		}, {
			name:      "regex match a list of strings input against a list of strings in scopes field",
			condition: `regex match scopes barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondRegexMatchListStrInput",
				"field_name":     "scopes",
			},
		}, {
			name:      "failed regex match a list of strings input against a list of strings in scopes field",
			condition: `regex match scopes barfoo (foobar|raboff`,
			shouldErr: true,
			err:       fmt.Errorf("error parsing regexp: missing closing ): `(foobar|raboff`"),
		}, {
			name:      "regex match a list of strings input against a string condition in scopes field",
			condition: `regex match scopes foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondRegexMatchListStrInput",
				"field_name":     "scopes",
			},
		}, {
			name:      "failed regex match a list of strings input against a string condition in scopes field",
			condition: `regex match scopes foobar|raboff)`,
			shouldErr: true,
			err:       fmt.Errorf("error parsing regexp: unexpected ): `foobar|raboff)`"),
		}, {
			name:      "always match a list of strings input against a list of strings in scopes field",
			condition: `always match scopes barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondAlwaysMatchListStrInput",
				"field_name":     "scopes",
			},
		}, {
			name:      "always match a list of strings input against a string condition in scopes field",
			condition: `always match scopes foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondAlwaysMatchListStrInput",
				"field_name":     "scopes",
			},
		}, {
			name:      "exact match a list of strings input against a list of strings in org field",
			condition: `exact match org barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondExactMatchListStrInput",
				"field_name":     "org",
			},
		}, {
			name:      "default match a list of strings input against a list of strings in org field",
			condition: ` match org barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondExactMatchListStrInput",
				"field_name":     "org",
			},
		}, {
			name:      "exact match a list of strings input against a string condition in org field",
			condition: `exact match org foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondExactMatchListStrInput",
				"field_name":     "org",
			},
		}, {
			name:      "default match a list of strings input against a string condition in org field",
			condition: ` match org foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondExactMatchListStrInput",
				"field_name":     "org",
			},
		}, {
			name:      "partial match a list of strings input against a list of strings in org field",
			condition: `partial match org barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondPartialMatchListStrInput",
				"field_name":     "org",
			},
		}, {
			name:      "partial match a list of strings input against a string condition in org field",
			condition: `partial match org foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondPartialMatchListStrInput",
				"field_name":     "org",
			},
		}, {
			name:      "prefix match a list of strings input against a list of strings in org field",
			condition: `prefix match org barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondPrefixMatchListStrInput",
				"field_name":     "org",
			},
		}, {
			name:      "prefix match a list of strings input against a string condition in org field",
			condition: `prefix match org foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondPrefixMatchListStrInput",
				"field_name":     "org",
			},
		}, {
			name:      "suffix match a list of strings input against a list of strings in org field",
			condition: `suffix match org barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondSuffixMatchListStrInput",
				"field_name":     "org",
			},
		}, {
			name:      "suffix match a list of strings input against a string condition in org field",
			condition: `suffix match org foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondSuffixMatchListStrInput",
				"field_name":     "org",
			},
		}, {
			name:      "regex match a list of strings input against a list of strings in org field",
			condition: `regex match org barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondRegexMatchListStrInput",
				"field_name":     "org",
			},
		}, {
			name:      "failed regex match a list of strings input against a list of strings in org field",
			condition: `regex match org barfoo (foobar|raboff`,
			shouldErr: true,
			err:       fmt.Errorf("error parsing regexp: missing closing ): `(foobar|raboff`"),
		}, {
			name:      "regex match a list of strings input against a string condition in org field",
			condition: `regex match org foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondRegexMatchListStrInput",
				"field_name":     "org",
			},
		}, {
			name:      "failed regex match a list of strings input against a string condition in org field",
			condition: `regex match org foobar|raboff)`,
			shouldErr: true,
			err:       fmt.Errorf("error parsing regexp: unexpected ): `foobar|raboff)`"),
		}, {
			name:      "always match a list of strings input against a list of strings in org field",
			condition: `always match org barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondAlwaysMatchListStrInput",
				"field_name":     "org",
			},
		}, {
			name:      "always match a list of strings input against a string condition in org field",
			condition: `always match org foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondAlwaysMatchListStrInput",
				"field_name":     "org",
			},
		}, {
			name:      "exact match an input string against a list of strings in jti field",
			condition: `exact match jti barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondExactMatchStrInput",
				"field_name":     "jti",
			},
		}, {
			name:      "default match an input string against a list of strings in jti field",
			condition: ` match jti barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondExactMatchStrInput",
				"field_name":     "jti",
			},
		}, {
			name:      "exact match an input string against a string condition in jti field",
			condition: `exact match jti foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondExactMatchStrInput",
				"field_name":     "jti",
			},
		}, {
			name:      "default match an input string against a string condition in jti field",
			condition: ` match jti foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondExactMatchStrInput",
				"field_name":     "jti",
			},
		}, {
			name:      "partial match an input string against a list of strings in jti field",
			condition: `partial match jti barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondPartialMatchStrInput",
				"field_name":     "jti",
			},
		}, {
			name:      "partial match an input string against a string condition in jti field",
			condition: `partial match jti foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondPartialMatchStrInput",
				"field_name":     "jti",
			},
		}, {
			name:      "prefix match an input string against a list of strings in jti field",
			condition: `prefix match jti barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondPrefixMatchStrInput",
				"field_name":     "jti",
			},
		}, {
			name:      "prefix match an input string against a string condition in jti field",
			condition: `prefix match jti foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondPrefixMatchStrInput",
				"field_name":     "jti",
			},
		}, {
			name:      "suffix match an input string against a list of strings in jti field",
			condition: `suffix match jti barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondSuffixMatchStrInput",
				"field_name":     "jti",
			},
		}, {
			name:      "suffix match an input string against a string condition in jti field",
			condition: `suffix match jti foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondSuffixMatchStrInput",
				"field_name":     "jti",
			},
		}, {
			name:      "regex match an input string against a list of strings in jti field",
			condition: `regex match jti barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondRegexMatchStrInput",
				"field_name":     "jti",
			},
		}, {
			name:      "failed regex match an input string against a list of strings in jti field",
			condition: `regex match jti barfoo (foobar|raboff`,
			shouldErr: true,
			err:       fmt.Errorf("error parsing regexp: missing closing ): `(foobar|raboff`"),
		}, {
			name:      "regex match an input string against a string condition in jti field",
			condition: `regex match jti foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondRegexMatchStrInput",
				"field_name":     "jti",
			},
		}, {
			name:      "failed regex match an input string against a string condition in jti field",
			condition: `regex match jti foobar|raboff)`,
			shouldErr: true,
			err:       fmt.Errorf("error parsing regexp: unexpected ): `foobar|raboff)`"),
		}, {
			name:      "always match an input string against a list of strings in jti field",
			condition: `always match jti barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondAlwaysMatchStrInput",
				"field_name":     "jti",
			},
		}, {
			name:      "always match an input string against a string condition in jti field",
			condition: `always match jti foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondAlwaysMatchStrInput",
				"field_name":     "jti",
			},
		}, {
			name:      "exact match an input string against a list of strings in iss field",
			condition: `exact match iss barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondExactMatchStrInput",
				"field_name":     "iss",
			},
		}, {
			name:      "default match an input string against a list of strings in iss field",
			condition: ` match iss barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondExactMatchStrInput",
				"field_name":     "iss",
			},
		}, {
			name:      "exact match an input string against a string condition in iss field",
			condition: `exact match iss foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondExactMatchStrInput",
				"field_name":     "iss",
			},
		}, {
			name:      "default match an input string against a string condition in iss field",
			condition: ` match iss foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondExactMatchStrInput",
				"field_name":     "iss",
			},
		}, {
			name:      "partial match an input string against a list of strings in iss field",
			condition: `partial match iss barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondPartialMatchStrInput",
				"field_name":     "iss",
			},
		}, {
			name:      "partial match an input string against a string condition in iss field",
			condition: `partial match iss foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondPartialMatchStrInput",
				"field_name":     "iss",
			},
		}, {
			name:      "prefix match an input string against a list of strings in iss field",
			condition: `prefix match iss barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondPrefixMatchStrInput",
				"field_name":     "iss",
			},
		}, {
			name:      "prefix match an input string against a string condition in iss field",
			condition: `prefix match iss foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondPrefixMatchStrInput",
				"field_name":     "iss",
			},
		}, {
			name:      "suffix match an input string against a list of strings in iss field",
			condition: `suffix match iss barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondSuffixMatchStrInput",
				"field_name":     "iss",
			},
		}, {
			name:      "suffix match an input string against a string condition in iss field",
			condition: `suffix match iss foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondSuffixMatchStrInput",
				"field_name":     "iss",
			},
		}, {
			name:      "regex match an input string against a list of strings in iss field",
			condition: `regex match iss barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondRegexMatchStrInput",
				"field_name":     "iss",
			},
		}, {
			name:      "failed regex match an input string against a list of strings in iss field",
			condition: `regex match iss barfoo (foobar|raboff`,
			shouldErr: true,
			err:       fmt.Errorf("error parsing regexp: missing closing ): `(foobar|raboff`"),
		}, {
			name:      "regex match an input string against a string condition in iss field",
			condition: `regex match iss foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondRegexMatchStrInput",
				"field_name":     "iss",
			},
		}, {
			name:      "failed regex match an input string against a string condition in iss field",
			condition: `regex match iss foobar|raboff)`,
			shouldErr: true,
			err:       fmt.Errorf("error parsing regexp: unexpected ): `foobar|raboff)`"),
		}, {
			name:      "always match an input string against a list of strings in iss field",
			condition: `always match iss barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondAlwaysMatchStrInput",
				"field_name":     "iss",
			},
		}, {
			name:      "always match an input string against a string condition in iss field",
			condition: `always match iss foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondAlwaysMatchStrInput",
				"field_name":     "iss",
			},
		}, {
			name:      "exact match an input string against a list of strings in sub field",
			condition: `exact match sub barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondExactMatchStrInput",
				"field_name":     "sub",
			},
		}, {
			name:      "default match an input string against a list of strings in sub field",
			condition: ` match sub barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondExactMatchStrInput",
				"field_name":     "sub",
			},
		}, {
			name:      "exact match an input string against a string condition in sub field",
			condition: `exact match sub foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondExactMatchStrInput",
				"field_name":     "sub",
			},
		}, {
			name:      "default match an input string against a string condition in sub field",
			condition: ` match sub foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondExactMatchStrInput",
				"field_name":     "sub",
			},
		}, {
			name:      "partial match an input string against a list of strings in sub field",
			condition: `partial match sub barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondPartialMatchStrInput",
				"field_name":     "sub",
			},
		}, {
			name:      "partial match an input string against a string condition in sub field",
			condition: `partial match sub foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondPartialMatchStrInput",
				"field_name":     "sub",
			},
		}, {
			name:      "prefix match an input string against a list of strings in sub field",
			condition: `prefix match sub barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondPrefixMatchStrInput",
				"field_name":     "sub",
			},
		}, {
			name:      "prefix match an input string against a string condition in sub field",
			condition: `prefix match sub foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondPrefixMatchStrInput",
				"field_name":     "sub",
			},
		}, {
			name:      "suffix match an input string against a list of strings in sub field",
			condition: `suffix match sub barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondSuffixMatchStrInput",
				"field_name":     "sub",
			},
		}, {
			name:      "suffix match an input string against a string condition in sub field",
			condition: `suffix match sub foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondSuffixMatchStrInput",
				"field_name":     "sub",
			},
		}, {
			name:      "regex match an input string against a list of strings in sub field",
			condition: `regex match sub barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondRegexMatchStrInput",
				"field_name":     "sub",
			},
		}, {
			name:      "failed regex match an input string against a list of strings in sub field",
			condition: `regex match sub barfoo (foobar|raboff`,
			shouldErr: true,
			err:       fmt.Errorf("error parsing regexp: missing closing ): `(foobar|raboff`"),
		}, {
			name:      "regex match an input string against a string condition in sub field",
			condition: `regex match sub foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondRegexMatchStrInput",
				"field_name":     "sub",
			},
		}, {
			name:      "failed regex match an input string against a string condition in sub field",
			condition: `regex match sub foobar|raboff)`,
			shouldErr: true,
			err:       fmt.Errorf("error parsing regexp: unexpected ): `foobar|raboff)`"),
		}, {
			name:      "always match an input string against a list of strings in sub field",
			condition: `always match sub barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondAlwaysMatchStrInput",
				"field_name":     "sub",
			},
		}, {
			name:      "always match an input string against a string condition in sub field",
			condition: `always match sub foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondAlwaysMatchStrInput",
				"field_name":     "sub",
			},
		}, {
			name:      "exact match an input string against a list of strings in addr field",
			condition: `exact match addr barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondExactMatchStrInput",
				"field_name":     "addr",
			},
		}, {
			name:      "default match an input string against a list of strings in addr field",
			condition: ` match addr barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondExactMatchStrInput",
				"field_name":     "addr",
			},
		}, {
			name:      "exact match an input string against a string condition in addr field",
			condition: `exact match addr foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondExactMatchStrInput",
				"field_name":     "addr",
			},
		}, {
			name:      "default match an input string against a string condition in addr field",
			condition: ` match addr foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondExactMatchStrInput",
				"field_name":     "addr",
			},
		}, {
			name:      "partial match an input string against a list of strings in addr field",
			condition: `partial match addr barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondPartialMatchStrInput",
				"field_name":     "addr",
			},
		}, {
			name:      "partial match an input string against a string condition in addr field",
			condition: `partial match addr foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondPartialMatchStrInput",
				"field_name":     "addr",
			},
		}, {
			name:      "prefix match an input string against a list of strings in addr field",
			condition: `prefix match addr barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondPrefixMatchStrInput",
				"field_name":     "addr",
			},
		}, {
			name:      "prefix match an input string against a string condition in addr field",
			condition: `prefix match addr foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondPrefixMatchStrInput",
				"field_name":     "addr",
			},
		}, {
			name:      "suffix match an input string against a list of strings in addr field",
			condition: `suffix match addr barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondSuffixMatchStrInput",
				"field_name":     "addr",
			},
		}, {
			name:      "suffix match an input string against a string condition in addr field",
			condition: `suffix match addr foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondSuffixMatchStrInput",
				"field_name":     "addr",
			},
		}, {
			name:      "regex match an input string against a list of strings in addr field",
			condition: `regex match addr barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondRegexMatchStrInput",
				"field_name":     "addr",
			},
		}, {
			name:      "failed regex match an input string against a list of strings in addr field",
			condition: `regex match addr barfoo (foobar|raboff`,
			shouldErr: true,
			err:       fmt.Errorf("error parsing regexp: missing closing ): `(foobar|raboff`"),
		}, {
			name:      "regex match an input string against a string condition in addr field",
			condition: `regex match addr foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondRegexMatchStrInput",
				"field_name":     "addr",
			},
		}, {
			name:      "failed regex match an input string against a string condition in addr field",
			condition: `regex match addr foobar|raboff)`,
			shouldErr: true,
			err:       fmt.Errorf("error parsing regexp: unexpected ): `foobar|raboff)`"),
		}, {
			name:      "always match an input string against a list of strings in addr field",
			condition: `always match addr barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleListStrCondAlwaysMatchStrInput",
				"field_name":     "addr",
			},
		}, {
			name:      "always match an input string against a string condition in addr field",
			condition: `always match addr foobar`,
			want: map[string]interface{}{
				"condition_type": "*acl.ruleStrCondAlwaysMatchStrInput",
				"field_name":     "addr",
			},
		}, {
			name:      "invalid condition syntax match not found",
			condition: `exact`,
			shouldErr: true,
			err:       fmt.Errorf("invalid condition syntax, match not found: exact"),
		}, {
			name:      "invalid condition syntax field name not found",
			condition: `exact match`,
			shouldErr: true,
			err:       fmt.Errorf("invalid condition syntax, field name not found: exact match"),
		}, {
			name:      "invalid condition syntax not matching field values",
			condition: `exact match roles`,
			shouldErr: true,
			err:       fmt.Errorf("invalid condition syntax, not matching field values: exact match roles"),
		}, {
			name:      "invalid condition syntax use of reserved keyword",
			condition: `exact match partial`,
			shouldErr: true,
			err:       fmt.Errorf("invalid condition syntax, use of reserved keyword: exact match partial"),
		}, {
			name:      "invalid condition syntax unsupported field",
			condition: `exact match bootstrap yes`,
			shouldErr: true,
			err:       fmt.Errorf("invalid condition syntax, unsupported field: bootstrap, condition: exact match bootstrap yes"),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf(tc.name)
			t.Logf(tc.condition)
			var cond aclRuleCondition
			parsedAclRuleCondition, err := newAclRuleCondition(strings.Split(tc.condition, " "))
			if tests.EvalErr(t, err, tc.condition, tc.shouldErr, tc.err) {
				return
			}
			cond = parsedAclRuleCondition
			condConfig := cond.getConfig(context.Background())
			got := make(map[string]interface{})
			got["field_name"] = condConfig.field
			// got["condition_type"] = condConfig.conditionType
			got["condition_type"] = reflect.TypeOf(cond).String()
			tests.EvalObjects(t, "output", tc.want, got)
		})
	}
}
