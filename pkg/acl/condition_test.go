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
	"github.com/greenpau/caddy-auth-jwt/pkg/tests"
	"strings"
	"testing"
)

func TestAclRuleConditions(t *testing.T) {
	var testcases = []struct {
		name      string
		condition string
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name:      "match roles field a list of strings input against a list of strings match any with exact match",
			condition: `roles barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondExactMatchListStrInput",
				"field_name":     "roles",
			},
		},
		{
			name:      "match aud field a list of strings input against a list of strings match any with exact match",
			condition: `aud barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondExactMatchListStrInput",
				"field_name":     "aud",
			},
		},
		{
			name:      "match scopes field a list of strings input against a list of strings match any with exact match",
			condition: `scopes barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondExactMatchListStrInput",
				"field_name":     "scopes",
			},
		},
		{
			name:      "match org field a list of strings input against a list of strings match any with exact match",
			condition: `org barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondExactMatchListStrInput",
				"field_name":     "org",
			},
		},
		{
			name:      "match roles field a list of strings input against a list of strings match any with partial match",
			condition: `roles barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondPartialMatchListStrInput",
				"field_name":     "roles",
			},
		},
		{
			name:      "match aud field a list of strings input against a list of strings match any with partial match",
			condition: `aud barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondPartialMatchListStrInput",
				"field_name":     "aud",
			},
		},
		{
			name:      "match scopes field a list of strings input against a list of strings match any with partial match",
			condition: `scopes barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondPartialMatchListStrInput",
				"field_name":     "scopes",
			},
		},
		{
			name:      "match org field a list of strings input against a list of strings match any with partial match",
			condition: `org barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondPartialMatchListStrInput",
				"field_name":     "org",
			},
		},
		{
			name:      "match roles field a list of strings input against a list of strings match any with prefix match",
			condition: `roles barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondPrefixMatchListStrInput",
				"field_name":     "roles",
			},
		},
		{
			name:      "match aud field a list of strings input against a list of strings match any with prefix match",
			condition: `aud barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondPrefixMatchListStrInput",
				"field_name":     "aud",
			},
		},
		{
			name:      "match scopes field a list of strings input against a list of strings match any with prefix match",
			condition: `scopes barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondPrefixMatchListStrInput",
				"field_name":     "scopes",
			},
		},
		{
			name:      "match org field a list of strings input against a list of strings match any with prefix match",
			condition: `org barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondPrefixMatchListStrInput",
				"field_name":     "org",
			},
		},
		{
			name:      "match roles field a list of strings input against a list of strings match any with suffix match",
			condition: `roles barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondSuffixMatchListStrInput",
				"field_name":     "roles",
			},
		},
		{
			name:      "match aud field a list of strings input against a list of strings match any with suffix match",
			condition: `aud barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondSuffixMatchListStrInput",
				"field_name":     "aud",
			},
		},
		{
			name:      "match scopes field a list of strings input against a list of strings match any with suffix match",
			condition: `scopes barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondSuffixMatchListStrInput",
				"field_name":     "scopes",
			},
		},
		{
			name:      "match org field a list of strings input against a list of strings match any with suffix match",
			condition: `org barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondSuffixMatchListStrInput",
				"field_name":     "org",
			},
		},
		{
			name:      "match roles field a list of strings input against a list of strings match any with regex match",
			condition: `roles barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondRegexMatchListStrInput",
				"field_name":     "roles",
			},
		},
		{
			name:      "match aud field a list of strings input against a list of strings match any with regex match",
			condition: `aud barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondRegexMatchListStrInput",
				"field_name":     "aud",
			},
		},
		{
			name:      "match scopes field a list of strings input against a list of strings match any with regex match",
			condition: `scopes barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondRegexMatchListStrInput",
				"field_name":     "scopes",
			},
		},
		{
			name:      "match org field a list of strings input against a list of strings match any with regex match",
			condition: `org barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondRegexMatchListStrInput",
				"field_name":     "org",
			},
		},
		{
			name:      "match roles field a list of strings input against a list of strings match any with always match",
			condition: `roles barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondAlwaysMatchListStrInput",
				"field_name":     "roles",
			},
		},
		{
			name:      "match aud field a list of strings input against a list of strings match any with always match",
			condition: `aud barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondAlwaysMatchListStrInput",
				"field_name":     "aud",
			},
		},
		{
			name:      "match scopes field a list of strings input against a list of strings match any with always match",
			condition: `scopes barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondAlwaysMatchListStrInput",
				"field_name":     "scopes",
			},
		},
		{
			name:      "match org field a list of strings input against a list of strings match any with always match",
			condition: `org barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondAlwaysMatchListStrInput",
				"field_name":     "org",
			},
		},
		{
			name:      "match email field a list of strings input against a string condition with exact match",
			condition: `email foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondExactMatchListStrInput",
				"field_name":     "email",
			},
		},
		{
			name:      "match origin field a list of strings input against a string condition with exact match",
			condition: `origin foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondExactMatchListStrInput",
				"field_name":     "origin",
			},
		},
		{
			name:      "match name field a list of strings input against a string condition with exact match",
			condition: `name foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondExactMatchListStrInput",
				"field_name":     "name",
			},
		},
		{
			name:      "match jti field a list of strings input against a string condition with exact match",
			condition: `jti foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondExactMatchListStrInput",
				"field_name":     "jti",
			},
		},
		{
			name:      "match iss field a list of strings input against a string condition with exact match",
			condition: `iss foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondExactMatchListStrInput",
				"field_name":     "iss",
			},
		},
		{
			name:      "match sub field a list of strings input against a string condition with exact match",
			condition: `sub foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondExactMatchListStrInput",
				"field_name":     "sub",
			},
		},
		{
			name:      "match addr field a list of strings input against a string condition with exact match",
			condition: `addr foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondExactMatchListStrInput",
				"field_name":     "addr",
			},
		},
		{
			name:      "match email field a list of strings input against a string condition with partial match",
			condition: `email foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondPartialMatchListStrInput",
				"field_name":     "email",
			},
		},
		{
			name:      "match origin field a list of strings input against a string condition with partial match",
			condition: `origin foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondPartialMatchListStrInput",
				"field_name":     "origin",
			},
		},
		{
			name:      "match name field a list of strings input against a string condition with partial match",
			condition: `name foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondPartialMatchListStrInput",
				"field_name":     "name",
			},
		},
		{
			name:      "match jti field a list of strings input against a string condition with partial match",
			condition: `jti foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondPartialMatchListStrInput",
				"field_name":     "jti",
			},
		},
		{
			name:      "match iss field a list of strings input against a string condition with partial match",
			condition: `iss foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondPartialMatchListStrInput",
				"field_name":     "iss",
			},
		},
		{
			name:      "match sub field a list of strings input against a string condition with partial match",
			condition: `sub foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondPartialMatchListStrInput",
				"field_name":     "sub",
			},
		},
		{
			name:      "match addr field a list of strings input against a string condition with partial match",
			condition: `addr foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondPartialMatchListStrInput",
				"field_name":     "addr",
			},
		},
		{
			name:      "match email field a list of strings input against a string condition with prefix match",
			condition: `email foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondPrefixMatchListStrInput",
				"field_name":     "email",
			},
		},
		{
			name:      "match origin field a list of strings input against a string condition with prefix match",
			condition: `origin foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondPrefixMatchListStrInput",
				"field_name":     "origin",
			},
		},
		{
			name:      "match name field a list of strings input against a string condition with prefix match",
			condition: `name foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondPrefixMatchListStrInput",
				"field_name":     "name",
			},
		},
		{
			name:      "match jti field a list of strings input against a string condition with prefix match",
			condition: `jti foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondPrefixMatchListStrInput",
				"field_name":     "jti",
			},
		},
		{
			name:      "match iss field a list of strings input against a string condition with prefix match",
			condition: `iss foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondPrefixMatchListStrInput",
				"field_name":     "iss",
			},
		},
		{
			name:      "match sub field a list of strings input against a string condition with prefix match",
			condition: `sub foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondPrefixMatchListStrInput",
				"field_name":     "sub",
			},
		},
		{
			name:      "match addr field a list of strings input against a string condition with prefix match",
			condition: `addr foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondPrefixMatchListStrInput",
				"field_name":     "addr",
			},
		},
		{
			name:      "match email field a list of strings input against a string condition with suffix match",
			condition: `email foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondSuffixMatchListStrInput",
				"field_name":     "email",
			},
		},
		{
			name:      "match origin field a list of strings input against a string condition with suffix match",
			condition: `origin foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondSuffixMatchListStrInput",
				"field_name":     "origin",
			},
		},
		{
			name:      "match name field a list of strings input against a string condition with suffix match",
			condition: `name foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondSuffixMatchListStrInput",
				"field_name":     "name",
			},
		},
		{
			name:      "match jti field a list of strings input against a string condition with suffix match",
			condition: `jti foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondSuffixMatchListStrInput",
				"field_name":     "jti",
			},
		},
		{
			name:      "match iss field a list of strings input against a string condition with suffix match",
			condition: `iss foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondSuffixMatchListStrInput",
				"field_name":     "iss",
			},
		},
		{
			name:      "match sub field a list of strings input against a string condition with suffix match",
			condition: `sub foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondSuffixMatchListStrInput",
				"field_name":     "sub",
			},
		},
		{
			name:      "match addr field a list of strings input against a string condition with suffix match",
			condition: `addr foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondSuffixMatchListStrInput",
				"field_name":     "addr",
			},
		},
		{
			name:      "match email field a list of strings input against a string condition with regex match",
			condition: `email foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondRegexMatchListStrInput",
				"field_name":     "email",
			},
		},
		{
			name:      "match origin field a list of strings input against a string condition with regex match",
			condition: `origin foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondRegexMatchListStrInput",
				"field_name":     "origin",
			},
		},
		{
			name:      "match name field a list of strings input against a string condition with regex match",
			condition: `name foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondRegexMatchListStrInput",
				"field_name":     "name",
			},
		},
		{
			name:      "match jti field a list of strings input against a string condition with regex match",
			condition: `jti foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondRegexMatchListStrInput",
				"field_name":     "jti",
			},
		},
		{
			name:      "match iss field a list of strings input against a string condition with regex match",
			condition: `iss foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondRegexMatchListStrInput",
				"field_name":     "iss",
			},
		},
		{
			name:      "match sub field a list of strings input against a string condition with regex match",
			condition: `sub foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondRegexMatchListStrInput",
				"field_name":     "sub",
			},
		},
		{
			name:      "match addr field a list of strings input against a string condition with regex match",
			condition: `addr foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondRegexMatchListStrInput",
				"field_name":     "addr",
			},
		},
		{
			name:      "match email field a list of strings input against a string condition with always match",
			condition: `email foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondAlwaysMatchListStrInput",
				"field_name":     "email",
			},
		},
		{
			name:      "match origin field a list of strings input against a string condition with always match",
			condition: `origin foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondAlwaysMatchListStrInput",
				"field_name":     "origin",
			},
		},
		{
			name:      "match name field a list of strings input against a string condition with always match",
			condition: `name foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondAlwaysMatchListStrInput",
				"field_name":     "name",
			},
		},
		{
			name:      "match jti field a list of strings input against a string condition with always match",
			condition: `jti foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondAlwaysMatchListStrInput",
				"field_name":     "jti",
			},
		},
		{
			name:      "match iss field a list of strings input against a string condition with always match",
			condition: `iss foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondAlwaysMatchListStrInput",
				"field_name":     "iss",
			},
		},
		{
			name:      "match sub field a list of strings input against a string condition with always match",
			condition: `sub foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondAlwaysMatchListStrInput",
				"field_name":     "sub",
			},
		},
		{
			name:      "match addr field a list of strings input against a string condition with always match",
			condition: `addr foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondAlwaysMatchListStrInput",
				"field_name":     "addr",
			},
		},
		{
			name:      "match roles field an input string against a list of strings match any with exact match",
			condition: `roles barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondExactMatchStrInput",
				"field_name":     "roles",
			},
		},
		{
			name:      "match aud field an input string against a list of strings match any with exact match",
			condition: `aud barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondExactMatchStrInput",
				"field_name":     "aud",
			},
		},
		{
			name:      "match scopes field an input string against a list of strings match any with exact match",
			condition: `scopes barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondExactMatchStrInput",
				"field_name":     "scopes",
			},
		},
		{
			name:      "match org field an input string against a list of strings match any with exact match",
			condition: `org barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondExactMatchStrInput",
				"field_name":     "org",
			},
		},
		{
			name:      "match roles field an input string against a list of strings match any with partial match",
			condition: `roles barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondPartialMatchStrInput",
				"field_name":     "roles",
			},
		},
		{
			name:      "match aud field an input string against a list of strings match any with partial match",
			condition: `aud barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondPartialMatchStrInput",
				"field_name":     "aud",
			},
		},
		{
			name:      "match scopes field an input string against a list of strings match any with partial match",
			condition: `scopes barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondPartialMatchStrInput",
				"field_name":     "scopes",
			},
		},
		{
			name:      "match org field an input string against a list of strings match any with partial match",
			condition: `org barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondPartialMatchStrInput",
				"field_name":     "org",
			},
		},
		{
			name:      "match roles field an input string against a list of strings match any with prefix match",
			condition: `roles barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondPrefixMatchStrInput",
				"field_name":     "roles",
			},
		},
		{
			name:      "match aud field an input string against a list of strings match any with prefix match",
			condition: `aud barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondPrefixMatchStrInput",
				"field_name":     "aud",
			},
		},
		{
			name:      "match scopes field an input string against a list of strings match any with prefix match",
			condition: `scopes barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondPrefixMatchStrInput",
				"field_name":     "scopes",
			},
		},
		{
			name:      "match org field an input string against a list of strings match any with prefix match",
			condition: `org barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondPrefixMatchStrInput",
				"field_name":     "org",
			},
		},
		{
			name:      "match roles field an input string against a list of strings match any with suffix match",
			condition: `roles barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondSuffixMatchStrInput",
				"field_name":     "roles",
			},
		},
		{
			name:      "match aud field an input string against a list of strings match any with suffix match",
			condition: `aud barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondSuffixMatchStrInput",
				"field_name":     "aud",
			},
		},
		{
			name:      "match scopes field an input string against a list of strings match any with suffix match",
			condition: `scopes barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondSuffixMatchStrInput",
				"field_name":     "scopes",
			},
		},
		{
			name:      "match org field an input string against a list of strings match any with suffix match",
			condition: `org barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondSuffixMatchStrInput",
				"field_name":     "org",
			},
		},
		{
			name:      "match roles field an input string against a list of strings match any with regex match",
			condition: `roles barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondRegexMatchStrInput",
				"field_name":     "roles",
			},
		},
		{
			name:      "match aud field an input string against a list of strings match any with regex match",
			condition: `aud barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondRegexMatchStrInput",
				"field_name":     "aud",
			},
		},
		{
			name:      "match scopes field an input string against a list of strings match any with regex match",
			condition: `scopes barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondRegexMatchStrInput",
				"field_name":     "scopes",
			},
		},
		{
			name:      "match org field an input string against a list of strings match any with regex match",
			condition: `org barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondRegexMatchStrInput",
				"field_name":     "org",
			},
		},
		{
			name:      "match roles field an input string against a list of strings match any with always match",
			condition: `roles barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondAlwaysMatchStrInput",
				"field_name":     "roles",
			},
		},
		{
			name:      "match aud field an input string against a list of strings match any with always match",
			condition: `aud barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondAlwaysMatchStrInput",
				"field_name":     "aud",
			},
		},
		{
			name:      "match scopes field an input string against a list of strings match any with always match",
			condition: `scopes barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondAlwaysMatchStrInput",
				"field_name":     "scopes",
			},
		},
		{
			name:      "match org field an input string against a list of strings match any with always match",
			condition: `org barfoo foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleListStrCondAlwaysMatchStrInput",
				"field_name":     "org",
			},
		},
		{
			name:      "match email field an input string against a string condition with exact match",
			condition: `email foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondExactMatchStrInput",
				"field_name":     "email",
			},
		},
		{
			name:      "match origin field an input string against a string condition with exact match",
			condition: `origin foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondExactMatchStrInput",
				"field_name":     "origin",
			},
		},
		{
			name:      "match name field an input string against a string condition with exact match",
			condition: `name foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondExactMatchStrInput",
				"field_name":     "name",
			},
		},
		{
			name:      "match jti field an input string against a string condition with exact match",
			condition: `jti foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondExactMatchStrInput",
				"field_name":     "jti",
			},
		},
		{
			name:      "match iss field an input string against a string condition with exact match",
			condition: `iss foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondExactMatchStrInput",
				"field_name":     "iss",
			},
		},
		{
			name:      "match sub field an input string against a string condition with exact match",
			condition: `sub foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondExactMatchStrInput",
				"field_name":     "sub",
			},
		},
		{
			name:      "match addr field an input string against a string condition with exact match",
			condition: `addr foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondExactMatchStrInput",
				"field_name":     "addr",
			},
		},
		{
			name:      "match email field an input string against a string condition with partial match",
			condition: `email foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondPartialMatchStrInput",
				"field_name":     "email",
			},
		},
		{
			name:      "match origin field an input string against a string condition with partial match",
			condition: `origin foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondPartialMatchStrInput",
				"field_name":     "origin",
			},
		},
		{
			name:      "match name field an input string against a string condition with partial match",
			condition: `name foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondPartialMatchStrInput",
				"field_name":     "name",
			},
		},
		{
			name:      "match jti field an input string against a string condition with partial match",
			condition: `jti foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondPartialMatchStrInput",
				"field_name":     "jti",
			},
		},
		{
			name:      "match iss field an input string against a string condition with partial match",
			condition: `iss foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondPartialMatchStrInput",
				"field_name":     "iss",
			},
		},
		{
			name:      "match sub field an input string against a string condition with partial match",
			condition: `sub foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondPartialMatchStrInput",
				"field_name":     "sub",
			},
		},
		{
			name:      "match addr field an input string against a string condition with partial match",
			condition: `addr foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondPartialMatchStrInput",
				"field_name":     "addr",
			},
		},
		{
			name:      "match email field an input string against a string condition with prefix match",
			condition: `email foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondPrefixMatchStrInput",
				"field_name":     "email",
			},
		},
		{
			name:      "match origin field an input string against a string condition with prefix match",
			condition: `origin foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondPrefixMatchStrInput",
				"field_name":     "origin",
			},
		},
		{
			name:      "match name field an input string against a string condition with prefix match",
			condition: `name foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondPrefixMatchStrInput",
				"field_name":     "name",
			},
		},
		{
			name:      "match jti field an input string against a string condition with prefix match",
			condition: `jti foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondPrefixMatchStrInput",
				"field_name":     "jti",
			},
		},
		{
			name:      "match iss field an input string against a string condition with prefix match",
			condition: `iss foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondPrefixMatchStrInput",
				"field_name":     "iss",
			},
		},
		{
			name:      "match sub field an input string against a string condition with prefix match",
			condition: `sub foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondPrefixMatchStrInput",
				"field_name":     "sub",
			},
		},
		{
			name:      "match addr field an input string against a string condition with prefix match",
			condition: `addr foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondPrefixMatchStrInput",
				"field_name":     "addr",
			},
		},
		{
			name:      "match email field an input string against a string condition with suffix match",
			condition: `email foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondSuffixMatchStrInput",
				"field_name":     "email",
			},
		},
		{
			name:      "match origin field an input string against a string condition with suffix match",
			condition: `origin foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondSuffixMatchStrInput",
				"field_name":     "origin",
			},
		},
		{
			name:      "match name field an input string against a string condition with suffix match",
			condition: `name foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondSuffixMatchStrInput",
				"field_name":     "name",
			},
		},
		{
			name:      "match jti field an input string against a string condition with suffix match",
			condition: `jti foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondSuffixMatchStrInput",
				"field_name":     "jti",
			},
		},
		{
			name:      "match iss field an input string against a string condition with suffix match",
			condition: `iss foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondSuffixMatchStrInput",
				"field_name":     "iss",
			},
		},
		{
			name:      "match sub field an input string against a string condition with suffix match",
			condition: `sub foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondSuffixMatchStrInput",
				"field_name":     "sub",
			},
		},
		{
			name:      "match addr field an input string against a string condition with suffix match",
			condition: `addr foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondSuffixMatchStrInput",
				"field_name":     "addr",
			},
		},
		{
			name:      "match email field an input string against a string condition with regex match",
			condition: `email foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondRegexMatchStrInput",
				"field_name":     "email",
			},
		},
		{
			name:      "match origin field an input string against a string condition with regex match",
			condition: `origin foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondRegexMatchStrInput",
				"field_name":     "origin",
			},
		},
		{
			name:      "match name field an input string against a string condition with regex match",
			condition: `name foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondRegexMatchStrInput",
				"field_name":     "name",
			},
		},
		{
			name:      "match jti field an input string against a string condition with regex match",
			condition: `jti foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondRegexMatchStrInput",
				"field_name":     "jti",
			},
		},
		{
			name:      "match iss field an input string against a string condition with regex match",
			condition: `iss foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondRegexMatchStrInput",
				"field_name":     "iss",
			},
		},
		{
			name:      "match sub field an input string against a string condition with regex match",
			condition: `sub foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondRegexMatchStrInput",
				"field_name":     "sub",
			},
		},
		{
			name:      "match addr field an input string against a string condition with regex match",
			condition: `addr foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondRegexMatchStrInput",
				"field_name":     "addr",
			},
		},
		{
			name:      "match email field an input string against a string condition with always match",
			condition: `email foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondAlwaysMatchStrInput",
				"field_name":     "email",
			},
		},
		{
			name:      "match origin field an input string against a string condition with always match",
			condition: `origin foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondAlwaysMatchStrInput",
				"field_name":     "origin",
			},
		},
		{
			name:      "match name field an input string against a string condition with always match",
			condition: `name foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondAlwaysMatchStrInput",
				"field_name":     "name",
			},
		},
		{
			name:      "match jti field an input string against a string condition with always match",
			condition: `jti foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondAlwaysMatchStrInput",
				"field_name":     "jti",
			},
		},
		{
			name:      "match iss field an input string against a string condition with always match",
			condition: `iss foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondAlwaysMatchStrInput",
				"field_name":     "iss",
			},
		},
		{
			name:      "match sub field an input string against a string condition with always match",
			condition: `sub foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondAlwaysMatchStrInput",
				"field_name":     "sub",
			},
		},
		{
			name:      "match addr field an input string against a string condition with always match",
			condition: `addr foobar`,
			want: map[string]interface{}{
				"condition_type": "ruleStrCondAlwaysMatchStrInput",
				"field_name":     "addr",
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var cond aclRuleCondition
			parsedAclRuleCondition, err := newAclRuleCondition(strings.Split(tc.condition, " "))
			if tests.EvalErr(t, err, tc.condition, tc.shouldErr, tc.err) {
				return
			}
			cond = parsedAclRuleCondition
			condConfig := cond.getConfig(context.Background())
			got := make(map[string]interface{})
			got["condition_type"] = condConfig.field
			got["condition_type"] = condConfig.conditionType
			tests.EvalObjects(t, "output", tc.want, got)
		})
	}
}
