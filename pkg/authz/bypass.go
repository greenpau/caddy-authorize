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

package authz

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

type bypassMatchStrategy int

const (
	bypassMatchUnknown bypassMatchStrategy = 0
	bypassMatchExact   bypassMatchStrategy = 1
	bypassMatchPartial bypassMatchStrategy = 2
	bypassMatchPrefix  bypassMatchStrategy = 3
	bypassMatchSuffix  bypassMatchStrategy = 4
	bypassMatchRegex   bypassMatchStrategy = 5
)

// BypassConfig contains the entry for the authorization bypass.
type BypassConfig struct {
	MatchType string `json:"match_type,omitempty" xml:"match_type,omitempty" yaml:"match_type,omitempty"`
	URI       string `json:"uri,omitempty" xml:"uri,omitempty" yaml:"uri,omitempty"`
	match     bypassMatchStrategy
	regex     *regexp.Regexp
}

// Validate validates BypassConfig
func (b *BypassConfig) Validate() error {
	switch b.MatchType {
	case "exact":
		b.match = bypassMatchExact
	case "partial":
		b.match = bypassMatchPartial
	case "prefix":
		b.match = bypassMatchPrefix
	case "suffix":
		b.match = bypassMatchSuffix
	case "regex":
		b.match = bypassMatchRegex
	case "":
		return fmt.Errorf("undefined bypass match type")
	default:
		return fmt.Errorf("invalid %q bypass match type", b.MatchType)
	}
	b.URI = strings.TrimSpace(b.URI)
	if b.URI == "" {
		return fmt.Errorf("undefined bypass uri")
	}
	if b.regex == nil {
		r, err := regexp.Compile(b.URI)
		if err != nil {
			return err
		}
		b.regex = r
	}
	return nil
}

func (m *Authorizer) bypass(r *http.Request) bool {
	for _, cfg := range m.BypassConfigs {
		switch cfg.match {
		case bypassMatchExact:
			if cfg.URI == r.URL.Path {
				return true
			}
		case bypassMatchPartial:
			if strings.Contains(r.URL.Path, cfg.URI) {
				return true
			}
		case bypassMatchPrefix:
			if strings.HasPrefix(r.URL.Path, cfg.URI) {
				return true
			}
		case bypassMatchSuffix:
			if strings.HasSuffix(r.URL.Path, cfg.URI) {
				return true
			}
		case bypassMatchRegex:
			if cfg.regex.MatchString(r.URL.Path) {
				return true
			}
		}
	}
	return false
}
