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

package validate

import (
	"github.com/greenpau/caddy-authorize/pkg/errors"
	"net/mail"
	"regexp"
)

func LoginHint(redirOpts map[string]interface{}) error {
	validators := redirOpts["login_hint_validators"].([]string)

	for _, validator := range validators {
		switch validator {
		case "email":
			if _, err := mail.ParseAddress(redirOpts["login_hint"].(string)); err == nil {
				return nil
			}
		case "phone":
			regex, _ := regexp.Compile("^[0-9\\-+\\s]+$")
			if match := regex.MatchString(redirOpts["login_hint"].(string)); match == true {
				return nil
			}
		case "alphanumeric":
			regex, _ := regexp.Compile("^[a-zA-Z0-9\\-._!~*'()]+$")
			if match := regex.MatchString(redirOpts["login_hint"].(string)); match == true {
				return nil
			}
		}
	}
	return errors.ErrInvalidLoginHint
}
