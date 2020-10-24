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

package jwt

import (
	"errors"
	"fmt"
)

type strError string

func (e strError) Error() string { return string(e) }

// F captures the values for an error string formatting.
func (e strError) WithArgs(v ...interface{}) error {
	var hasErr, hasNil bool
	for _, vv := range v {
		switch err := vv.(type) {
		case error:
			if err == nil {
				return nil // we pass nill errors along
			}
			hasErr = true
		case nil:
			hasNil = true
		}
	}

	if hasNil && !hasErr {
		return nil
	}

	return fmtErr{err: fmt.Errorf("%w", e), v: v}
}

// fmtErr is for errors that will be formatted. It holds
// formatting values in a slice so they can be added when the
// error is stringfied. Otherwise the underlining error without
// formatting can be matched.
type fmtErr struct {
	err error
	v   []interface{}
}

func (e fmtErr) Error() string { return fmt.Sprintf(e.err.Error(), e.v...) }

// Unwrap is a method to help unwrap errors on the base error for go1.13+
func (e fmtErr) Unwrap() error { return errors.Unwrap(e.err) }
