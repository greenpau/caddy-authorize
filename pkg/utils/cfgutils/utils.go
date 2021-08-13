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

package cfgutils

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strings"
)

// ParseBoolArg converts string to boolean.
func ParseBoolArg(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "":
		return false, fmt.Errorf("empty switch")
	case "yes", "true", "on", "1":
		return true, nil
	case "no", "false", "off", "0":
		return false, nil
	}
	return false, fmt.Errorf("invalid switch: %s", s)
}

// EncodeArgs encodes passed arguments.
func EncodeArgs(args []string) string {
	var b []byte
	bb := bytes.NewBuffer(b)
	w := csv.NewWriter(bb)
	w.Comma = ' '
	w.Write(args)
	w.Flush()
	s := string(bb.Bytes())
	s = strings.TrimSpace(s)
	return s
}

// DecodeArgs decode arguments from string.
func DecodeArgs(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	r := csv.NewReader(strings.NewReader(s))
	r.Comma = ' '
	args, err := r.Read()
	if err != nil {
		return nil, err
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("empty")
	}
	return args, err
}
