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

package addrutils

import (
	"net/http"
	"strings"
)

// GetSourceAddress returns the IP address of the request.
func GetSourceAddress(r *http.Request) string {
	var addr string
	if r.Header.Get("X-Real-Ip") != "" {
		addr = r.Header.Get("X-Real-Ip")
	} else {
		if r.Header.Get("X-Forwarded-For") != "" {
			addr = r.Header.Get("X-Forwarded-For")
		} else {
			addr = r.RemoteAddr
		}
	}
	if strings.Contains(addr, ",") {
		addr = strings.TrimSpace(addr)
		addr = strings.SplitN(addr, ",", 2)[0]
	}
	switch {
	case strings.Contains(addr, "["):
		// Handle IPv6 "[host]:port" address.
		return parseAddr6(addr)
	case strings.Contains(addr, "::"):
		// Handle IPv6 address.
		return addr
	}
	if strings.Contains(addr, ":") {
		parts := strings.Split(addr, ":")
		if len(parts) > 2 {
			// Handle IPv6 address.
			return parts[0]
		}
		return parts[0]
	}
	return addr
}

func parseAddr6(s string) string {
	i := strings.IndexByte(s, '[')
	if i < 0 {
		return s
	}
	j := strings.IndexByte(s, ']')
	if j < 0 {
		return s
	}
	if i >= j {
		return s
	}
	return s[(i + 1):j]
}
