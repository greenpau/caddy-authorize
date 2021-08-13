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

package shared

import (
	"fmt"
	"sync"
)

var (
	// Buffer is a key-value store.
	Buffer *buffer
)

func init() {
	Buffer = newBuffer()
}

type buffer struct {
	mu      sync.RWMutex
	Entries map[string]string
}

func newBuffer() *buffer {
	c := &buffer{
		Entries: make(map[string]string),
	}
	return c
}

// Add adds a serialized key to the buffer.
func (c *buffer) Add(k, v string) error {
	if k == "" || v == "" {
		return fmt.Errorf("invalid input")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.Entries[k]; exists {
		return fmt.Errorf("not empty")
	}
	c.Entries[k] = v
	return nil
}

// Get returns a serialized key from the stash.
func (c *buffer) Get(k string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, exists := c.Entries[k]; exists {
		return v, nil
	}
	return "", fmt.Errorf("not found")
}
