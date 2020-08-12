// Copyright 2020 Paul Greenberg (greenpau@outlook.com)

package jwt

import (
	"io/ioutil"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestPlugin(t *testing.T) {
	tester := caddytest.NewTester(t)
	baseURL := "https://127.0.0.1:3443"
	configFile := "assets/conf/config.json"
	configContent, err := ioutil.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load configuration file %s: %s", configFile, err)
	}
	rawConfig := string(configContent)
	tester.InitServer(rawConfig, "json")
	tester.AssertGetResponse(baseURL+"/version", 200, "1.0.0")
	time.Sleep(1 * time.Millisecond)
	// Uncomment the below line to perform manual testing
	// time.Sleep(6000 * time.Second)
}
