package sources

import (
	"testing"

	"github.com/OWASP/Amass/amass/core"
)

func TestTwitter(t *testing.T) {
	if *networkTest == false || *configPath == "" {
		return
	}

	config := setupConfig(domainTest)

	API := new(core.APIKey)
	API = config.GetAPIKey("twitter")

	if API == nil || API.Key == "" || API.Secret == "" {
		t.Errorf("API key data was not provided")
		return
	}

	bus, out := setupEventBus(core.NewNameTopic)
	defer bus.Stop()

	srv := NewTwitter(config, bus)

	result := testService(srv, out)
	if result < expectedTest {
		t.Errorf("Found %d names, expected at least %d instead", result, expectedTest)
	}
}
