package sources

import (
	"testing"
	
	"github.com/OWASP/Amass/amass/core"
)

const (
	key = "my_api_key"
	secret = "my_secret_key"
)

func TestTwitter(t *testing.T) {
	if *networkTest == false {
		return
	}

	config := setupConfig(domainTest)
	
	personalKey := &core.APIKey{
		Key : key,
		Secret : secret,
	}

	config.AddAPIKey("twitter",personalKey)


	bus, out := setupEventBus(core.NewNameTopic)
	defer bus.Stop()

	srv := NewTwitter(config, bus)

	result := testService(srv, out)
	if result < expectedTest {
		t.Errorf("Found %d names, expected at least %d instead", result, expectedTest)
	}
}