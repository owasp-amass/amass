package sources

import (
	"testing"

	"github.com/OWASP/Amass/config"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
)

func TestShodan(t *testing.T) {
	if *networkTest == false || *configPath == "" {
		return
	}

	cfg := setupConfig(domainTest)

	API := new(config.APIKey)
	API = cfg.GetAPIKey("shodan")

	if API == nil || API.Key == "" {
		t.Errorf("API key data was not provided")
		return
	}

	bus, out := setupEventBus(requests.NewNameTopic)
	defer bus.Stop()

	pool := resolvers.NewResolverPool(nil)
	defer pool.Stop()

	srv := NewShodan(cfg, bus, pool)

	result := testService(srv, out)
	if result < expectedTest {
		t.Errorf("Found %d names, expected at least %d instead", result, expectedTest)
	}
}
