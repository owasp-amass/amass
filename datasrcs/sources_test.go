package datasrcs

import (
	"testing"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/systems"
)

func TestGetAllSources(t *testing.T) {
	cfg := config.NewConfig()
	sys, err := systems.NewLocalSystem(cfg)
	if err != nil {
		return
	}
	r := GetAllSources(sys)
	if len(r) <= 0 {
		t.Errorf("DataSources Not Found")
	}
	_ = sys.Shutdown()
}
