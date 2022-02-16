package datasrcs

import (
	"reflect"
	"testing"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/systems"
)

func TestRegistryRADbURL(t *testing.T) {

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Case arin",
			input:    "arin",
			expected: "https://rdap.arin.net/registry/",
		}, {
			name:     "Case ripencc",
			input:    "ripencc",
			expected: "https://rdap.db.ripe.net/",
		}, {
			name:     "Case apnic",
			input:    "apnic",
			expected: "https://rdap.apnic.net/",
		}, {
			name:     "Case lacnic",
			input:    "lacnic",
			expected: "https://rdap.lacnic.net/rdap/",
		}, {
			name:     "Case afrinic",
			input:    "afrinic",
			expected: "https://rdap.afrinic.net/rdap/",
		},
	}
	cfg := config.NewConfig()
	sys, err := systems.NewLocalSystem(cfg)
	if err != nil {
		return
	}
	myRADb := NewRADb(sys)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := myRADb.registryRADbURL(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("Unexpected Result, expected %v, got %v", tt.expected, result)
			}
		})
	}
	defer sys.Shutdown()
}
