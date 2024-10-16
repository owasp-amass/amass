package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestLoadRigidSettings(t *testing.T) {
	tests := []struct {
		name          string
		options       string
		expectedRigid bool
		expectError   bool
	}{
		{
			name:          "RigidBoundariesTrue",
			options:       "rigid_boundaries: true",
			expectedRigid: true,
			expectError:   false,
		},
		{
			name:          "RigidBoundariesFalse",
			options:       "rigid_boundaries: false",
			expectedRigid: false,
			expectError:   false,
		},
		{
			name:          "RigidBoundariesNotPresent",
			options:       "",
			expectedRigid: false,
			expectError:   false,
		},
		{
			name:          "RigidBoundariesInvalidType",
			options:       "rigid_boundaries: invalid",
			expectedRigid: false,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()
			err := yaml.Unmarshal([]byte(tt.options), &cfg.Options)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			err = cfg.loadRigidSettings(cfg)
			if (err != nil) != tt.expectError {
				t.Errorf("loadRigidSettings() error = %v, expectError %v", err, tt.expectError)
				return
			}
			if cfg.Rigid != tt.expectedRigid {
				t.Errorf("loadRigidSettings() Rigid = %v, expectedRigid %v", cfg.Rigid, tt.expectedRigid)
			}
		})
	}
}
