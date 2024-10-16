package config

import "fmt"

func (c *Config) loadRigidSettings(cfg *Config) error {
	// Retrieve the rigid_boundaries option from the configuration
	rigidinterface, ok := c.Options["rigid_boundaries"]
	if !ok {
		// "rigid_boundaries" not found in options, so nothing to do here.
		return nil
	}

	rigid, ok := rigidinterface.(bool)
	if !ok {
		return fmt.Errorf("failed to parse rigid_boundaries setting, value is not a boolean")
	}
	c.Rigid = rigid
	return nil
}
