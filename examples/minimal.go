package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/OWASP/Amass/amass"
)

func main() {
	output := make(chan *amass.AmassOutput)

	go func() {
		for result := range output {
			fmt.Println(result.Name)
		}
	}()

	// Seed the default pseudo-random number generator
	rand.Seed(time.Now().UTC().UnixNano())

	// Setup the most basic amass configuration
	config := amass.CustomConfig(&amass.AmassConfig{Output: output})
	config.AddDomain("example.com")

	// Begin the enumeration process
	amass.StartEnumeration(config)
}
