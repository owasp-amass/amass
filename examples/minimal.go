package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/OWASP/Amass/amass"
)

func main() {
	// Seed the default pseudo-random number generator
	rand.Seed(time.Now().UTC().UnixNano())

	enum := amass.NewEnumeration()
	go func() {
		for result := range enum.Output {
			fmt.Println(result.Name)
		}
	}()
	// Setup the most basic amass configuration
	enum.Config.AddDomain("example.com")
	// Begin the enumeration process
	enum.Start()
}
