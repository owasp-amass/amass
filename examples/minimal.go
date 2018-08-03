package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/OWASP/Amass/amass"
)

func main() {
	enum := amass.NewEnumeration()

	go func() {
		for result := range enum.Output {
			fmt.Println(result.Name)
		}
	}()

	// Seed the default pseudo-random number generator
	rand.Seed(time.Now().UTC().UnixNano())
	// Setup the most basic amass configuration
	enum.AddDomain("example.com")
	// Begin the enumeration process
	enum.Start()
}
