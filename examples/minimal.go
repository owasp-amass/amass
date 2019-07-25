package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/OWASP/Amass/enum"
)

func main() {
	// Seed the default pseudo-random number generator
	rand.Seed(time.Now().UTC().UnixNano())

	e := enum.NewEnumeration()
	if e == nil {
        return
	}
	
	go func() {
		for result := range e.Output {
			fmt.Println(result.Name)
		}
	}()
	
	// Setup the most basic amass configuration
	e.Config.AddDomain("example.com")
	e.Start()
}
