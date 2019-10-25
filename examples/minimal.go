package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/enum"
	"github.com/OWASP/Amass/v3/services"
)

func main() {
	// Seed the default pseudo-random number generator
	rand.Seed(time.Now().UTC().UnixNano())

	sys, err := services.NewLocalSystem(config.NewConfig())
	if err != nil {
		return
	}

	e := enum.NewEnumeration(sys)
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
