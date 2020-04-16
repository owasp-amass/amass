package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/datasrcs"
	"github.com/OWASP/Amass/v3/enum"
	"github.com/OWASP/Amass/v3/systems"
)

func main() {
	// Seed the default pseudo-random number generator
	rand.Seed(time.Now().UTC().UnixNano())

	sys, err := systems.NewLocalSystem(config.NewConfig())
	if err != nil {
		return
	}
	sys.SetDataSources(datasrcs.GetAllSources(sys))

	e := enum.NewEnumeration(sys)
	if e == nil {
		return
	}
	defer e.Close()

	// Setup the most basic amass configuration
	e.Config.AddDomain("example.com")
	e.Start()

	for _, o := range e.ExtractOutput(nil) {
		fmt.Println(o.Name)
	}
}
