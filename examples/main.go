package main

import (
	"os"
)

func main() {
	exampleType := os.Args[1]
	if exampleType == "1" {
		acquireTokenDeviceCode()
	} else if exampleType == "2" {
		acquireByAuthorizationCodePublic()
	}
}
