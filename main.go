package main

import (
	"gotlsaflare/cmd"
	"os"
)

func main() {
	err := cmd.Execute()
	if err != nil {
		os.Exit(1)
	}

	os.Exit(0)
}
