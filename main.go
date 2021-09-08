package main

import (
	"GoSyncDNS/Only"
	"GoSyncDNS/cmd"
	"fmt"
	"os"
)

// https://centrexapi.overthewire.com.au/ns-api/webroot/apidoc/

func main() {
	var err error

	for range Only.Once {
		err = cmd.Execute()
		if err != nil {
			break
		}

	}

	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "ERROR: %s\n", err)
	}
}
