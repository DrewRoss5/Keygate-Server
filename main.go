package main

import (
	"fmt"
	"os"
	"syscall"

	"github.com/DrewRoss5/keygate-server/serverutils"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Error: This program takes at least one argument.")
		return
	}
	switch os.Args[1] {
	case "init":
		err := serverutils.InitServer()
		if err != nil {
			fmt.Printf("Failed to initalize server!\nError %v\n", err)
			return
		}
		fmt.Println("Server initialized successfully!")

	case "run":
		// warn the user if we're not running as root.
		if syscall.Geteuid() != 0 {
			fmt.Println("Warning: This server is intended to be run as root. Running as another use may lead to unexpected behavior.")
		}
		if len(os.Args) != 4 {
			fmt.Println("Error: This command takes exactly two arguments")
			return
		}
		cert_path := os.Args[2]
		key_path := os.Args[3]
		err := serverutils.RunServer(cert_path, key_path)
		if err != nil {
			fmt.Printf("Error: Failed to start HTTPS\nError: %v\n", err)
		}

	default:
		fmt.Printf("Unrecognized command: \"%s\"\n", os.Args[1])
	}
}
