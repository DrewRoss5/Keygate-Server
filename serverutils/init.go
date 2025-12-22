package serverutils

import (
	"bytes"
	"fmt"
	"os"
	"syscall"

	"encoding/base64"
	"encoding/json"

	"github.com/DrewRoss5/keygate-server/cryptoutils"
	"golang.org/x/term"
)

func CheckDirectoryExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	if err != nil {
		return false
	}
	return info.IsDir()
}

func InitServer() error {
	var err error
	// get the user's name
	var username string
	fmt.Print("Username: ")
	fmt.Scanln(&username)
	// get the user's password
	var password []byte
	var confirm_pass []byte
	for {
		fmt.Print("Password: ")
		password, err = term.ReadPassword(int(syscall.Stdin))
		fmt.Println("")
		if err != nil {
			fmt.Println("Failed to read password!")
			return err
		}
		fmt.Print("Confirm: ")
		confirm_pass, err = term.ReadPassword(int(syscall.Stdin))
		fmt.Println("")
		if err != nil {
			fmt.Println("Failed to read password!")
			return err
		}
		// ensure that password matches confirmation
		if bytes.Equal(password, confirm_pass) {
			break
		}
		fmt.Println("Password does not match confirmation!")
	}
	// read the user's primary file path
	var file_path string
	for {
		fmt.Printf("Base File Path: ")
		fmt.Scanln(&file_path)
		// ensure the directory is valid, and create the keygate directory in it.
		if !CheckDirectoryExists(file_path) {
			fmt.Println("File path does does not exist, or is not a directory.")
		}
		err = os.Mkdir(file_path+"/keygate", 0555)
		if err == nil {
			break
		}
		fmt.Println("Invalid file path.")
	}
	// get the user's public key
	var key_path string
	for {
		fmt.Printf("Public Key Path: ")
		fmt.Scanln(&key_path)
		// attempt to import the public key to ensure its valid
		_, err := cryptoutils.ImportRsaPubFile(key_path)
		if err == nil {
			break
		}
		fmt.Printf("Invalid RSA Public Key.\nerror: %v", err)
	}
	// hash and encode the user's password for storage
	salt := cryptoutils.GenAesKey() // this is a bit of hack, but works for getting a securely random 32-bit salt
	pw_hash := cryptoutils.HashKey(password, salt, 32)
	hash_str := base64.StdEncoding.EncodeToString(pw_hash)
	salt_str := base64.StdEncoding.EncodeToString(salt)
	// store the user's info to a map
	user_info := make(map[string]string)
	user_info["Password"] = hash_str
	user_info["Salt"] = salt_str
	user_info["Path"] = file_path
	// save the map to JSON (the additional dictionary is used to allow for the possibility of multiple users in the future)
	config_map := make(map[string]map[string]string)
	config_map[username] = user_info
	// create the config directory
	err = os.Mkdir("config", 0755)
	if err != nil {
		fmt.Printf("Failed to initialize server!\nError: %s\n", err)
		return err
	}
	// save the user's RSA Public key to their directory
	key_bytes, _ := os.ReadFile(key_path) // if the key was already validated, we don't need to check the error for this call
	err = os.WriteFile(fmt.Sprintf("%s/keygate/pub.pem", file_path), key_bytes, 0644)
	if err != nil {
		return err
	}
	// save the user configuration
	json_data, err := json.Marshal(config_map)
	if err != nil {
		fmt.Printf("Error saving user data: %v\n", err)
		return err
	}
	err = os.WriteFile("config/user.json", json_data, 0644) // 0644 sets file permissions
	if err != nil {
		fmt.Printf("Error saving user data: %v\n", err)
		return err
	}
	return nil
}
