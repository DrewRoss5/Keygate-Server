package serverutils

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/DrewRoss5/keygate-server/cryptoutils"
	"github.com/DrewRoss5/keygate-server/fileutils"
)

const TokenDuration = 3600 // this is the default expiration time for an authorization token, in the future, it may be configured by the user

type User struct {
	Path     string
	Password string
	Salt     string
}

type AuthToken struct {
	Token     string
	Timestamp int64
}

// wraps a file's path, both by making it "safe" (unable to go outside of the keygate directory), and prepending it with the user's keygate path
// returns an error if a deliberate attack is detected
func wrap_path(file_path string, user_path string) (string, error) {
	if path.IsAbs(file_path) || strings.Contains(file_path, "..") || strings.Contains(file_path, "~") {
		return "", fmt.Errorf("invalid file path")
	}
	file_path = path.Clean(file_path)
	return fmt.Sprintf("%v/keygate/files/%v", user_path, file_path), nil
}

func authorize_user(auth_tokens map[string]AuthToken, key_cache map[string]rsa.PublicKey, token_mut *sync.Mutex, key_mut *sync.Mutex, req *http.Request) (int, error) {
	username := req.Header.Get("username")
	header_token := req.Header.Get("token")
	if username == "" || header_token == "" {
		return http.StatusBadRequest, fmt.Errorf("invalid authorization request")
	}
	// check that the authtoken exists and is valid
	token_mut.Lock()
	token, ok := auth_tokens[username]
	token_mut.Unlock()
	if !ok || (token.Token != header_token) {

		return http.StatusUnauthorized, fmt.Errorf("invalid token or username")
	}

	// check if the token is expired (more than one hour has passed since its creation)
	if (time.Now().Unix() - token.Timestamp) > TokenDuration {
		delete(auth_tokens, username)
		go delete_key(key_cache, username, key_mut)
		return http.StatusUnauthorized, fmt.Errorf("expired token")
	}
	return http.StatusOK, nil
}

func login(user_info map[string]User, auth_tokens map[string]AuthToken, token_mut *sync.Mutex) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		username := req.Header.Get("username")
		password := req.Header.Get("password")
		if username == "" || password == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		user, ok := user_info[username]
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Invalid Username"))
			return
		}
		if !cryptoutils.VerifyPassword(password, user.Password, user.Salt) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Invalid Password"))
			return
		}
		// generate authentication token
		token_bytes := make([]byte, 64)
		rand.Reader.Read(token_bytes)
		token_str := base64.StdEncoding.EncodeToString(token_bytes)
		token_mut.Lock()
		auth_tokens[username] = AuthToken{
			Token:     token_str,
			Timestamp: time.Now().Unix(),
		}
		// send the token string
		fmt.Fprintf(w, "%v", token_str)
		token_mut.Unlock()
	}
}

// logs a user out
func logout(auth_tokens map[string]AuthToken, key_cache map[string]rsa.PublicKey, token_mut *sync.Mutex, key_mut *sync.Mutex) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		status_code, err := authorize_user(auth_tokens, key_cache, token_mut, key_mut, req)
		if err != nil {
			w.WriteHeader(status_code)
			w.Write([]byte(err.Error()))
			return
		}
		// we don't need to verify this exists, as it must've been used by the previous function
		username := req.Header.Get("username")
		token_mut.Lock()
		delete(auth_tokens, username)
		token_mut.Unlock()
		key_mut.Lock()
		delete(key_cache, username)
		key_mut.Unlock()
	}
}

func auth_test(auth_tokens map[string]AuthToken, key_cache map[string]rsa.PublicKey, token_mut *sync.Mutex, key_mut *sync.Mutex) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		status_code, err := authorize_user(auth_tokens, key_cache, token_mut, key_mut, req)
		if err != nil {
			w.WriteHeader(status_code)
			w.Write([]byte(err.Error()))
		}
	}
}

// handles a file upload request
func file_upload(users map[string]User, auth_tokens map[string]AuthToken, key_cache map[string]rsa.PublicKey, token_mut *sync.Mutex, key_mut *sync.Mutex) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// validate the provided username and authtoken
		status_code, err := authorize_user(auth_tokens, key_cache, token_mut, key_mut, req)
		if err != nil {
			w.WriteHeader(status_code)
			w.Write([]byte(err.Error()))
			return
		}
		username := req.Header.Get("username")
		user := users[username]
		// validate the file request
		tmp_name := req.Header.Get("filename")
		file_name, err := wrap_path(tmp_name, user.Path)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid file path"))
			return
		}
		if file_name == "." {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("missing file name"))
			return
		}
		// read the file content
		content, err := io.ReadAll(req.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("failed to read file content"))
			return
		}
		if len(content) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("missing file content"))
			return
		}
		// get the user's public key and path
		key_mut.Lock()
		pub_key, ok := key_cache[username]
		if !ok {
			pub_key, err = cryptoutils.ImportRsaPubFile(user.Path + "/keygate/pub.pem")
			if err != nil {
				key_mut.Unlock()
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("internal server error"))
				return
			}
		}
		key_mut.Unlock()
		// store the file to the user's path
		path_segments := strings.Split(file_name, "/")
		directory := strings.Join(path_segments[:(len(path_segments)-1)], "/")
		// create the directory
		err = os.MkdirAll(directory, 0777)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("failed to create directory for file upload."))
			return
		}
		err = fileutils.EncryptFile(file_name, content, &pub_key)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("internal server error"))
			return
		}
		w.WriteHeader(http.StatusOK)

	}
}

// handles a download request
func file_download(users map[string]User, auth_tokens map[string]AuthToken, key_cache map[string]rsa.PublicKey, token_mut *sync.Mutex, key_mut *sync.Mutex) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// validate the provided username and authtoken
		status_code, err := authorize_user(auth_tokens, key_cache, token_mut, key_mut, req)
		if err != nil {
			w.WriteHeader(status_code)
			w.Write([]byte(err.Error()))
			return
		}
		user := users[req.Header.Get("username")]
		// validate the file path
		tmp_name := req.Header.Get("filename")
		file_name, err := wrap_path(tmp_name, user.Path)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid file path"))
			return
		}
		if file_name == "." {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("missing file name"))
			return
		}
		file_content, err := os.ReadFile(file_name)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("could not read the requested file. does it exist?"))
			return
		}
		w.Write(file_content)
	}
}

func mkdir(users map[string]User, auth_tokens map[string]AuthToken, key_cache map[string]rsa.PublicKey, token_mut *sync.Mutex, key_mut *sync.Mutex) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// validate the provided username and authtoken
		status_code, err := authorize_user(auth_tokens, key_cache, token_mut, key_mut, req)
		if err != nil {
			w.WriteHeader(status_code)
			w.Write([]byte(err.Error()))
			return
		}
		// ensure the directory name is provided
		username := req.Header.Get("username")
		user := users[username]
		// validate the file request
		tmp_name := req.Header.Get("filename")
		dir_name, err := wrap_path(tmp_name, user.Path)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid file path"))
			return
		}
		if dir_name == "." {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("missing file name"))
			return
		}
		_, err = os.Stat(dir_name)
		if err == nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("directory already exists"))
			return
		}
		os.MkdirAll(dir_name, 0755)

	}
}

func list_dir(users map[string]User, auth_tokens map[string]AuthToken, key_cache map[string]rsa.PublicKey, token_mut *sync.Mutex, key_mut *sync.Mutex) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// validate the provided username and authtoken
		status_code, err := authorize_user(auth_tokens, key_cache, token_mut, key_mut, req)
		if err != nil {
			w.WriteHeader(status_code)
			w.Write([]byte(err.Error()))
			return
		}
		user := users[req.Header.Get("username")]
		// validate the file request
		tmp_name := req.Header.Get("filename")
		dir_name, err := wrap_path(tmp_name, user.Path)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid file path"))
			return
		}
		if dir_name == "." {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("missing file name"))
			return
		}
		dir_path := fmt.Sprintf("%v/keygate/files/%v", user.Path, dir_name)
		// ensure the directory exists, and list it's contents if so
		file_info, err := os.Stat(dir_path)
		if err != nil || !file_info.IsDir() {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid path"))
			return
		}
		entries, err := os.ReadDir(dir_path)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("internal server error"))
			return
		}
		// create a list of all entries, followed by a boolean representing if they're a directory
		dir_list := make(map[string]bool)
		for _, entry := range entries {
			dir_list[entry.Name()] = entry.IsDir()
		}
		json_response, _ := json.Marshal(dir_list)
		w.Write(json_response)
	}
}

// locking goroutine that deletes a specified key from the key cache
func delete_key(key_cache map[string]rsa.PublicKey, username string, mut *sync.Mutex) {
	mut.Lock()
	delete(key_cache, username)
	mut.Unlock()
}

// goroutine that checks for expired authtokens and deletes them
func sweep_tokens(tokens map[string]AuthToken, key_cache map[string]rsa.PublicKey, token_mut *sync.Mutex, key_mut *sync.Mutex) {
	for {
		time.Sleep(time.Minute)
		token_mut.Lock()
		for username, token := range tokens {
			if (time.Now().Unix() - token.Timestamp) > TokenDuration {
				delete(tokens, username)
				go delete_key(key_cache, username, key_mut)
			}
		}
		token_mut.Unlock()
	}
}

func RunServer(cert_path string, key_path string) error {
	fmt.Println("Starting server...\nReading User Data..")
	// read the user data from the JSON file
	user_json, err := os.ReadFile("config/user.json")
	if err != nil {
		err = fmt.Errorf("error: failed to read user data file. does it exist?")
		return err
	}
	users := make(map[string]User)
	json.Unmarshal(user_json, &users)
	fmt.Println("Read user data.")
	// initialize the authtoken map, and key cache
	var token_mut sync.Mutex
	var key_mut sync.Mutex
	auth_tokens := make(map[string]AuthToken)
	key_cache := make(map[string]rsa.PublicKey)

	// start the goroutine to find and delete expired tokens
	go sweep_tokens(auth_tokens, key_cache, &token_mut, &key_mut)

	// handler functions
	http.HandleFunc("/login", login(users, auth_tokens, &token_mut))
	http.HandleFunc("/logout", logout(auth_tokens, key_cache, &token_mut, &key_mut))
	http.HandleFunc("/auth_test", auth_test(auth_tokens, key_cache, &token_mut, &key_mut))
	http.HandleFunc("/upload", file_upload(users, auth_tokens, key_cache, &token_mut, &key_mut))
	http.HandleFunc("/download", file_download(users, auth_tokens, key_cache, &token_mut, &key_mut))
	http.HandleFunc("/mkdir", mkdir(users, auth_tokens, key_cache, &token_mut, &key_mut))
	http.HandleFunc("/ls", list_dir(users, auth_tokens, key_cache, &token_mut, &key_mut))

	err = http.ListenAndServeTLS(":8080", cert_path, key_path, nil) // use nil for default handler
	if err != nil {
		return err
	}
	return nil
}
