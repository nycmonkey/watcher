package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/alexbrainman/sspi/ntlm"
	"github.com/cenkalti/backoff"
	"github.com/fsnotify/fsnotify"
)

var (
	watcher       *fsnotify.Watcher
	wg            sync.WaitGroup
	inProgress    map[string]bool
	client        *http.Client
	config        *Config
	configPath    = flag.String("config", "config.json", "path to the configuration file")
	errNotCreated = errors.New("File not created - FileVault did not return status 201")
)

// FileConfig specifies how each data file should be handled
type FileConfig struct {
	Subject  string
	Inbound  string
	Outbound []string
}

// Config describes implementation details for security, logging and file hanlding
type Config struct {
	VaultURL string
	CACert   string
	LogFile  string
	Files    []*FileConfig
}

func setupWatcher() (w *fsnotify.Watcher, err error) {
	w, err = fsnotify.NewWatcher()
	if err != nil {
		return
	}
	// start watching configured directories
	for _, conf := range config.Files {
		err = registerWatcher(w, conf.Inbound)
		if err != nil {
			log.Println("Error registering watcher for", conf.Inbound, ":", err)
			return
		}
	}
	return
}

func main() {
	flag.Parse()
	err := loadConfig()
	// send paths to the vault to ingest and encrypt
	err = setupHTTPClient()
	if err != nil {
		log.Fatalln("Error setting up http client:", err)
	}
	log.Println("Config OK")
	// Start the file watcher
	watcher, err = setupWatcher()
	if err != nil {
		log.Fatalln("Error setting up fsnotify.Watcher:", err)
	}
	inProgress = make(map[string]bool)

	// handle file notifications
	go handleEvents()

	// Trap signals to initiate shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill)
	_ = <-c
	log.Println("Shutting down...")
	done := shutdown()
	select {
	case <-done:
		log.Println("Graceful shutdown succeeded")
		return
	case <-time.After(5 * time.Second):
		log.Println("Shutdown timed out")
		return
	}
}

func loadConfig() error {
	data, err := ioutil.ReadFile(*configPath)
	if err != nil {
		return err
	}
	config = &Config{}
	return json.Unmarshal(data, config)
}

func setupHTTPClient() error {
	pemData, err := ioutil.ReadFile(config.CACert)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemData)
	tlsConfig := &tls.Config{
		RootCAs: pool,
	}
	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client = &http.Client{Transport: tr}
	return nil
}

func registerWatcher(w *fsnotify.Watcher, glob string) (err error) {
	_, err = filepath.Match(glob, `C:\tmp`)
	if err != nil {
		return errors.New("Invalid glob pattern: " + glob)
	}

	log.Println("WATCHING:", filepath.Dir(glob))
	return w.Add(filepath.Dir(glob))
}

func ingestFile(path, subject string) (id string, err error) {
	operation := func() error {
		var resp *http.Response
		params := url.Values{}
		params.Set("path", path)
		params.Set("subject", subject)
		resp, err = client.PostForm(config.VaultURL, params)
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusCreated {
			var data []byte
			data, err = ioutil.ReadAll(resp.Body)
			if err == nil {
				id = string(data)
			}
			return err
		}
		return errNotCreated
	}
	err = backoff.Retry(operation, backoff.NewExponentialBackOff())
	return
}

func processFile(path string) {
	wg.Add(1)                      // wg is a sync.WaitGroup
	defer delete(inProgress, path) // using this map as a lock
	defer wg.Done()
	for _, conf := range config.Files {
		matched, err := filepath.Match(conf.Inbound, path)
		if err != nil {
			log.Println("BAD CONFIG:", conf.Inbound)
			continue
		}
		if !matched {
			continue
		}
		id, err := ingestFile(path, conf.Subject)
		digest := sha256.New()
		if err != nil {
			log.Println("NOT ARCHIVED:", path)
			log.Println("ARCHIVE ERR:", err)
			return
		}
		var writers []io.Writer
		var requestURLs []string
		writers = append(writers, digest)
		for _, dest := range conf.Outbound {
			if strings.HasPrefix(dest, "http") {
				requestURLs = append(requestURLs, dest)
			} else {
				_ = os.MkdirAll(dest, 0666)
				var o *os.File
				o, err = os.Create(filepath.Join(dest, filepath.Base(path)))
				if err != nil {
					log.Println("OUTPUT ERR:", err)
					continue
				}
				log.Println("SENDING", filepath.Join(dest, filepath.Base(path)))
				writers = append(writers, o)
				defer o.Close()
			}
		}
		var fileSize int64
		var source *os.File
		source, err = os.Open(path)
		if err != nil {
			log.Println("COPY FAIL:", err)
			return
		}
		defer source.Close()
		w := io.MultiWriter(writers...)
		if fileSize, err = io.Copy(w, source); err != nil {
			log.Println("COPY FAIL:", err)
			return
		}
		source.Close()
		localID := fmt.Sprintf("%x", digest.Sum(nil))
		if id == localID {
			log.Println(id, "<<", filepath.Base(path))
			err = removeInboundFile(path)
			if err != nil {
				log.Println("DELETE FAIL:", path)
				log.Println("DELETE ERR:", err)
			}
		} else {
			log.Printf("ARCHIVE FAIL: %s != %s\n", id, localID)
			log.Println("NOT DELETING", path)
		}
		// define metadata
		metadata := struct {
			ID       string `json:"id"`
			Subject  string `json:"subject"`
			Size     int64  `json:"size"`
			Filename string `json:"filename"`
		}{
			id,
			conf.Subject,
			fileSize,
			filepath.Base(path),
		}
		var js []byte
		js, err = json.Marshal(metadata)
		if err != nil {
			log.Fatalln("BUG in json marshalling:", err)
		}
		client := &http.Client{}
		client.Timeout = 3 * time.Second
		httpCalls := new(sync.WaitGroup)
		for _, u := range requestURLs {
			httpCalls.Add(1)
			go notifyByHTTP(u, id, js, httpCalls)
		}
		httpCalls.Wait()
		return
	}
	// File was not handled
	log.Println("GLOB FAIL:", path, "was ingnored")
	return
}

func notifyByHTTP(url, id string, postData []byte, wg *sync.WaitGroup) {
	defer wg.Done()
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(postData))
	if err != nil {
		log.Println("ERROR while creating http request:", err)
		log.Println("NOTIFY FAIL:", url)
		return
	}

	resp, err := get(req)
	if resp.StatusCode == http.StatusOK {
		log.Println("NOTIFIED", url, "about", id)
		return
	}
	if resp.StatusCode != http.StatusUnauthorized {
		log.Println("ERROR while notifying via HTTP - unexpected status code:", resp.StatusCode)
		log.Println("NOTIFY FAIL:", url)
		return
	}

	cred, err := ntlm.AcquireCurrentUserCredentials()
	if err != nil {
		log.Println("ERROR while acquiring credentials for NTLM:", err)
		log.Println("NOTIFY FAIL:", url)
		return
	}
	defer cred.Release()

	secctx, negotiate, err := ntlm.NewClientContext(cred)
	if err != nil {
		log.Println("ERROR while creating client context for NTLM:", err)
		log.Println("NOTIFY FAIL:", url)
		return
	}
	defer secctx.Release()

	req, err = http.NewRequest("POST", url, bytes.NewBuffer(postData))
	if err != nil {
		log.Println("ERROR while creating http request for NTLM negotiation:", err)
		log.Println("NOTIFY FAIL:", url)
		return
	}
	req.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(negotiate))
	resp, err = get(req)
	if resp.StatusCode == http.StatusOK {
		log.Println("NOTIFIED", url, "about", id)
	}
	if resp.StatusCode != 401 {
		log.Println("ERROR during notification: unexpected HTTP StatusCode -", resp.StatusCode)
		log.Println("NOTIFY FAIL:", url)
		return
	}
	authHeaders, found := resp.Header["Www-Authenticate"]
	if !found || len(authHeaders) != 1 || len(authHeaders[0]) < 6 || !strings.HasPrefix(authHeaders[0], "NTLM ") {
		log.Println("ERROR during notification: unexpected response headers")
		log.Println("NOTIFY FAIL:", url)
		return
	}
	log.Println("Header:", authHeaders[0])
	challenge, err := base64.StdEncoding.DecodeString(authHeaders[0][5:])
	if err != nil {
		log.Println("ERROR during notification: couldn't decode challenge")
		log.Println("NOTIFY FAIL:", url)
		return
	}
	authenticate, err := secctx.Update(challenge)
	if err != nil {
		log.Println("ERROR during notification: couldn't process challenge")
		log.Println("NOTIFY FAIL:", url)
		return
	}
	req, err = http.NewRequest("POST", url, bytes.NewBuffer(postData))
	if err != nil {
		log.Println("ERROR while creating http request for NTLM authentication:", err)
		log.Println("NOTIFY FAIL:", url)
		return
	}
	req.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(authenticate))
	resp, err = get(req)
	if err != nil {
		log.Println("ERROR while making NTLM authentication request:", err)
		log.Println("NOTIFY FAIL:", url)
		return
	}
	if resp.StatusCode != http.StatusOK {
		log.Println("NTLM authentication failed with status code", resp.StatusCode)
		log.Printf("%+v\r\n", resp)
		log.Println("NOTIFY FAIL:", url)
		return
	}
	log.Println("NOTIFIED", url, "about", id)
	return
}

func get(req *http.Request) (*http.Response, error) {
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	return res, nil
}

func removeInboundFile(path string) error {
	var err error
	operation := func() error {
		err = os.Remove(path)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	err = backoff.Retry(operation, backoff.NewExponentialBackOff())
	return err
}

func handleEvents() {
	mu := new(sync.Mutex)
	for {
		select {
		case event := <-watcher.Events:
			if event.Op == fsnotify.Create {
				log.Println(event)
				// filesystem sometimes sends to create events for
				// the same file in quick succession.  We use a mutex
				// to only process a given file once at a time
				mu.Lock()
				if _, ok := inProgress[event.Name]; !ok {
					inProgress[event.Name] = true
					go processFile(event.Name)
				}
				mu.Unlock()
			} else {
				if event.Op == fsnotify.Remove {
					log.Println(event)
				}
			}
		case err := <-watcher.Errors:
			if err != nil {
				log.Println("FSNOTIFY ERR:", err)
			}
		case <-time.After(15 * time.Minute):
			newWatcher, err := setupWatcher()
			if err != nil {
				log.Println("ERROR RELOADING WATCHER:", err)
				continue
			}
			oldWatcher := watcher
			watcher = newWatcher
			oldWatcher.Close()
			oldWatcher = nil
		}
	}
}

func shutdown() <-chan bool {
	done := make(chan bool, 1)
	watcher.Close()
	go func() {
		wg.Wait()
		done <- true
	}()
	return done
}
