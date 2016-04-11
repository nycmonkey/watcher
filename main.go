package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
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
	"sync"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/fsnotify/fsnotify"
)

var (
	watcher    *fsnotify.Watcher
	wg         sync.WaitGroup
	inProgress map[string]bool
	client     *http.Client
	config     *Config
	configPath = flag.String("config", "config.json", "path to the configuration file")
)

type FileConfig struct {
	Subject  string
	Inbound  string
	Outbound []string
}
type Config struct {
	VaultURL string
	CACert   string
	LogFile  string
	Files    []*FileConfig
}

func main() {
	flag.Parse()
	err := loadConfig()
	if err != nil {
		log.Fatalln("Error loading config:", err)
	}
	var logfile *os.File
	err = os.MkdirAll(filepath.Dir(config.LogFile), 0666)
	if err != nil {
		log.Fatalln(err)
	}
	logfile, err = os.OpenFile(config.LogFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	defer logfile.Close()
	if err != nil {
		log.Println("Error opening log file, using stdout:", err)
	} else {
		log.SetPrefix("watcher: ")
		log.SetOutput(logfile)
	}
	// send paths to the vault to ingest and encrypt
	err = setupHttpClient()
	if err != nil {
		log.Fatalln("Error setting up http client:", err)
	}
	log.Println("Config OK")
	// Start the file watcher
	watcher, err = fsnotify.NewWatcher()
	if err != nil {
		log.Fatalln("Error instantiating fsnotify.Watcher:", err)
	}
	inProgress = make(map[string]bool)

	// handle file notifications
	go handleEvents()

	// start watching configured directories
	for _, conf := range config.Files {
		err = registerWatcher(conf.Inbound)
		if err != nil {
			log.Fatalln("Error registering watcher for", conf.Inbound, ":", err)
		}
	}

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
	case <-time.After(30 * time.Second):
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

func setupHttpClient() error {
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

func registerWatcher(glob string) (err error) {
	_, err = filepath.Match(glob, `C:\tmp`)
	if err != nil {
		return errors.New("Invalid glob pattern: " + glob)
	}

	log.Println("WATCHING:", filepath.Dir(glob))
	return watcher.Add(filepath.Dir(glob))
}

func ingestFile(path, subject string) (id string, err error) {
	notCreated := errors.New("Wrong status code")
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
		return notCreated
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
		if matched {
			id, err := ingestFile(path, conf.Subject)
			digest := sha256.New()
			if err != nil {
				log.Println("NOT ARCHIVED:", path)
				log.Println("ARCHIVE ERR:", err)
				return
			}
			writers := make([]io.Writer, 0)
			writers = append(writers, digest)
			for _, dest := range conf.Outbound {
				_ = os.MkdirAll(dest, 0666)
				o, err := os.Create(filepath.Join(dest, filepath.Base(path)))
				if err != nil {
					log.Println("OUTPUT ERR:", err)
					continue
				}
				log.Println("SENDING", filepath.Join(dest, filepath.Base(path)))
				writers = append(writers, o)
				defer o.Close()
			}
			if len(writers) > 0 {
				var source *os.File
				source, err = os.Open(path)
				if err != nil {
					log.Println("COPY FAIL:", err)
					return
				}
				defer source.Close()
				w := io.MultiWriter(writers...)
				if _, err = io.Copy(w, source); err != nil {
					log.Println("COPY FAIL:", err)
					return
				}
				source.Close()
				local_id := fmt.Sprintf("%x", digest.Sum(nil))
				if id == local_id {
					log.Println(id, "<<", filepath.Base(path))
					err = removeInboundFile(path)
					if err != nil {
						log.Println("DELETE FAIL:", path)
						log.Println("DELETE ERR:", err)
					}
				} else {
					log.Printf("ARCHIVE FAIL: %s != %s\n", id, local_id)
					log.Println("NOT DELETING", path)
				}
			}

			// file was handled; exit loop
			return
		}
	}
	// File was not handled
	log.Println("GLOB FAIL:", path, "was ingnored")
	return
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
