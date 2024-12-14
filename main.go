package main

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	MAX_ADDRESSES_PER_PAGE = 1000
	SAVE_INTERVAL          = 5 * time.Minute
)

var SPACER_GIF = []byte{
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00,
	0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00,
	0x00, 0x01, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
	0x00, 0x02, 0x02, 0x4c, 0x01, 0x00, 0x3b,
}

var last_time_saved time.Time

var arguments flag.FlagSet

type Config struct {
	FileName *string
	Host     *string
	Port     *int
	Secret   *string
	secret   []byte
}

var config Config

type HitCounter struct {
	mu    sync.Mutex
	Pages map[string]*PageHits `json:"pages"`
}

type PageHits struct {
	Hits      int                 `json:"hits"`
	Addresses map[string]*HitInfo `json:"addrs"`
}

type HitInfo struct {
	Hits int `json:"hits"`
}

var counter = HitCounter{
	Pages: make(map[string]*PageHits),
}

func (hc *HitCounter) register_hit(page string, clientIP string) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	var entry *PageHits
	var ok = false
	if entry, ok = hc.Pages[page]; !ok {
		entry = &PageHits{Addresses: make(map[string]*HitInfo)}
		hc.Pages[page] = entry
	}

	entry.Hits++

	var info *HitInfo
	if info, ok = entry.Addresses[clientIP]; !ok {
		// TODO expire old entries to open space for new hits
		if len(entry.Addresses) >= MAX_ADDRESSES_PER_PAGE {
			return
		}
		info = &HitInfo{}
		entry.Addresses[clientIP] = info
	}

	info.Hits++

	// persist data to disk if enough time has passed
	now := time.Now().UTC()
	if now.Add(SAVE_INTERVAL).After(last_time_saved) {
		last_time_saved = now
		hc.unsafe_save(*config.FileName)
		log.Print("Saved hit information")
	}
}

func (hc *HitCounter) save(filename string) error {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	return hc.unsafe_save(filename)
}

func (hc *HitCounter) unsafe_save(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	return encoder.Encode(hc)
}

func (hc *HitCounter) load(filename string) error {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	return decoder.Decode(hc)
}

func get_address(r *http.Request) string {
	value := r.RemoteAddr
	ip, _, err := net.SplitHostPort(value)
	if err != nil {
		return value
	}
	return ip
}

const URL_PATTERN = `^/[a-zA-Z]+/([a-fA-F0-9]{32})/([a-zA-Z0-9_-]+)$`

var URL_REGEX = regexp.MustCompile(URL_PATTERN)

func parseRequetPath(input string, secretKey []byte) (string, error) {
	// Match the input string with the regex pattern
	matches := URL_REGEX.FindStringSubmatch(input)
	if matches == nil {
		return "", fmt.Errorf("invalid format")
	}

	hmacHex := matches[1]
	base64url := matches[2]

	// decode path information
	base64url = strings.ReplaceAll(base64url, "-", "+")
	base64url = strings.ReplaceAll(base64url, "_", "/")
	base64Decoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(base64url)
	if err != nil {
		return "", fmt.Errorf("invalid base64url encoding: %v", err)
	}

	// signature verification (HMAC-MD5)
	mac := hmac.New(md5.New, secretKey)
	mac.Write([]byte(base64url))
	expectedMAC := mac.Sum(nil)
	expectedHmacHex := fmt.Sprintf("%x", expectedMAC)
	if hmacHex != expectedHmacHex {
		return "", fmt.Errorf("invalid signature")
	}

	return string(base64Decoded), nil
}

func hit_handler(w http.ResponseWriter, r *http.Request) {
	page, err := parseRequetPath(r.URL.Path, config.secret)
	if err == nil && len(page) > 0 {
		log.Printf("Hit path '%s'", page)
		address := get_address(r)
		counter.register_hit(page, address)
	}

	now := time.Now().UTC()
	before := now.Add(time.Hour * 2)
	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Last-Modified", now.Format(http.TimeFormat))
	w.Header().Set("Expires", before.Format(http.TimeFormat))
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, post-check=0, pre-check=0")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	w.Write(SPACER_GIF)
}

func main() {
	config.FileName = arguments.String("file", "", "Path to the persistence file")
	config.Host = arguments.String("host", "0.0.0.0", "IPv4 address to bind to")
	config.Port = arguments.Int("port", 8180, "Port to bind to")
	config.Secret = arguments.String("secret", "", "Secret key to check signatures")
	if err := arguments.Parse(os.Args[1:]); err != nil {
		fmt.Printf("ERROR: %s", err)
		os.Exit(1)
	}

	fmt.Printf("File name: %s\n", *config.FileName)
	fmt.Printf("     Host: %s\n", *config.Host)
	fmt.Printf("     Port: %d\n", *config.Port)

	if len(*config.FileName) == 0 || len(*config.Host) == 0 || *config.Port <= 0 || *config.Port > 65535 {
		arguments.PrintDefaults()
		os.Exit(1)
	}
	if len(*config.Secret) == 0 {
		fmt.Println("ERROR: missing secret key")
		arguments.PrintDefaults()
		os.Exit(1)
	}
	config.secret = []byte(*config.Secret)

	if err := counter.load(*config.FileName); err != nil {
		log.Fatalf("Error loading data: %v\n", err)
	}

	http.HandleFunc("/gif/", hit_handler)
	bind_to := fmt.Sprintf("%s:%d", *config.Host, *config.Port)
	server := &http.Server{Addr: bind_to}

	signal_channel := make(chan os.Signal, 1)
	signal.Notify(signal_channel, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-signal_channel
		log.Printf("Received signal: %s. Saving data and shutting down...\n", sig)
		if err := counter.save(*config.FileName); err != nil {
			log.Printf("Error saving data: %v\n", err)
		}
		server.Shutdown(context.Background())
	}()

	last_time_saved = time.Now().UTC()

	log.Printf("Starting server on %s\n", bind_to)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Could not start server: %v\n", err)
	}
}
