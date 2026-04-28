package checks

import (
	"io"
	"math/rand"
	"net/http"
	"net/url"
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
}

func randomUA() string {
	return userAgents[rand.Intn(len(userAgents))]
}

func get(client *http.Client, rawURL string) (*http.Response, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", randomUA())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json,*/*;q=0.9")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	return client.Do(req)
}

func drainClose(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// injectParam replaces the named query parameter's value with payload.
func injectParam(rawURL, param, payload string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set(param, payload)
	u.RawQuery = q.Encode()
	return u.String()
}

// semaphore is a counting semaphore backed by a buffered channel.
type semaphore chan struct{}

func newSem(n int) semaphore    { return make(chan struct{}, n) }
func (s semaphore) Acquire()    { s <- struct{}{} }
func (s semaphore) Release()    { <-s }
