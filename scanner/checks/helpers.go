package checks

import (
	"io"
	"net/http"
	"net/url"
)

const ua = "WhiteClaw-Scanner/3.1 (H1whiteclaw)"

func randomUA() string { return ua }

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
