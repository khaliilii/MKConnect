package profile

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

// FetchSubscription downloads a subscription (a list of share links, usually base64 encoded).
func FetchSubscription(url string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("subscription: HTTP %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 10<<20))
}
