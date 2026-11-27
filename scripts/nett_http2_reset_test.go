package v2rayhttp

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestNettResetClosesActiveHTTP2AndAllowsReconnect(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	// A local test server has a generated, untrusted certificate.
	transport := &http2.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer ResetTransport(transport)
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	closed := make(chan error, 1)
	go func() { _, err := io.ReadAll(response.Body); closed <- err }()
	ResetTransport(transport)
	select {
	case err := <-closed:
		if err == nil {
			t.Fatal("reset must interrupt the active response")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reset left an active HTTP/2 connection open")
	}
	response, err = client.Get(server.URL)
	if err != nil {
		t.Fatal("reconnect after reset:", err)
	}
	response.Body.Close()
}
