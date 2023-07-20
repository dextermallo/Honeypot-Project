package main

import (
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	txhttp "github.com/corazawaf/coraza/v3/http"
)

func setup(t *testing.T) *httptest.Server {
	t.Helper()
	buildService()

	if curHoneypotService == nil {
		t.Errorf("curHoneypotService should not be nil")
	}

	waf := createWAF()
	return httptest.NewServer(txhttp.WrapHandler(waf, http.HandlerFunc(handlerWrapper(curHoneypotService))))
}

func doGetRequest(t *testing.T, getPath string) int {
	t.Helper()
	resp, err := http.Get(getPath)
	if err != nil {
		log.Fatalln(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestServer(t *testing.T) {
	server := setup(t)
	defer server.Close()

	if doGetRequest(t, server.URL+"/public") != http.StatusOK {
		t.Errorf("GET /public should return 200")
	}

	for i := 0; i < 10; i++ {
		if doGetRequest(t, server.URL+"?param='><script>alert(1)</script>") != http.StatusOK {
			t.Errorf("GET /?param='><script>alert(1)</script> should return 200")
		}
	}
}
