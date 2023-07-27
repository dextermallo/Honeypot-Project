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

	if doGetRequest(t, server.URL+"/") != http.StatusOK {
		t.Errorf("GET / should return 200")
	}

	for i := 0; i < 10; i++ {
		if doGetRequest(t, server.URL+"?param='><script>alert(1)</script>") != http.StatusOK {
			t.Errorf("GET /?param='><script>alert(1)</script> should return 200")
		}
	}

	violation_list := []int{941100, 941110, 941160, 941390}
	for _, violation := range violation_list {
		if curHoneypotService.globalCtx.invokeCnt[violation] != 10 {
			t.Errorf("%d should be invoked once", violation)
		}
	}

	server.Close()
}
