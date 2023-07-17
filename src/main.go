package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"
	logger "github.com/dexter/owasp-honeypot/utils/logger"
)

var globalCtx = NewGlobalCtx()

func handler(w http.ResponseWriter, req *http.Request) {
	logger.Debug("start handler()")

	globalCtx.activityLock.Lock()

	curLogCtx := globalCtx.curLogCtx
	globalCtx.update(globalCtx.curLogCtx)

	globalCtx.activityLock.Unlock()

	for _, ruleID := range curLogCtx.ruleID {
		if _, isExist := globalCtx.blockList[ruleID]; isExist {
			logger.Info("Request blocked by MTD, Blocked IP: " + curLogCtx.ip)

			w.Header().Set("Content-Type", "text/plain")
			resBody := "Transaction not disrupted."

			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(resBody))
			return
		}
	}

	globalCtx.updateBlockList(curLogCtx.ruleID)

	for _, securityMeasure := range SecurityMeasureList {
		passInspection, err := securityMeasure.inspect(curLogCtx, globalCtx)

		if err != nil {
			logger.Error(err.Error())
			continue
		}

		if passInspection {
			logger.Info("Request passed inspection: " + securityMeasure.name)
			if securityMeasure.passFn != nil {
				go securityMeasure.passFn()

				w.Header().Set("Content-Type", "text/plain")
				resBody := "Transaction not disrupted."

				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(resBody))
				return
			}
		} else {
			logger.Info("Request failed inspection: " + securityMeasure.name)
			if securityMeasure.failFn != nil {
				go securityMeasure.failFn()

				w.Header().Set("Content-Type", "text/plain")
				resBody := "Transaction not disrupted."

				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(resBody))
				return
			}
		}
	}

	url := "http://localhost:80"
	client := &http.Client{}

	// Create a new request based on the incoming request
	proxyReq, err := http.NewRequest(req.Method, url, req.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Copy the headers from the incoming request to the proxy request
	proxyReq.Header = make(http.Header)
	copyHeaders(proxyReq.Header, req.Header)

	// Send the proxy request to the target server
	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy the headers from the target server's response to the outgoing response
	copyHeaders(w.Header(), resp.Header)

	// Read the response body from the target server
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Write the response body to the outgoing response
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

func copyHeaders(dest http.Header, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dest.Add(key, value)
		}
	}
}

func main() {
	logger.SetLogLevel(logger.DebugLevel)
	logger.SetOutputMode(true)

	logger.Debug("Initialize services")

	// start TTL cache
	go globalCtx.recentActivityCnt.Start()

	waf := createWAF()

	http.Handle("/", txhttp.WrapHandler(waf, http.HandlerFunc(handler)))
	logger.Fatal(http.ListenAndServe(":8080", nil))
}

func createWAF() coraza.WAF {
	directivesFile := "./default.conf"
	if s := os.Getenv("DIRECTIVES_FILE"); s != "" {
		directivesFile = s
	}

	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithErrorCallback(logError).
			WithDirectivesFromFile(directivesFile).
			WithDirectivesFromFile("./coreruleset/rules/*.conf").
			WithDirectivesFromFile("./coraza.conf"),
	)

	if err != nil {
		logger.Fatal(err)
	}
	return waf
}

func logError(error types.MatchedRule) {
	for globalCtx.isLocked {
		fmt.Println("sleeping")
		time.Sleep(5 * time.Second)
	}

	if globalCtx.curLogCtx.ip == "" {
		globalCtx.curLogCtx.ip = error.ClientIPAddress()
	}

	ruleId := error.Rule().ID()
	if ruleId == 949110 || ruleId == 949111 {
		for _, data := range error.MatchedDatas() {
			if data.Key() == "blocking_inbound_anomaly_score" {
				score, _ := strconv.Atoi(data.Value())
				globalCtx.curLogCtx.totalScore = score
				break
			}
		}
	}

	if _, isExist := RULE_WHITE_LIST[ruleId]; !isExist {
		globalCtx.curLogCtx.ruleID = append(globalCtx.curLogCtx.ruleID, ruleId)
	}
}
