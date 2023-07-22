package main

import (
	"io/ioutil"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/dextermallo/owasp-honeypot/utils/logger"
)

var curHoneypotService *HoneypotService
var SMLock = sync.Mutex{}

func handler(w http.ResponseWriter, req *http.Request, honeypotService *HoneypotService) {
	logger.Debug("start handler()")

	// add client ip to header for honeypot
	req.Header.Set("X-Forwarded-For", req.RemoteAddr)

	curHoneypotService = honeypotService
	honeypotService.globalCtx.activityLock.Lock()

	curLogCtx := honeypotService.globalCtx.curLogCtx
	honeypotService.globalCtx.update(honeypotService.globalCtx.curLogCtx)

	honeypotService.globalCtx.activityLock.Unlock()

	for _, ruleID := range curLogCtx.ruleID {
		if _, isExist := honeypotService.globalCtx.blockList[ruleID]; isExist {
			logger.Info("Request blocked by MTD, Blocked IP: " + curLogCtx.ip)

			w.Header().Set("Content-Type", "text/plain")
			resBody := "Transaction not disrupted."

			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(resBody))
			return
		}
	}

	if len(curLogCtx.ruleID) > 0 {
		logger.Warning("Violated Rules Detected: ", curLogCtx.ruleID)
	}

	honeypotService.globalCtx.updateBlockList(curLogCtx.ruleID)

	SMLock.Lock()
	for _, securityMeasure := range SecurityMeasureList {
		passInspection, err := securityMeasure.inspect(curLogCtx, honeypotService)

		if err != nil {
			logger.Error(err.Error())
			continue
		}

		if passInspection {
			logger.Info("Request passed inspection: " + securityMeasure.name)
			if securityMeasure.passFn != nil {
				go securityMeasure.passFn(honeypotService)

				w.Header().Set("Content-Type", "text/plain")
				resBody := "Transaction not disrupted."

				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(resBody))
				return
			}
		} else {
			logger.Warning("Request failed inspection: " + securityMeasure.name)
			if securityMeasure.failFn != nil {
				go securityMeasure.failFn(honeypotService)

				w.Header().Set("Content-Type", "text/plain")
				resBody := "Transaction not disrupted."

				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(resBody))
				return
			}
		}
	}
	SMLock.Unlock()

	url := honeypotService.endpoint
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

func handlerWrapper(honeypotService *HoneypotService) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		handler(w, req, honeypotService)
	}
}

func copyHeaders(dest http.Header, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dest.Add(key, value)
		}
	}
}

func buildService() {
	logger.SetLogLevel(logger.WarningLevel)
	logger.SetOutputMode(true)
	logger.Warning("Initialize services")

	honeypotServices := []*HoneypotService{
		NewHoneypotService("1", "http://localhost:8001/", "distributed-honeypot", "/public"),
		NewHoneypotService("2", "http://localhost:8002/", "distributed-honeypot", "/private"),
	}

	waf := createWAF()

	for _, honeypotService := range honeypotServices {
		go honeypotService.globalCtx.recentActivityCnt.Start()
		http.Handle(honeypotService.prefix, txhttp.WrapHandler(waf, http.HandlerFunc(handlerWrapper(honeypotService))))
	}

	// force bind first honeypot with prefix "/"
	http.Handle("/", txhttp.WrapHandler(waf, http.HandlerFunc(handlerWrapper(honeypotServices[0]))))

	curHoneypotService = honeypotServices[0]
}

func main() {
	buildService()
	logger.Fatal(http.ListenAndServe(":80", nil))
}

func createWAF() coraza.WAF {
	logger.Debug("start createWAF()")

	directivesFile := "./default.conf"

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
	for curHoneypotService.globalCtx.isLocked {
		logger.Debug("isLocked: " + strconv.FormatBool(curHoneypotService.globalCtx.isLocked))
		time.Sleep(5 * time.Second)
	}

	if curHoneypotService.globalCtx.curLogCtx.ip == "" {
		curHoneypotService.globalCtx.curLogCtx.ip = error.ClientIPAddress()
	}

	ruleId := error.Rule().ID()
	if ruleId == 949110 || ruleId == 949111 {
		for _, data := range error.MatchedDatas() {
			if data.Key() == "blocking_inbound_anomaly_score" {
				score, _ := strconv.Atoi(data.Value())
				curHoneypotService.globalCtx.curLogCtx.totalScore = score
				break
			}
		}
	}

	if _, isExist := RULE_WHITE_LIST[ruleId]; !isExist {
		curHoneypotService.globalCtx.curLogCtx.ruleID = append(curHoneypotService.globalCtx.curLogCtx.ruleID, ruleId)
	}
}
