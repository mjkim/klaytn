package rpc

import (
	"bytes"
	"encoding/json"
	"fmt"
	httptrace "gopkg.in/DataDog/dd-trace-go.v1/contrib/net/http"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
	"net/http"
	"os"
	"strings"
)

func newDatadogTracer() bool {
	ddTraceEnabled := os.Getenv("DD_TRACE_ENABLED")
	if strings.ToLower(ddTraceEnabled) != "true" {
		return false
	}

	tracer.Start()
	return true
}

func newDatadogHTTPHandler(handler http.Handler) http.Handler {
	headers := strings.Split(os.Getenv("DD_TRACE_HEADER_TAGS"), ",")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				logger.ErrorWithStack("Datadog http handler panic", "err", err)
			}
		}()

		reqMethod := ""
		reqParam := ""

		// parse RPC requests
		reqs, isBatch, err := getRPCRequests(r)

		if err != nil || len(reqs) < 1 {
			// The error will be handled in `handler.ServeHTTP()` and printed with `printRPCErrorLog()`
			logger.Debug("failed to parse RPC request", "err", err, "len(reqs)", len(reqs))
		} else {
			reqMethod = reqs[0].method
			if isBatch {
				reqMethod += "_batch"
			}
			encoded, _ := json.Marshal(reqs[0].params)
			reqParam = string(encoded)
		}

		// new relic transaction name contains the first API method of the request
		resource := r.Method + " " + r.URL.String() + " " + reqMethod

		// duplicate writer
		dupW := &dupWriter{
			ResponseWriter: w,
			body:           bytes.NewBufferString(""),
		}

		spanOpts := []ddtrace.StartSpanOption{
			tracer.Tag("request.method", reqMethod),
			tracer.Tag("request.params", reqParam),
		}

		for _, header := range headers {
			header = strings.TrimSpace(header)
			header = strings.ToLower(header)
			key := fmt.Sprintf("http.%s", header)

			var tag tracer.StartSpanOption
			if header == "remote_addr" {
				tag = tracer.Tag(key, r.RemoteAddr)
			} else {
				tag = tracer.Tag(key, r.Header.Get(header))
			}
			spanOpts = append(spanOpts, tag)
		}

		httptrace.TraceAndServe(handler, dupW, r, &httptrace.ServeConfig{
			Service:     os.Getenv("DD_SERVICE"),
			Resource:    resource,
			QueryParams: true,
			SpanOpts:    spanOpts,
		})

		// print RPC error logs if errors exist
		if isBatch {
			var rpcReturns []interface{}
			if err := json.Unmarshal(dupW.body.Bytes(), &rpcReturns); err == nil {
				for i, rpcReturn := range rpcReturns {
					if data, err := json.Marshal(rpcReturn); err == nil {
						// TODO-Klaytn: make the log level configurable or separate module name of the logger
						printRPCErrorLog(data, reqs[i].method, r)
					}
				}
			}
		} else {
			// TODO-Klaytn: make the log level configurable or separate module name of the logger
			printRPCErrorLog(dupW.body.Bytes(), reqMethod, r)
		}
	})
}
