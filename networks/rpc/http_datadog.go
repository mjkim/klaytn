package rpc

import (
	"bytes"
	"encoding/json"
	httptrace "gopkg.in/DataDog/dd-trace-go.v1/contrib/net/http"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
	"net/http"
	"os"
)

func newDatadogTracer() bool {
	appName := os.Getenv("DD_TRACE")
	if appName == "" {
		return false
	}

	rules := []tracer.SamplingRule{
		// sample 100.00% of traces for all spans
		tracer.RateRule(1.0000),
	}
	tracer.Start(tracer.WithSamplingRules(rules))
	return true
}

func newDatadogHTTPHandler(handler http.Handler) http.Handler {
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

		httptrace.TraceAndServe(handler, dupW, r, &httptrace.ServeConfig{
			Service:     os.Getenv("DD_SERVICE"),
			Resource:    resource,
			QueryParams: true,
			SpanOpts: []ddtrace.StartSpanOption{
				tracer.Tag("http.remote_addr", r.RemoteAddr),
				tracer.Tag("http.origin", r.Header.Get("ORIGIN")),
				tracer.Tag("http.host", r.Header.Get("HOST")),
				tracer.Tag("http.content-type", r.Header.Get("Content-Type")),
				tracer.Tag("http.user-agent", r.Header.Get("User-Agent")),
				tracer.Tag("http.x-forwarded-for", r.Header.Get("X-Forwarded-For")),
				tracer.Tag("request.method", reqMethod),
				tracer.Tag("request.params", reqParam),
			},
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
