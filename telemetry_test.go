package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"
)

func TestLogLevels(t *testing.T) {
	for _, level := range []string{"", "info", "DEBUG", "warn", "error"} {
		t.Run(level, func(t *testing.T) {
			t.Setenv("LOG_LEVEL", level)
			var logs bytes.Buffer
			log, err := newLogger(&logs)
			if err != nil {
				t.Fatal(err)
			}
			g := &gateway{log: log}
			request := `{"method":"tools/list","params":{"private":"request-content"}}`
			handler := g.accessLog(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if string(body) != request {
					t.Fatal("request changed")
				}
				io.WriteString(w, `{"result":"response-content"}`)
			}))
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/fake/mcp", strings.NewReader(request)))
			out := logs.String()
			wantRequest := level == "" || level == "info" || level == "DEBUG"
			if strings.Contains(out, "msg=request") != wantRequest {
				t.Fatalf("unexpected access log: %s", out)
			}
			for _, body := range []string{"request_body", "response_body", "request-content", "response-content"} {
				if strings.Contains(out, body) != (level == "DEBUG") {
					t.Fatalf("level %q: unexpected %q in %s", level, body, out)
				}
			}
		})
	}
	t.Setenv("LOG_LEVEL", "typo")
	if _, err := newLogger(io.Discard); err == nil {
		t.Fatal("invalid level accepted")
	}
}

func TestTraceProxyPropagationAndPrivacy(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	t.Cleanup(func() { provider.Shutdown(context.Background()); otel.SetTracerProvider(previous) })
	const traceID = "0123456789abcdef0123456789abcdef"
	var upstreamTrace string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamTrace = r.Header.Get("Traceparent")
		if r.Header.Get("Authorization") != "Bearer upstream-secret" {
			t.Error("upstream authentication lost")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		io.WriteString(w, "data: {\"result\":\"private-reply\"}\n\n")
	}))
	defer up.Close()
	g, srv := newTestGateway(t, up.URL, "upstream-secret", strings.Repeat("p", 40))
	defer srv.Close()
	// Use a unique cache key to isolate this upstream from the OAuth flow tests.
	upstreamConfig := g.upstreams["fake"]
	upstreamConfig.Name = "trace-test"
	g.upstreams = map[string]*upstream{"trace-test": upstreamConfig}
	g.tokens[sha("client-secret")] = accessToken{Resource: "trace-test", Expires: time.Now().Add(time.Hour)}
	var logs bytes.Buffer
	g.log = slog.New(slog.NewJSONHandler(&logs, nil))
	req, _ := http.NewRequest("POST", srv.URL+"/trace-test/mcp?code=private-query", strings.NewReader(`{"method":"tools/list","params":{"private":"private-request"}}`))
	req.Header.Set("Authorization", "Bearer client-secret")
	req.Header.Set("Traceparent", "00-"+traceID+"-0123456789abcdef-01")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || !bytes.Contains(body, []byte("private-reply")) {
		t.Fatalf("proxy failed: %d %s %v", resp.StatusCode, body, err)
	}
	spans := exporter.GetSpans()
	if len(spans) != 2 {
		t.Fatalf("want server and client spans, got %d", len(spans))
	}
	var serverID, clientID trace.SpanID
	for _, span := range spans {
		if span.SpanContext.TraceID().String() != traceID {
			t.Fatal("trace ID not propagated")
		}
		if span.SpanKind == trace.SpanKindServer {
			serverID = span.SpanContext.SpanID()
			if span.Name != "POST /{name}/mcp" {
				t.Errorf("route missing: %s", span.Name)
			}
		} else if span.SpanKind == trace.SpanKindClient {
			clientID = span.SpanContext.SpanID()
		}
		data, _ := json.Marshal(span.Attributes)
		for _, secret := range []string{"private-query", "private-request", "private-reply", "client-secret", "upstream-secret"} {
			if bytes.Contains(data, []byte(secret)) {
				t.Fatalf("trace leaked %s", secret)
			}
		}
	}
	for _, span := range spans {
		if span.SpanKind == trace.SpanKindClient && span.Parent.SpanID() != serverID {
			t.Fatal("client span is not a child of server span")
		}
	}
	if upstreamTrace != "00-"+traceID+"-"+clientID.String()+"-01" {
		t.Fatalf("bad upstream trace context: %s", upstreamTrace)
	}
	if !strings.Contains(logs.String(), traceID) || strings.Contains(logs.String(), "private-reply") {
		t.Fatalf("incorrect log correlation: %s", logs.String())
	}
	before := len(exporter.GetSpans())
	health, err := srv.Client().Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, health.Body)
	health.Body.Close()
	if len(exporter.GetSpans()) != before {
		t.Fatal("healthcheck created traces")
	}
}

func TestOTLPExportAndShutdown(t *testing.T) {
	received := make(chan *collectortrace.ExportTraceServiceRequest, 1)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/traces" || r.Header.Get("Content-Type") != "application/x-protobuf" {
			t.Error("incorrect OTLP request")
		}
		body, _ := io.ReadAll(r.Body)
		var data collectortrace.ExportTraceServiceRequest
		if err := proto.Unmarshal(body, &data); err != nil {
			t.Error(err)
		}
		received <- &data
		w.Header().Set("Content-Type", "application/x-protobuf")
	}))
	defer collector.Close()
	for _, key := range []string{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "OTEL_EXPORTER_OTLP_HEADERS", "OTEL_EXPORTER_OTLP_TRACES_HEADERS", "OTEL_RESOURCE_ATTRIBUTES"} {
		t.Setenv(key, "")
	}
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", collector.URL)
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
	t.Setenv("OTEL_SDK_DISABLED", "false")
	t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
	t.Setenv("OTEL_TRACES_SAMPLER", "always_on")
	t.Setenv("OTEL_SERVICE_NAME", "gateway-export-test")
	previous := otel.GetTracerProvider()
	defer otel.SetTracerProvider(previous)
	shutdown, err := initTracing(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, span := otel.Tracer("test").Start(context.Background(), "export-check")
	span.End()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case data := <-received:
		if len(data.ResourceSpans) != 1 {
			t.Fatal("trace missing")
		}
		found := false
		for _, attr := range data.ResourceSpans[0].Resource.Attributes {
			if attr.Key == "service.name" && attr.Value.GetStringValue() == "gateway-export-test" {
				found = true
			}
		}
		if !found {
			t.Fatal("configured service.name missing")
		}
	case <-ctx.Done():
		t.Fatal("shutdown did not export the span")
	}
}
