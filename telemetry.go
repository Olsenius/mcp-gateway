package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

func newLogger(w io.Writer) (*slog.Logger, error) {
	var level slog.Level
	switch strings.ToLower(env("LOG_LEVEL", "info")) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return nil, fmt.Errorf("LOG_LEVEL must be debug, info, warn or error")
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})), nil
}

// Export is opt-in: without an endpoint the API remains a no-op. The HTTP
// exporter reads standard OTEL endpoint, TLS, header and timeout settings.
func initTracing(ctx context.Context) (func(context.Context) error, error) {
	noop := func(context.Context) error { return nil }
	disabled, err := strconv.ParseBool(env("OTEL_SDK_DISABLED", "false"))
	if err != nil {
		return nil, fmt.Errorf("OTEL_SDK_DISABLED must be a boolean")
	}
	if disabled || env("OTEL_TRACES_EXPORTER", "") == "none" ||
		(env("OTEL_EXPORTER_OTLP_ENDPOINT", "") == "" && env("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "") == "") {
		return noop, nil
	}
	if exporter := env("OTEL_TRACES_EXPORTER", "otlp"); exporter != "otlp" {
		return nil, fmt.Errorf("OTEL_TRACES_EXPORTER must be otlp or none")
	}
	if protocol := env("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", env("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")); protocol != "http/protobuf" {
		return nil, fmt.Errorf("OTLP tracing supports http/protobuf; use an HTTP endpoint (normally port 4318)")
	}
	res, err := resource.New(ctx, resource.WithFromEnv(), resource.WithTelemetrySDK())
	if err != nil {
		return nil, fmt.Errorf("trace resource: %w", err)
	}
	// Environment resource attributes override defaults (including service.name).
	res, err = resource.Merge(resource.NewSchemaless(
		attribute.String("service.name", "mcp-gateway"), attribute.String("service.version", version)), res)
	if err != nil {
		return nil, err
	}
	exporter, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("trace exporter: %w", err)
	}
	provider := sdktrace.NewTracerProvider(sdktrace.WithResource(res), sdktrace.WithBatcher(exporter))
	otel.SetTracerProvider(provider)
	return provider.Shutdown, nil
}

// Trace only explicitly selected metadata: OAuth query strings, headers and
// request/response contents must never be added to spans.
func traceHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		parent := propagation.TraceContext{}.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, span := otel.Tracer("mcp-gateway").Start(parent, r.Method, trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(attribute.String("http.request.method", r.Method)))
		defer span.End()
		sw := &statusWriter{ResponseWriter: w}
		req := r.WithContext(ctx)
		next.ServeHTTP(sw, req)
		setRouteSpan(req)
		if sw.code == 0 {
			sw.code = http.StatusOK
		}
		span.SetAttributes(attribute.Int("http.response.status_code", sw.code))
		if sw.code >= 500 {
			span.SetStatus(codes.Error, http.StatusText(sw.code))
		}
	})
}

func setRouteSpan(r *http.Request) {
	if r.Pattern == "" {
		return
	}
	span := trace.SpanFromContext(r.Context())
	route := r.Pattern
	if _, path, ok := strings.Cut(route, " "); ok {
		route = path
	}
	span.SetName(r.Method + " " + route)
	span.SetAttributes(attribute.String("http.route", route))
}

type tracingTransport struct{ base http.RoundTripper }

func (t tracingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	ctx, span := otel.Tracer("mcp-gateway").Start(r.Context(), "upstream "+r.Method, trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attribute.String("http.request.method", r.Method), attribute.String("server.address", r.URL.Hostname()), attribute.String("url.path", r.URL.Path)))
	req := r.Clone(ctx)
	propagation.TraceContext{}.Inject(ctx, propagation.HeaderCarrier(req.Header))
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(req)
	if err != nil {
		span.SetAttributes(attribute.String("error.type", fmt.Sprintf("%T", err)))
		span.SetStatus(codes.Error, "upstream request failed")
		span.End()
		return resp, err
	}
	span.SetAttributes(attribute.Int("http.response.status_code", resp.StatusCode))
	if resp.StatusCode >= 400 {
		span.SetStatus(codes.Error, http.StatusText(resp.StatusCode))
	}
	if resp.Body == nil {
		span.End()
	} else {
		resp.Body = &spanBody{ReadCloser: resp.Body, span: span}
	}
	return resp, nil
}

type spanBody struct {
	io.ReadCloser
	span trace.Span
	once sync.Once
}

func (b *spanBody) finish(err error) {
	b.once.Do(func() {
		if err != nil && err != io.EOF {
			b.span.SetAttributes(attribute.String("error.type", fmt.Sprintf("%T", err)))
			b.span.SetStatus(codes.Error, "upstream response failed")
		}
		b.span.End()
	})
}
func (b *spanBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.finish(err)
	}
	return n, err
}
func (b *spanBody) Close() error {
	err := b.ReadCloser.Close()
	b.finish(err)
	return err
}
