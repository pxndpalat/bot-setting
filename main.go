package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultPort             = 3000
	defaultLineWebhookURL   = "http://hermes:8646/line/webhook"
	maxLineWebhookBodyBytes = 100 * 1024
)

var hopByHopHeaders = map[string]struct{}{
	"accept-encoding":     {},
	"connection":          {},
	"content-length":      {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"te":                  {},
	"trailer":             {},
	"transfer-encoding":   {},
	"upgrade":             {},
	"host":                {},
}

type appConfig struct {
	port                 int
	lineChannelSecret    string
	lineWebhookTargetURL string
}

type app struct {
	config appConfig
	client *http.Client
}

type lineWebhookPayload struct {
	Events []lineEvent `json:"events"`
}

type lineEvent struct {
	Source  lineEventSource  `json:"source"`
	Message lineEventMessage `json:"message"`
}

type lineEventSource struct {
	Type string `json:"type"`
}

type lineEventMessage struct {
	Mention lineMention `json:"mention"`
}

type lineMention struct {
	Mentionees []lineMentionee `json:"mentionees"`
}

type lineMentionee struct {
	IsSelf bool `json:"isSelf"`
}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
	bytesSent  int
}

type bodyLogReadCloser struct {
	source io.ReadCloser
	buffer *bytes.Buffer
}

func main() {
	config, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	app := &app{
		config: config,
		client: &http.Client{Timeout: 30 * time.Second},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", app.handleHealth)
	mux.HandleFunc("POST /webhook/line", app.handleLineWebhook)

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", config.port),
		Handler:           logRequest(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf(
		"LINE webhook middleware listening on port %d; forwarding to %s",
		config.port,
		config.lineWebhookTargetURL,
	)

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func loadConfig() (appConfig, error) {
	port := defaultPort
	if portValue := strings.TrimSpace(os.Getenv("PORT")); portValue != "" {
		parsedPort, err := strconv.Atoi(portValue)
		if err != nil || parsedPort <= 0 {
			return appConfig{}, fmt.Errorf("invalid PORT %q", portValue)
		}
		port = parsedPort
	}

	lineWebhookTargetURL := strings.TrimSpace(os.Getenv("LINE_WEBHOOK_TARGET_URL"))
	if lineWebhookTargetURL == "" {
		lineWebhookTargetURL = defaultLineWebhookURL
	}

	return appConfig{
		port:                 port,
		lineChannelSecret:    os.Getenv("LINE_CHANNEL_SECRET"),
		lineWebhookTargetURL: lineWebhookTargetURL,
	}, nil
}

func (a *app) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *app) handleLineWebhook(w http.ResponseWriter, r *http.Request) {
	if a.config.lineChannelSecret == "" {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "LINE_CHANNEL_SECRET is not configured",
		})
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxLineWebhookBodyBytes))
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{
			"error": "Request body is too large",
		})
		return
	}

	signature := r.Header.Get("x-line-signature")
	if signature == "" || !isValidLineSignature(body, signature, a.config.lineChannelSecret) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "Invalid LINE signature",
		})
		return
	}

	var payload lineWebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "Invalid JSON payload",
		})
		return
	}

	if hasEventSourceGroup(payload.Events) && !hasBotMention(payload.Events) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	}

	upstreamResponse, err := a.forwardLineWebhook(r.Context(), r, body)
	if err != nil {
		log.Printf("failed to forward LINE webhook: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Internal server error",
		})
		return
	}
	defer upstreamResponse.Body.Close()

	relayResponse(w, upstreamResponse)
}

func isValidLineSignature(body []byte, signature string, secret string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expected), []byte(signature))
}

func hasBotMention(events []lineEvent) bool {
	for _, event := range events {
		for _, mentionee := range event.Message.Mention.Mentionees {
			if mentionee.IsSelf {
				return true
			}
		}
	}

	return false
}

func hasEventSourceGroup(events []lineEvent) bool {
	for _, event := range events {
		if event.Source.Type == "group" {
			return true
		}
	}

	return false
}

func (a *app) forwardLineWebhook(ctx context.Context, original *http.Request, body []byte) (*http.Response, error) {
	request, err := http.NewRequestWithContext(
		ctx,
		original.Method,
		a.config.lineWebhookTargetURL,
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}

	copyForwardHeaders(request.Header, original.Header)

	return a.client.Do(request)
}

func copyForwardHeaders(destination http.Header, source http.Header) {
	for name, values := range source {
		if _, skip := hopByHopHeaders[strings.ToLower(name)]; skip {
			continue
		}
		destination.Set(name, strings.Join(values, ", "))
	}
}

func relayResponse(w http.ResponseWriter, upstreamResponse *http.Response) {
	copyResponseHeaders(w.Header(), upstreamResponse.Header)
	w.WriteHeader(upstreamResponse.StatusCode)

	if _, err := io.Copy(w, upstreamResponse.Body); err != nil {
		log.Printf("failed to relay upstream response body: %v", err)
	}
}

func copyResponseHeaders(destination http.Header, source http.Header) {
	blockedHeaders := map[string]struct{}{
		"connection":        {},
		"content-encoding":  {},
		"transfer-encoding": {},
	}

	for name, values := range source {
		if _, skip := blockedHeaders[strings.ToLower(name)]; skip {
			continue
		}
		for _, value := range values {
			destination.Add(name, value)
		}
	}
}

func writeJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("failed to write JSON response: %v", err)
	}
}

func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startedAt := time.Now()
		bodyBuffer := &bytes.Buffer{}
		if r.Body != nil {
			r.Body = &bodyLogReadCloser{
				source: r.Body,
				buffer: bodyBuffer,
			}
		}

		responseWriter := &loggingResponseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(responseWriter, r)

		body := "-"
		if bodyBuffer.Len() > 0 || r.Method != http.MethodGet {
			body = bodyBuffer.String()
		}

		log.Printf(
			"%s %s %d %.1fms %db body=%s",
			r.Method,
			r.URL.RequestURI(),
			responseWriter.statusCode,
			float64(time.Since(startedAt).Microseconds())/1000,
			responseWriter.bytesSent,
			body,
		)
	})
}

func (w *loggingResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *loggingResponseWriter) Write(body []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}

	bytesSent, err := w.ResponseWriter.Write(body)
	w.bytesSent += bytesSent

	return bytesSent, err
}

func (r *bodyLogReadCloser) Read(p []byte) (int, error) {
	bytesRead, err := r.source.Read(p)
	if bytesRead > 0 {
		_, _ = r.buffer.Write(p[:bytesRead])
	}

	return bytesRead, err
}

func (r *bodyLogReadCloser) Close() error {
	return r.source.Close()
}
