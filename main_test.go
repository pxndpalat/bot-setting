package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLineWebhookSkipsGroupEventsWithoutBotMention(t *testing.T) {
	upstreamHits := 0
	app := testApp(roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		upstreamHits++
		return testUpstreamResponse(http.StatusAccepted, "", nil), nil
	}))
	body := `{"events":[{"source":{"type":"group"},"message":{"text":"hello"}}]}`
	request := signedLineRequest(t, body, "test-secret")
	response := httptest.NewRecorder()

	app.handleLineWebhook(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, response.Code)
	}
	if strings.TrimSpace(response.Body.String()) != "ok" {
		t.Fatalf("expected ok response, got %q", response.Body.String())
	}
	if upstreamHits != 0 {
		t.Fatal("expected upstream not to be called")
	}
}

func TestLineWebhookForwardsWhenBotIsMentioned(t *testing.T) {
	upstreamHits := 0
	app := testApp(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		upstreamHits++
		if r.Header.Get("x-line-signature") == "" {
			t.Error("expected LINE signature header to be forwarded")
		}
		return testUpstreamResponse(http.StatusAccepted, "forwarded", http.Header{
			"X-Upstream": []string{"hermes"},
		}), nil
	}))

	body := `{"events":[{"source":{"type":"group"},"message":{"mention":{"mentionees":[{"isSelf":true}]}}}]}`
	request := signedLineRequest(t, body, "test-secret")
	response := httptest.NewRecorder()

	app.handleLineWebhook(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf("expected status %d, got %d", http.StatusAccepted, response.Code)
	}
	if strings.TrimSpace(response.Body.String()) != "forwarded" {
		t.Fatalf("expected upstream body, got %q", response.Body.String())
	}
	if response.Header().Get("X-Upstream") != "hermes" {
		t.Fatalf("expected upstream header to be relayed")
	}
	if upstreamHits != 1 {
		t.Fatalf("expected upstream to be called once, got %d", upstreamHits)
	}
}

func TestLineWebhookRejectsInvalidSignature(t *testing.T) {
	app := testApp(roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		t.Fatal("expected upstream not to be called")
		return nil, nil
	}))
	request := httptest.NewRequest(http.MethodPost, "/webhook/line", strings.NewReader(`{"events":[]}`))
	request.Header.Set("x-line-signature", "invalid")
	response := httptest.NewRecorder()

	app.handleLineWebhook(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, response.Code)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func testApp(transport http.RoundTripper) *app {
	return &app{
		config: appConfig{
			lineChannelSecret:    "test-secret",
			lineWebhookTargetURL: "http://hermes.test/line/webhook",
		},
		client: &http.Client{
			Timeout:   time.Second,
			Transport: transport,
		},
	}
}

func testUpstreamResponse(statusCode int, body string, header http.Header) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func signedLineRequest(t *testing.T, body string, secret string) *http.Request {
	t.Helper()

	request := httptest.NewRequest(http.MethodPost, "/webhook/line", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("x-line-signature", signBody(body, secret))

	return request
}

func signBody(body string, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(body))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
