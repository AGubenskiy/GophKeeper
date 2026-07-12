package serverapp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AGubenskiy/GophKeeper/internal/buildinfo"
	"github.com/AGubenskiy/GophKeeper/internal/config"
)

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"version"}, &stdout, &stderr, buildinfo.New("1.0.0", "2026-07-02", "abc123"))

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Build version: 1.0.0") {
		t.Fatalf("stdout = %q, want build version", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunVersionRejectsArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"version", "extra"}, &stdout, &stderr, buildinfo.New("", "", ""))

	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "accepts no arguments") {
		t.Fatalf("stderr = %q, want argument error", stderr.String())
	}
}

func TestRunHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"help"}, &stdout, &stderr, buildinfo.New("", "", ""))

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Fatalf("stdout = %q, want usage", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunRejectsInvalidLogLevel(t *testing.T) {
	t.Setenv(config.EnvServerLogLevel, "verbose")
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), nil, &stdout, &stderr, buildinfo.New("", "", ""))

	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "configure logger") {
		t.Fatalf("stderr = %q, want logger configuration error", stderr.String())
	}
}

func TestRunRejectsUnexpectedArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"unexpected"}, &stdout, &stderr, buildinfo.New("", "", ""))

	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "unexpected argument") {
		t.Fatalf("stderr = %q, want unexpected argument error", stderr.String())
	}
}

func TestRunRejectsDatabaseWithoutAccessSecret(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(
		context.Background(),
		[]string{"--database-dsn", "postgres://localhost/gophkeeper"},
		&stdout,
		&stderr,
		buildinfo.New("", "", ""),
	)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "access token secret") {
		t.Fatalf("stderr = %q, want access token secret error", stderr.String())
	}
}

func TestNewHandlerHealth(t *testing.T) {
	handler := NewHandler(buildinfo.New("", "", ""))
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", response.Code, http.StatusOK)
	}

	var body map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("status = %q, want ok", body["status"])
	}
}

func TestNewHandlerAuthUnavailable(t *testing.T) {
	handler := NewHandler(buildinfo.New("", "", ""))
	request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/params?login=alice", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status code = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if response.Header().Get("X-Request-ID") == "" {
		t.Fatal("X-Request-ID response header is empty")
	}
}

func TestNewHandlerVersion(t *testing.T) {
	handler := NewHandler(buildinfo.New("1.0.0", "2026-07-02", "abc123"))
	request := httptest.NewRequest(http.MethodGet, "/version", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", response.Code, http.StatusOK)
	}

	var body buildinfo.Info
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Version != "1.0.0" || body.Date != "2026-07-02" || body.Commit != "abc123" {
		t.Fatalf("version response = %+v, want injected build info", body)
	}
}

func TestNewHandlerRejectsUnsupportedMethod(t *testing.T) {
	handler := NewHandler(buildinfo.New("", "", ""))
	request := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status code = %d, want %d", response.Code, http.StatusMethodNotAllowed)
	}
	if response.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("Allow header = %q, want GET", response.Header().Get("Allow"))
	}
}

func TestServeRejectsNilListener(t *testing.T) {
	cfg := config.DefaultServer()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	app := New(cfg, log, buildinfo.New("", "", ""))

	if err := app.Serve(context.Background(), nil); err == nil {
		t.Fatal("Serve returned nil error, want nil listener error")
	}
}

func TestApplicationServeStartsAndStops(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	cfg := config.DefaultServer()
	cfg.Address = listener.Addr().String()
	cfg.ShutdownTimeout = time.Second
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	app := New(cfg, log, buildinfo.New("test", "2026-07-02", "abc123"))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- app.Serve(ctx, listener)
	}()

	client := http.Client{Timeout: 100 * time.Millisecond}
	url := "http://" + listener.Addr().String() + "/healthz"
	deadline := time.After(2 * time.Second)

	for {
		response, err := client.Get(url)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("status code = %d, want %d", response.StatusCode, http.StatusOK)
			}
			break
		}

		select {
		case <-deadline:
			cancel()
			t.Fatalf("server did not become ready: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not stop after context cancellation")
	}
}

func TestApplicationServeWithTLS(t *testing.T) {
	certFile, keyFile := writeTestCertificate(t)
	tlsConfig, err := serverTLSConfig(certFile, keyFile)
	if err != nil {
		t.Fatalf("serverTLSConfig returned error: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tlsListener := tls.NewListener(listener, tlsConfig)

	cfg := config.DefaultServer()
	cfg.Address = listener.Addr().String()
	cfg.ShutdownTimeout = time.Second
	cfg.TLSCertFile = certFile
	cfg.TLSKeyFile = keyFile
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	app := New(cfg, log, buildinfo.New("test", "2026-07-02", "abc123"))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- app.Serve(ctx, tlsListener)
	}()

	client := http.Client{
		Timeout: 100 * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	url := "https://" + listener.Addr().String() + "/healthz"
	deadline := time.After(2 * time.Second)

	for {
		response, err := client.Get(url)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("status code = %d, want %d", response.StatusCode, http.StatusOK)
			}
			break
		}

		select {
		case <-deadline:
			cancel()
			t.Fatalf("TLS server did not become ready: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not stop after context cancellation")
	}
}

func writeTestCertificate(t *testing.T) (string, string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate returned error: %v", err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err = os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("WriteFile cert returned error: %v", err)
	}
	if err = os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("WriteFile key returned error: %v", err)
	}
	return certFile, keyFile
}
