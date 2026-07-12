package netutil

import (
	"net/url"
	"testing"
)

func TestValidateServerTransport(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		wantErr bool
	}{
		{name: "https external", rawURL: "https://server.local", wantErr: false},
		{name: "http localhost", rawURL: "http://localhost:8080", wantErr: false},
		{name: "http ipv4 loopback", rawURL: "http://127.0.0.1:8080", wantErr: false},
		{name: "http ipv6 loopback", rawURL: "http://[::1]:8080", wantErr: false},
		{name: "http external", rawURL: "http://server.local", wantErr: true},
		{name: "unsupported scheme", rawURL: "ftp://localhost:8080", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("Parse returned error: %v", err)
			}

			err = ValidateServerTransport(parsed)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateServerTransport error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateServerTransportRejectsNilURL(t *testing.T) {
	if err := ValidateServerTransport(nil); err == nil {
		t.Fatal("ValidateServerTransport returned nil error for nil URL")
	}
}
