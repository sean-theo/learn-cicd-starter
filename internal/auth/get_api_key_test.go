package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		wantAPIKey    string
		wantErrExpect error
		expectErr     bool
	}{
		{
			name:          "Valid ApiKey header",
			headers:       http.Header{"Authorization": []string{"ApiKey secret-12345"}},
			wantAPIKey:    "secret-12345",
			wantErrExpect: nil,
			expectErr:     false,
		},
		{
			name:          "Missing Authorization header",
			headers:       http.Header{},
			wantAPIKey:    "",
			wantErrExpect: ErrNoAuthHeaderIncluded,
			expectErr:     true,
		},
		{
			name:          "Malformed header - missing ApiKey prefix",
			headers:       http.Header{"Authorization": []string{"Bearer secret-12345"}},
			wantAPIKey:    "",
			wantErrExpect: errors.New("malformed authorization header"),
			expectErr:     true,
		},
		{
			name:          "Malformed header - no key provided",
			headers:       http.Header{"Authorization": []string{"ApiKey"}},
			wantAPIKey:    "",
			wantErrExpect: errors.New("malformed authorization header"),
			expectErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)

			if (err != nil) != tt.expectErr {
				t.Fatalf("GetAPIKey() error = %v, expectErr %v", err, tt.expectErr)
			}

			if got != tt.wantAPIKey {
				t.Errorf("GetAPIKey() got = %v, want %v", got, tt.wantAPIKey)
			}
		})
	}
}
