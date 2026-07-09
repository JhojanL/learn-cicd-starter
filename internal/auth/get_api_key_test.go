package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		// name      string
		headers   http.Header
		wantKey   string
		wantError error
	}{
		{
			name: "Valid API Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey valid_api_key"},
			},
			wantKey:   "valid_api_key",
			wantError: nil,
		},
		{
			name: "No Authorization Header",
			headers: http.Header{
				"Content-Type": []string{"application/json"},
			},
			wantKey:   "",
			wantError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header",
			headers: http.Header{
				"Authorization": []string{"Bearer some_token"},
			},
			wantKey:   "",
			wantError: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tt.headers)

			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey(%v): got key %q, want %q", tt.headers, gotKey, tt.wantKey)
			}

			// Validate mismatch in error presence
			if (gotErr == nil) != (tt.wantError == nil) {
				t.Fatalf("GetAPIKey(%v): got error %v, want %v", tt.headers, gotErr, tt.wantError)
			}

			// Validate error content matching
			if gotErr != nil && gotErr.Error() != tt.wantError.Error() {
				t.Errorf("GetAPIKey(%v): got error message %q, want %q", tt.headers, gotErr.Error(), tt.wantError.Error())
			}
		})
	}
}
