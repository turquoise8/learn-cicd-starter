package auth

import (
	"net/http"
	"strings"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		headers        http.Header
		expectedKey    string
		expectedError  error
		errorSubstring string
	}{
		{
			name:           "Valid API Key",
			headers:        http.Header{"Authorization": []string{"ApiKey test-api-key"}},
			expectedKey:    "test-api-key",
			expectedError:  nil,
			errorSubstring: "",
		},
		{
			name:           "Missing Authorization Header",
			headers:        http.Header{},
			expectedKey:    "",
			expectedError:  ErrNoAuthHeaderIncluded,
			errorSubstring: "",
		},
		{
			name:           "Malformed Authorization Header - No ApiKey Prefix",
			headers:        http.Header{"Authorization": []string{"Bearer test-api-key"}},
			expectedKey:    "",
			expectedError:  nil,
			errorSubstring: "malformed authorization header",
		},
		{
			name:           "Malformed Authorization Header - No Space",
			headers:        http.Header{"Authorization": []string{"ApiKeytest-api-key"}},
			expectedKey:    "",
			expectedError:  nil,
			errorSubstring: "malformed authorization header",
		},
		{
			name:           "Malformed Authorization Header - Empty Value",
			headers:        http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey:    "",
			expectedError:  nil,
			errorSubstring: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			// Check the returned key
			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}

			// Check the error
			if tt.expectedError != nil {
				if err != tt.expectedError {
					t.Errorf("expected error %v, got %v", tt.expectedError, err)
				}
			} else if tt.errorSubstring != "" {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errorSubstring)
				} else if !strings.Contains(err.Error(), tt.errorSubstring) {
					t.Errorf("expected error containing %q, got %q", tt.errorSubstring, err.Error())
				}
			} else if err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}
