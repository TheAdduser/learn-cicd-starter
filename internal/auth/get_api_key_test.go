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
		expectedKey   string
		expectedError error
	}{
		{
			name: "Proper ApiKey Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey secret-key-123"},
			},
			expectedKey:   "secret-key-123",
			expectedError: nil,
		},
		{
			name:          "No Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Wrong Format - No Space",
			headers: http.Header{
				"Authorization": []string{"ApiKey-without-space"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Wrong Prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer jakis-token"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if key != tt.expectedKey {
				t.Errorf("GetAPIKey() key = %v, want %v", key, tt.expectedKey)
			}

			if tt.expectedError != nil {
				if err == nil || err.Error() != tt.expectedError.Error() {
					t.Errorf("GetAPIKey() error = %v, want %v", err, tt.expectedError)
				}
			} else if err != nil {
				t.Errorf("GetAPIKey() unexpected error = %v", err)
			}
		})
	}
}