package database

import (
	"encoding/base64"
	"net/http"
	"strings"
)

/*
*

	It checks image signatures to identify supported raster formats.
	@param content - The byte slice containing the logo data.
	@returns string - The detected MIME type ("image/png", "image/jpeg", "image/webp") or an empty string if unsupported.
*/
func detectLogoMime(content []byte) string {
	detected := strings.ToLower(http.DetectContentType(content))
	if strings.HasPrefix(detected, "image/png") {
		return "image/png"
	}
	if strings.HasPrefix(detected, "image/jpeg") {
		return "image/jpeg"
	}
	if strings.HasPrefix(detected, "image/webp") {
		return "image/webp"
	}
	return ""
}

/*
*

	decodeBase64Logo attempts to decode a base64-encoded logo string, trying both standard and URL-safe encodings.
	It also normalizes the input by removing common whitespace characters before decoding.
	@param payload - The base64-encoded string representing the logo.
	@returns []byte - The decoded byte slice of the logo, or an error if decoding fails.
*/
func decodeBase64Logo(payload string) ([]byte, error) {
	normalized := strings.NewReplacer("\n", "", "\r", "", "\t", "", " ", "").Replace(payload)
	if decoded, err := base64.StdEncoding.DecodeString(normalized); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(normalized); err == nil {
		return decoded, nil
	}
	return nil, base64.CorruptInputError(0)
}

/*
*

	normalizeCustomLogo processes a raw input string for a custom logo, validating and converting it into a standardized data URI format if valid.
	It supports both direct base64 strings and data URIs, ensuring the content is a valid raster image before encoding it back to a data URI.
	@param raw - The raw input string for the custom logo, which may be a base64 string or a data URI.
	@returns string - A normalized data URI string for the logo if valid, or an empty string if the input is invalid or unsupported.
*/
func normalizeCustomLogo(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(raw), "data:") {
		header, payload, ok := strings.Cut(raw, ",")
		if !ok || payload == "" {
			return ""
		}
		header = strings.ToLower(strings.TrimSpace(header))
		if !strings.Contains(header, ";base64") {
			return ""
		}
		decoded, err := decodeBase64Logo(payload)
		if err != nil || len(decoded) == 0 {
			return ""
		}
		mime := detectLogoMime(decoded)
		if mime == "" {
			return ""
		}
		return "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(decoded)
	}
	decoded, err := decodeBase64Logo(raw)
	if err != nil || len(decoded) == 0 {
		return ""
	}
	mime := detectLogoMime(decoded)
	if mime == "" {
		return ""
	}
	return "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(decoded)
}
