package provider

import "encoding/json"

// UnwrapDoubleEncoded handles dstack fields that may be JSON-encoded as either
// a raw object or a string containing JSON. Returns the inner bytes.
func UnwrapDoubleEncoded(data []byte) []byte {
	var str string
	if json.Unmarshal(data, &str) == nil {
		return []byte(str)
	}
	return data
}

// NormalizeUncompressedKey prepends the "04" uncompressed-point prefix to
// 128-char hex public keys that omit it.
func NormalizeUncompressedKey(key string) string {
	if len(key) == 128 {
		return "04" + key
	}
	return key
}
