package provider

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/13rac1/teep/internal/jsonstrict"
)

// KeyRejection inspects only a documented pre-inference rejection envelope.
// It restores the bounded body for ordinary error handling and never logs it.
func KeyRejection(resp *http.Response, name, path string) (bool, error) {
	if name != "nearcloud" && name != "neardirect" && name != "tinfoil_v3_cloud" && name != "tinfoil_v3_direct" {
		return false, errors.New("unsupported key rejection provider")
	}
	if resp == nil {
		return false, nil
	}
	isTinfoil := name == "tinfoil_v3_cloud" || name == "tinfoil_v3_direct"
	nearType, isNear := nearRejectionType(name, path)
	candidate := isTinfoil && resp.StatusCode == http.StatusUnprocessableEntity || isNear && resp.StatusCode == http.StatusBadRequest
	if !candidate || len(resp.Header.Values("Ehbp-Response-Nonce")) != 0 {
		return false, nil
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return false, errors.New("invalid rejection content type")
	}
	if isTinfoil && media != "application/problem+json" {
		return false, nil
	}
	if isNear && media != "application/json" {
		return false, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, (64<<10)+1))
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return false, errors.New("read key rejection response")
	}
	if len(body) > 64<<10 {
		return false, errors.New("key rejection response exceeds limit")
	}
	if err := jsonstrict.ValidateUniqueFields(body); err != nil {
		return false, errors.New("malformed key rejection response")
	}
	if isTinfoil {
		return ehbpKeyRejection(body)
	}
	return nearKeyRejection(body, nearType)
}

func ehbpKeyRejection(body []byte) (bool, error) {
	var problem struct {
		Type     string `json:"type"`
		Title    string `json:"title,omitempty"`
		Status   int    `json:"status,omitempty"`
		Detail   string `json:"detail,omitempty"`
		Instance string `json:"instance,omitempty"`
	}
	unknown, missing, err := jsonstrict.Unmarshal(body, &problem)
	if err != nil || len(unknown) > 0 || len(missing) > 0 {
		return false, errors.New("malformed EHBP problem response")
	}
	return problem.Type == "urn:ietf:params:ehbp:error:key-config", nil
}

func nearKeyRejection(body []byte, expected string) (bool, error) {
	var envelope struct {
		Error json.RawMessage `json:"error"`
	}
	unknown, missing, err := jsonstrict.Unmarshal(body, &envelope)
	if err != nil || len(unknown) > 0 || len(missing) > 0 {
		return false, errors.New("malformed NEAR error response")
	}
	// jsonstrict reports fields at one object level. Validate the nested
	// protocol object separately before treating the response as retryable.
	var detail struct {
		Type    *string `json:"type"`
		Message *string `json:"message"`
		Code    any     `json:"code,omitempty"`
		Param   any     `json:"param,omitempty"`
	}
	unknown, missing, err = jsonstrict.Unmarshal(envelope.Error, &detail)
	if err != nil || len(unknown) > 0 || len(missing) > 0 || detail.Type == nil || detail.Message == nil {
		return false, errors.New("malformed NEAR error detail")
	}
	return *detail.Type == expected && *detail.Message == "Decryption failed", nil
}

func nearRejectionType(name, path string) (string, bool) {
	if name == "neardirect" {
		switch path {
		case "/v1/chat/completions", "/v1/embeddings", "/v1/images/generations", "/v1/rerank", "/v1/score":
			return "bad_request", true
		}
	}
	if name == "nearcloud" {
		switch path {
		case "/v1/chat/completions":
			return "invalid_request_error", true
		case "/v1/embeddings":
			return "provider_error", true
		}
	}
	return "", false
}
