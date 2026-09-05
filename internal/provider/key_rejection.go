package provider

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/13rac1/teep/internal/jsonstrict"
)

// KeyRejection inspects only a documented pre-inference rejection envelope.
// It restores the bounded body for ordinary error handling and never logs it.
func KeyRejection(resp *http.Response, name, path string) (bool, error) {
	if resp == nil {
		return false, nil
	}
	isTinfoil := name == "tinfoil_v3_cloud" || name == "tinfoil_v3_direct"
	isNear := name == "neardirect" || name == "nearcloud"
	candidate := isTinfoil && resp.StatusCode == http.StatusUnprocessableEntity || isNear && resp.StatusCode == http.StatusBadRequest && path == "/v1/chat/completions"
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
	return nearKeyRejection(body, name)
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

func nearKeyRejection(body []byte, name string) (bool, error) {
	var envelope struct {
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
			Code    any    `json:"code,omitempty"`
			Param   any    `json:"param,omitempty"`
		} `json:"error"`
	}
	unknown, missing, err := jsonstrict.Unmarshal(body, &envelope)
	if err != nil || len(unknown) > 0 || len(missing) > 0 {
		return false, errors.New("malformed NEAR error response")
	}
	expected := "bad_request"
	if name == "nearcloud" {
		expected = "invalid_request_error"
	}
	return envelope.Error.Type == expected && envelope.Error.Message == "Decryption failed", nil
}
