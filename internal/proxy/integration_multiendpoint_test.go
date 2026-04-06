package proxy_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"testing"
)

// --------------------------------------------------------------------------
// NearDirect VL (vision-language) integration
// --------------------------------------------------------------------------

func nearDirectVLModel() string {
	if m := os.Getenv("NEARAI_VL_MODEL"); m != "" {
		return m
	}
	return "Qwen/Qwen3-VL-30B-A3B-Instruct"
}

// testPNG returns a base64-encoded 8x8 solid red PNG image.
func testPNG() string {
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	red := color.RGBA{R: 255, A: 255}
	for y := range 8 {
		for x := range 8 {
			img.Set(x, y, red)
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func TestIntegration_NearDirect_VL(t *testing.T) {
	skipNearDirectIntegration(t)

	proxySrv := newProxyServer(t, integrationNearDirectConfig(t))
	defer proxySrv.Close()

	model := nearDirectVLModel()
	body := fmt.Sprintf(`{
		"model": %q,
		"messages": [{
			"role": "user",
			"content": [
				{"type": "text", "text": "What color is this image? Answer in one word."},
				{"type": "image_url", "image_url": {"url": "data:image/png;base64,%s"}}
			]
		}],
		"stream": false,
		"max_tokens": 50
	}`, model, testPNG())

	resp, err := integrationClient.Post(proxySrv.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST chat (VL): %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, respBody)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	content := extractMessageContent(t, respBody)
	if !isPrintableUTF8(content) {
		t.Errorf("content is not valid printable UTF-8: %q", content)
	}
	t.Logf("VL response: %q", content)
}

// --------------------------------------------------------------------------
// Chutes VL integration
// --------------------------------------------------------------------------

func chutesVLModel() string {
	if m := os.Getenv("CHUTES_VL_MODEL"); m != "" {
		return m
	}
	return "Qwen/Qwen3.5-397B-A17B-TEE"
}

func TestIntegration_Chutes_VL(t *testing.T) {
	skipChutesIntegration(t)

	proxySrv := newProxyServer(t, integrationChutesPlaintextConfig(t))
	defer proxySrv.Close()

	model := chutesVLModel()
	// Simple chat prompt (not VL image) to verify model name resolution.
	body := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"Say hello"}],"stream":false,"max_tokens":50}`, model)

	resp, err := integrationClient.Post(proxySrv.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, respBody)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	// Verify we got a valid chat response. Content may be empty for models
	// with thinking mode (Qwen3.5) — the test's purpose is model name
	// resolution and proxy forwarding, not model output quality.
	content := extractMessageContent(t, respBody)
	t.Logf("chutes VL model response: %q", content)
}

// TestIntegration_Chutes_VL_E2EE sends a real VL request with an image through
// the proxy with E2EE enabled. Chutes whole-body ML-KEM encryption covers all
// request fields including the VL content array.
func TestIntegration_Chutes_VL_E2EE(t *testing.T) {
	skipChutesIntegration(t)

	proxySrv := newProxyServer(t, integrationChutesE2EEConfig(t))
	defer proxySrv.Close()

	model := chutesVLModel()
	body := fmt.Sprintf(`{
		"model": %q,
		"messages": [{
			"role": "user",
			"content": [
				{"type": "text", "text": "What color is this image? Answer in one word."},
				{"type": "image_url", "image_url": {"url": "data:image/png;base64,%s"}}
			]
		}],
		"stream": true,
		"max_tokens": 50
	}`, model, testPNG())

	resp, err := integrationClient.Post(proxySrv.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST chat (VL E2EE): %v", err)
	}
	defer resp.Body.Close()

	assertStreamResponse(t, resp)
}

// --------------------------------------------------------------------------
// NearDirect Images integration (FLUX)
// --------------------------------------------------------------------------

func nearDirectImagesModel() string {
	if m := os.Getenv("NEARAI_IMAGES_MODEL"); m != "" {
		return m
	}
	return "black-forest-labs/FLUX.2-klein-4B"
}

func TestIntegration_NearDirect_Images(t *testing.T) {
	skipNearDirectIntegration(t)

	proxySrv := newProxyServer(t, integrationNearDirectConfig(t))
	defer proxySrv.Close()

	model := nearDirectImagesModel()
	body := fmt.Sprintf(`{"model":%q,"prompt":"a solid red square","n":1,"size":"256x256","response_format":"b64_json"}`, model)

	resp, err := integrationClient.Post(proxySrv.URL+"/v1/images/generations", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST images: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, respBody)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	assertImagesResponse(t, respBody)
}

// --------------------------------------------------------------------------
// NearDirect Audio integration (Whisper)
// --------------------------------------------------------------------------

func nearDirectAudioModel() string {
	if m := os.Getenv("NEARAI_AUDIO_MODEL"); m != "" {
		return m
	}
	return "openai/whisper-large-v3"
}

func TestIntegration_NearDirect_Audio(t *testing.T) {
	skipNearDirectIntegration(t)

	proxySrv := newProxyServer(t, integrationNearDirectConfig(t))
	defer proxySrv.Close()

	model := nearDirectAudioModel()

	// Create a minimal WAV file (PCM, 16-bit, 16kHz, 0.1s of silence).
	wavData := makeMinimalWAV()

	// Build multipart form using mime/multipart for correct binary encoding.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	if err := mw.WriteField("model", model); err != nil {
		t.Fatalf("write model field: %v", err)
	}

	fw, err := mw.CreateFormFile("file", "test.wav")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := fw.Write(wavData); err != nil {
		t.Fatalf("write wav data: %v", err)
	}
	mw.Close()

	resp, err := integrationClient.Post(
		proxySrv.URL+"/v1/audio/transcriptions",
		mw.FormDataContentType(),
		&buf)
	if err != nil {
		t.Fatalf("POST audio: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, respBody)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	assertAudioResponse(t, respBody)
}

// --------------------------------------------------------------------------
// NearDirect Rerank integration
// --------------------------------------------------------------------------

func nearDirectRerankModel() string {
	if m := os.Getenv("NEARAI_RERANK_MODEL"); m != "" {
		return m
	}
	return "Qwen/Qwen3-Reranker-0.6B"
}

func TestIntegration_NearDirect_Rerank(t *testing.T) {
	skipNearDirectIntegration(t)

	proxySrv := newProxyServer(t, integrationNearDirectConfig(t))
	defer proxySrv.Close()

	model := nearDirectRerankModel()
	body := fmt.Sprintf(`{"model":%q,"query":"What is deep learning?","documents":["Deep learning is a subset of machine learning.","The weather today is sunny.","Neural networks have multiple layers."],"top_n":2}`, model)

	resp, err := integrationClient.Post(proxySrv.URL+"/v1/rerank", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST rerank: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, respBody)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	assertRerankResponse(t, respBody)
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// assertImagesResponse validates the response body matches OpenAI images spec.
func assertImagesResponse(t *testing.T, body []byte) {
	t.Helper()

	var resp struct {
		Created int64 `json:"created"`
		Data    []struct {
			URL     string `json:"url,omitempty"`
			B64JSON string `json:"b64_json,omitempty"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode images response: %v\nraw: %s", err, body[:min(500, len(body))])
	}

	if len(resp.Data) == 0 {
		t.Fatal("no image data in response")
	}
	if resp.Data[0].URL == "" && resp.Data[0].B64JSON == "" {
		t.Error("image data[0] has neither url nor b64_json")
	}
	t.Logf("images: created=%d count=%d has_url=%v has_b64=%v",
		resp.Created, len(resp.Data), resp.Data[0].URL != "", resp.Data[0].B64JSON != "")
}

// makeMinimalWAV returns a minimal WAV file (PCM 16-bit 16kHz, ~0.1s silence).
func makeMinimalWAV() []byte {
	sampleRate := 16000
	numSamples := sampleRate / 10 // 0.1 seconds
	dataSize := numSamples * 2    // 16-bit = 2 bytes per sample
	fileSize := 36 + dataSize

	buf := make([]byte, 44+dataSize)
	copy(buf[0:4], "RIFF")
	putLE32(buf[4:], uint32(fileSize))
	copy(buf[8:12], "WAVE")
	copy(buf[12:16], "fmt ")
	putLE32(buf[16:], 16) // chunk size
	putLE16(buf[20:], 1)  // PCM
	putLE16(buf[22:], 1)  // mono
	putLE32(buf[24:], uint32(sampleRate))
	putLE32(buf[28:], uint32(sampleRate*2)) // byte rate
	putLE16(buf[32:], 2)                    // block align
	putLE16(buf[34:], 16)                   // bits per sample
	copy(buf[36:40], "data")
	putLE32(buf[40:], uint32(dataSize))
	// samples are all zero (silence)
	return buf
}

func putLE16(b []byte, v uint16) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
}

func putLE32(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

// assertAudioResponse validates the response body matches OpenAI audio
// transcription spec: {"text": "..."}.
func assertAudioResponse(t *testing.T, body []byte) {
	t.Helper()

	var resp struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode audio response: %v\nraw: %s", err, body[:min(500, len(body))])
	}

	// A silent WAV produces empty or whitespace-only transcription — that's
	// fine. The test validates the response structure, not speech content.
	t.Logf("audio transcription: %q", resp.Text)
}

// assertRerankResponse validates the response body matches a rerank response spec.
func assertRerankResponse(t *testing.T, body []byte) {
	t.Helper()

	var resp struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Results []struct {
			Index          int     `json:"index"`
			RelevanceScore float64 `json:"relevance_score"`
			Document       struct {
				Text string `json:"text"`
			} `json:"document"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode rerank response: %v\nraw: %s", err, body[:min(500, len(body))])
	}

	if len(resp.Results) == 0 {
		t.Fatal("no rerank results in response")
	}
	for i, r := range resp.Results {
		if r.RelevanceScore == 0 && r.Document.Text == "" {
			t.Errorf("result[%d] has zero score and empty document", i)
		}
	}
	t.Logf("rerank: model=%s results=%d top_score=%.4f",
		resp.Model, len(resp.Results), resp.Results[0].RelevanceScore)
}
