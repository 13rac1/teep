package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot changes the working directory to the repository root for tests that
// rely on relative paths (Makefile, internal/provider/, cmd/teep/).
func repoRoot(t *testing.T) {
	t.Helper()
	t.Chdir("../..") // cmd/teeplint → repo root
}

// parseGo parses a Go source string and returns the file and fileset.
func parseGo(t *testing.T, src string) (*ast.File, *token.FileSet) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return f, fset
}

// newResult returns a fresh result for checking counts.
func newResult() *result {
	return &result{}
}

// =============================================================================
// result methods
// =============================================================================

func TestResult_PassFailSkip(t *testing.T) {
	r := newResult()
	r.passf("ok %s", "one")
	r.failf("bad %s", "two")
	r.skipf("skip %s", "three")
	if r.passed != 1 || r.failed != 1 || r.skipped != 1 {
		t.Errorf("got passed=%d failed=%d skipped=%d; want 1 1 1", r.passed, r.failed, r.skipped)
	}
}

// =============================================================================
// typeString
// =============================================================================

func TestTypeString(t *testing.T) {
	f, _ := parseGo(t, `package p
type T struct {
	A string
	B *int
	C http.Client
	D *http.Client
	E []byte
}
`)
	st := f.Decls[0].(*ast.GenDecl).Specs[0].(*ast.TypeSpec).Type.(*ast.StructType)
	fields := st.Fields.List

	cases := []struct {
		idx  int
		want string
	}{
		{0, "string"},
		{1, "*int"},
		{2, "http.Client"},
		{3, "*http.Client"},
		{4, "[]byte"},
	}
	for _, tc := range cases {
		got := typeString(fields[tc.idx].Type)
		if got != tc.want {
			t.Errorf("field %d: got %q want %q", tc.idx, got, tc.want)
		}
	}
}

func TestTypeString_Unknown(t *testing.T) {
	// Map type — not handled, returns "".
	f, _ := parseGo(t, `package p; type T map[string]int`)
	ts := f.Decls[0].(*ast.GenDecl).Specs[0].(*ast.TypeSpec)
	got := typeString(ts.Type)
	if got != "" {
		t.Errorf("got %q; want empty", got)
	}
}

func TestTypeString_ArrayWithLen(t *testing.T) {
	// Fixed-size array — ArrayType with Len set, returns "".
	f, _ := parseGo(t, `package p; type T [4]byte`)
	ts := f.Decls[0].(*ast.GenDecl).Specs[0].(*ast.TypeSpec)
	got := typeString(ts.Type)
	if got != "" {
		t.Errorf("got %q; want empty", got)
	}
}

// =============================================================================
// hasStruct
// =============================================================================

func TestHasStruct(t *testing.T) {
	f, _ := parseGo(t, `package p; type Attester struct{}`)
	if !hasStruct([]*ast.File{f}, "Attester") {
		t.Error("expected hasStruct to be true")
	}
	if hasStruct([]*ast.File{f}, "Missing") {
		t.Error("expected hasStruct to be false for missing")
	}
}

func TestHasStruct_NotAStruct(t *testing.T) {
	// Type alias to int — hasStruct should return false.
	f, _ := parseGo(t, `package p; type Attester int`)
	if hasStruct([]*ast.File{f}, "Attester") {
		t.Error("expected hasStruct to be false for non-struct type")
	}
}

// =============================================================================
// hasFunc
// =============================================================================

func TestHasFunc(t *testing.T) {
	f, _ := parseGo(t, `package p
func ParseGatewayResponse() {}
func (r T) method() {}
`)
	if !hasFunc([]*ast.File{f}, "ParseGatewayResponse") {
		t.Error("expected true for top-level func")
	}
	if hasFunc([]*ast.File{f}, "method") {
		t.Error("expected false for method (has receiver)")
	}
	if hasFunc([]*ast.File{f}, "Missing") {
		t.Error("expected false for missing func")
	}
}

// =============================================================================
// containsCall
// =============================================================================

func TestContainsCall(t *testing.T) {
	f, _ := parseGo(t, `package p
import "fmt"
func fn() {
	fmt.Sprintf("x")
}
`)
	fd := f.Decls[1].(*ast.FuncDecl)
	if !containsCall(fd.Body, "fmt", "Sprintf") {
		t.Error("expected true")
	}
	if containsCall(fd.Body, "fmt", "Println") {
		t.Error("expected false for absent call")
	}
	if containsCall(nil, "fmt", "Sprintf") {
		t.Error("expected false for nil node")
	}
}

// =============================================================================
// findFunc
// =============================================================================

func TestFindFunc(t *testing.T) {
	f, _ := parseGo(t, `package p
func target() {}
`)
	fd := findFunc(f, "target")
	if fd == nil {
		t.Fatal("expected to find target")
	}
	if findFunc(f, "missing") != nil {
		t.Error("expected nil for missing func")
	}
}

func TestFindFunc_SkipsReceivers(t *testing.T) {
	f, _ := parseGo(t, `package p
type T struct{}
func (T) target() {}
`)
	if findFunc(f, "target") != nil {
		t.Error("expected nil: target has a receiver")
	}
}

// =============================================================================
// collectSwitchCases
// =============================================================================

func TestCollectSwitchCases(t *testing.T) {
	f, _ := parseGo(t, `package p
func fn(s string) {
	switch s {
	case "alpha", "beta":
	case "gamma":
	default:
	}
}
`)
	fd := findFunc(f, "fn")
	cases := collectSwitchCases(fd.Body)
	for _, k := range []string{"alpha", "beta", "gamma"} {
		if !cases[k] {
			t.Errorf("expected case %q", k)
		}
	}
}

func TestCollectSwitchCases_Nil(t *testing.T) {
	cases := collectSwitchCases(nil)
	if len(cases) != 0 {
		t.Error("expected empty for nil body")
	}
}

// =============================================================================
// detectArchetype
// =============================================================================

func TestDetectArchetype_Gateway(t *testing.T) {
	f, _ := parseGo(t, `package p
import "github.com/13rac1/teep/internal/formatdetect"
func fn() { formatdetect.Detect(nil) }
`)
	got := detectArchetype([]*ast.File{f})
	if got != archetypeGateway {
		t.Errorf("got %q; want gateway", got)
	}
}

func TestDetectArchetype_FixedGateway(t *testing.T) {
	f, _ := parseGo(t, `package p
func ParseGatewayResponse() {}
`)
	got := detectArchetype([]*ast.File{f})
	if got != archetypeFixedGateway {
		t.Errorf("got %q; want fixed-gateway", got)
	}
}

func TestDetectArchetype_Direct(t *testing.T) {
	f, _ := parseGo(t, `package p
func ParseAttestationResponse() {}
`)
	got := detectArchetype([]*ast.File{f})
	if got != archetypeDirect {
		t.Errorf("got %q; want direct", got)
	}
}

// =============================================================================
// collectCompositeLitKeys
// =============================================================================

func TestCollectCompositeLitKeys(t *testing.T) {
	f, _ := parseGo(t, `package p
var myMap = map[string]string{
	"alpha": "A",
	"beta":  "B",
}
`)
	keys := collectCompositeLitKeys(f, "myMap")
	if !keys["alpha"] || !keys["beta"] {
		t.Error("expected alpha and beta keys")
	}
	if keys["missing"] {
		t.Error("unexpected key")
	}
}

func TestCollectCompositeLitKeys_Missing(t *testing.T) {
	f, _ := parseGo(t, `package p; var x int`)
	keys := collectCompositeLitKeys(f, "noSuchVar")
	if len(keys) != 0 {
		t.Error("expected empty")
	}
}

func TestCollectCompositeLitKeys_NotCompositeLit(t *testing.T) {
	f, _ := parseGo(t, `package p; var myMap = someFunc()`)
	keys := collectCompositeLitKeys(f, "myMap")
	if len(keys) != 0 {
		t.Error("expected empty when value is not composite literal")
	}
}

// =============================================================================
// extractFuncStringLiterals
// =============================================================================

func TestExtractFuncStringLiterals(t *testing.T) {
	f, _ := parseGo(t, "package p\nfunc printHelp() {\n\tprintln(`hello world`)\n\tprintln(\"goodbye\")\n}\n")
	got := extractFuncStringLiterals(f, "printHelp")
	if !strings.Contains(got, "hello world") {
		t.Errorf("expected raw string literal, got %q", got)
	}
	if !strings.Contains(got, "goodbye") {
		t.Errorf("expected quoted literal, got %q", got)
	}
}

func TestExtractFuncStringLiterals_Missing(t *testing.T) {
	f, _ := parseGo(t, `package p`)
	got := extractFuncStringLiterals(f, "noFunc")
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

// =============================================================================
// checkAttestationPathConst
// =============================================================================

func TestCheckAttestationPathConst_Pass(t *testing.T) {
	f, fset := parseGo(t, `package p
const attestationPath = "/v1/attest"
`)
	p := &providerInfo{name: "test", files: []*ast.File{f}, fset: fset}
	r := newResult()
	checkAttestationPathConst(r, p)
	if r.failed != 0 {
		t.Errorf("expected pass, got %d failures", r.failed)
	}
}

func TestCheckAttestationPathConst_Fail(t *testing.T) {
	f, fset := parseGo(t, `package p; const other = "x"`)
	p := &providerInfo{name: "test", files: []*ast.File{f}, fset: fset}
	r := newResult()
	checkAttestationPathConst(r, p)
	if r.failed == 0 {
		t.Error("expected failure")
	}
}

// =============================================================================
// checkResponseStruct
// =============================================================================

func TestCheckResponseStruct_Pass(t *testing.T) {
	f, fset := parseGo(t, `package p; type attestationResponse struct{ Field string }`)
	p := &providerInfo{name: "test", files: []*ast.File{f}, fset: fset}
	r := newResult()
	checkResponseStruct(r, p, "attestationResponse")
	if r.failed != 0 {
		t.Errorf("expected pass, got %d failures", r.failed)
	}
}

func TestCheckResponseStruct_Fail(t *testing.T) {
	f, fset := parseGo(t, `package p; type other struct{}`)
	p := &providerInfo{name: "test", files: []*ast.File{f}, fset: fset}
	r := newResult()
	checkResponseStruct(r, p, "attestationResponse")
	if r.failed == 0 {
		t.Error("expected failure")
	}
}

func TestCheckResponseStruct_NotStruct(t *testing.T) {
	f, fset := parseGo(t, `package p; type attestationResponse int`)
	p := &providerInfo{name: "test", files: []*ast.File{f}, fset: fset}
	r := newResult()
	checkResponseStruct(r, p, "attestationResponse")
	if r.failed == 0 {
		t.Error("expected failure: type exists but is not a struct")
	}
}

// =============================================================================
// checkAttesterClientField
// =============================================================================

func TestCheckAttesterClientField_Pass(t *testing.T) {
	f, fset := parseGo(t, `package p
import "net/http"
type Attester struct {
	client *http.Client
}
`)
	p := &providerInfo{name: "test", files: []*ast.File{f}, fset: fset}
	r := newResult()
	checkAttesterClientField(r, p)
	if r.failed != 0 {
		t.Errorf("expected pass, got %d failures", r.failed)
	}
}

func TestCheckAttesterClientField_Fail_NoField(t *testing.T) {
	f, fset := parseGo(t, `package p; type Attester struct{ other string }`)
	p := &providerInfo{name: "test", files: []*ast.File{f}, fset: fset}
	r := newResult()
	checkAttesterClientField(r, p)
	if r.failed == 0 {
		t.Error("expected failure")
	}
}

func TestCheckAttesterClientField_Fail_WrongType(t *testing.T) {
	f, fset := parseGo(t, `package p; type Attester struct{ client string }`)
	p := &providerInfo{name: "test", files: []*ast.File{f}, fset: fset}
	r := newResult()
	checkAttesterClientField(r, p)
	if r.failed == 0 {
		t.Error("expected failure: client exists but wrong type")
	}
}

func TestCheckAttesterClientField_Fail_NoAttester(t *testing.T) {
	f, fset := parseGo(t, `package p; type Other struct{ client string }`)
	p := &providerInfo{name: "test", files: []*ast.File{f}, fset: fset}
	r := newResult()
	checkAttesterClientField(r, p)
	if r.failed == 0 {
		t.Error("expected failure: no Attester struct")
	}
}

// =============================================================================
// checkParseFunc
// =============================================================================

func TestCheckParseFunc_Pass(t *testing.T) {
	f, fset := parseGo(t, `package p; func ParseAttestationResponse() {}`)
	p := &providerInfo{name: "test", files: []*ast.File{f}, fset: fset}
	r := newResult()
	fd := checkParseFunc(r, p, "ParseAttestationResponse")
	if fd == nil || r.failed != 0 {
		t.Errorf("expected pass and non-nil fd, got failed=%d fd=%v", r.failed, fd)
	}
}

func TestCheckParseFunc_Fail(t *testing.T) {
	f, fset := parseGo(t, `package p`)
	p := &providerInfo{name: "test", files: []*ast.File{f}, fset: fset}
	r := newResult()
	fd := checkParseFunc(r, p, "ParseAttestationResponse")
	if fd != nil || r.failed == 0 {
		t.Error("expected nil fd and failure")
	}
}

func TestCheckParseFunc_SkipsReceivers(t *testing.T) {
	// Function with a receiver must not count.
	f, fset := parseGo(t, `package p
type T struct{}
func (T) ParseAttestationResponse() {}
`)
	p := &providerInfo{name: "test", files: []*ast.File{f}, fset: fset}
	r := newResult()
	fd := checkParseFunc(r, p, "ParseAttestationResponse")
	if fd != nil || r.failed == 0 {
		t.Error("expected nil fd and failure: method should not satisfy top-level func check")
	}
}

// =============================================================================
// checkParseFuncUsesJSONStrict
// =============================================================================

func TestCheckParseFuncUsesJSONStrict_Pass(t *testing.T) {
	f, fset := parseGo(t, `package p
func Parse() {
	jsonstrict.Unmarshal(nil, nil)
}
`)
	fd := findFunc(f, "Parse")
	p := &providerInfo{name: "test", files: []*ast.File{f}, fset: fset}
	r := newResult()
	checkParseFuncUsesJSONStrict(r, p, fd)
	if r.failed != 0 {
		t.Errorf("expected pass, got %d failures", r.failed)
	}
}

func TestCheckParseFuncUsesJSONStrict_Fail(t *testing.T) {
	f, fset := parseGo(t, `package p; func Parse() { _ = 1 }`)
	fd := findFunc(f, "Parse")
	p := &providerInfo{name: "test", files: []*ast.File{f}, fset: fset}
	r := newResult()
	checkParseFuncUsesJSONStrict(r, p, fd)
	if r.failed == 0 {
		t.Error("expected failure")
	}
}

func TestCheckParseFuncUsesJSONStrict_NilFunc(t *testing.T) {
	f, fset := parseGo(t, `package p`)
	p := &providerInfo{name: "test", files: []*ast.File{f}, fset: fset}
	r := newResult()
	checkParseFuncUsesJSONStrict(r, p, nil)
	if r.failed == 0 {
		t.Error("expected failure for nil func decl")
	}
}

// =============================================================================
// checkUsesFormatDetect
// =============================================================================

func TestCheckUsesFormatDetect_Pass(t *testing.T) {
	f, fset := parseGo(t, `package p
func Parse() {
	formatdetect.Detect(nil)
}
`)
	fd := findFunc(f, "Parse")
	p := &providerInfo{name: "test", files: []*ast.File{f}, fset: fset}
	r := newResult()
	checkUsesFormatDetect(r, p, fd)
	if r.failed != 0 {
		t.Errorf("expected pass, got %d failures", r.failed)
	}
}

func TestCheckUsesFormatDetect_Fail(t *testing.T) {
	f, fset := parseGo(t, `package p; func Parse() {}`)
	fd := findFunc(f, "Parse")
	p := &providerInfo{name: "test", files: []*ast.File{f}, fset: fset}
	r := newResult()
	checkUsesFormatDetect(r, p, fd)
	if r.failed == 0 {
		t.Error("expected failure")
	}
}

func TestCheckUsesFormatDetect_NilFunc(t *testing.T) {
	f, fset := parseGo(t, `package p`)
	p := &providerInfo{name: "test", files: []*ast.File{f}, fset: fset}
	r := newResult()
	checkUsesFormatDetect(r, p, nil)
	if r.failed == 0 {
		t.Error("expected failure for nil fd")
	}
}

// =============================================================================
// checkFetchUsesBoundedRead
// =============================================================================

func TestCheckFetchUsesBoundedRead_Pass(t *testing.T) {
	f, fset := parseGo(t, `package p
type Attester struct{}
func (a *Attester) FetchAttestation() {
	provider.FetchAttestationJSON(nil, "")
}
`)
	p := &providerInfo{name: "test", files: []*ast.File{f}, fset: fset}
	r := newResult()
	checkFetchUsesBoundedRead(r, p)
	if r.failed != 0 {
		t.Errorf("expected pass, got %d failures", r.failed)
	}
}

func TestCheckFetchUsesBoundedRead_Fail_NoCall(t *testing.T) {
	f, fset := parseGo(t, `package p
type Attester struct{}
func (a *Attester) FetchAttestation() {}
`)
	p := &providerInfo{name: "test", files: []*ast.File{f}, fset: fset}
	r := newResult()
	checkFetchUsesBoundedRead(r, p)
	if r.failed == 0 {
		t.Error("expected failure: no provider.FetchAttestationJSON call")
	}
}

func TestCheckFetchUsesBoundedRead_Fail_NoMethod(t *testing.T) {
	f, fset := parseGo(t, `package p; type Attester struct{}`)
	p := &providerInfo{name: "test", files: []*ast.File{f}, fset: fset}
	r := newResult()
	checkFetchUsesBoundedRead(r, p)
	if r.failed == 0 {
		t.Error("expected failure: FetchAttestation not found")
	}
}

// =============================================================================
// checkNoSlogAPIKeyArgs
// =============================================================================

func TestCheckNoSlogAPIKeyArgs_Pass(t *testing.T) {
	f, fset := parseGo(t, `package p
import "log/slog"
func fn() { slog.Info("msg", "url", "x") }
`)
	p := &providerInfo{name: "test", files: []*ast.File{f}, fset: fset}
	r := newResult()
	checkNoSlogAPIKeyArgs(r, p)
	if r.failed != 0 {
		t.Errorf("expected pass, got %d failures", r.failed)
	}
}

func TestCheckNoSlogAPIKeyArgs_Fail(t *testing.T) {
	f, fset := parseGo(t, `package p
import "log/slog"
func fn() { slog.Info("msg", "api_key", "secret") }
`)
	p := &providerInfo{name: "test", files: []*ast.File{f}, fset: fset}
	r := newResult()
	checkNoSlogAPIKeyArgs(r, p)
	if r.failed == 0 {
		t.Error("expected failure")
	}
}

func TestCheckNoSlogAPIKeyArgs_OtherBadNames(t *testing.T) {
	for _, bad := range []string{"apiKey", "APIKey", "apikey"} {
		f, fset := parseGo(t, `package p
import "log/slog"
func fn() { slog.Info("msg", "`+bad+`", "v") }
`)
		p := &providerInfo{name: "test", files: []*ast.File{f}, fset: fset}
		r := newResult()
		checkNoSlogAPIKeyArgs(r, p)
		if r.failed == 0 {
			t.Errorf("expected failure for bad name %q", bad)
		}
	}
}

// =============================================================================
// checkNoJSONRawMessage + collectRawMessageViolations
// =============================================================================

func TestCheckNoJSONRawMessage_Pass(t *testing.T) {
	f, fset := parseGo(t, `package p; type attestationResponse struct{ A string }`)
	p := &providerInfo{
		name:      "test",
		files:     []*ast.File{f},
		fileNames: []string{"test.go"},
		fset:      fset,
	}
	r := newResult()
	checkNoJSONRawMessage(r, p)
	if r.failed != 0 {
		t.Errorf("expected pass, got %d failures", r.failed)
	}
}

func TestCheckNoJSONRawMessage_Fail(t *testing.T) {
	f, fset := parseGo(t, `package p
import "encoding/json"
type attestationResponse struct{ Raw json.RawMessage }
`)
	p := &providerInfo{
		name:      "test",
		files:     []*ast.File{f},
		fileNames: []string{"test.go"},
		fset:      fset,
	}
	r := newResult()
	checkNoJSONRawMessage(r, p)
	if r.failed == 0 {
		t.Error("expected failure")
	}
}

func TestCheckNoJSONRawMessage_SkipsModels(t *testing.T) {
	f, fset := parseGo(t, `package p
import "encoding/json"
type attestationResponse struct{ Raw json.RawMessage }
`)
	// Name the file models.go — should be skipped.
	p := &providerInfo{
		name:      "test",
		files:     []*ast.File{f},
		fileNames: []string{"models.go"},
		fset:      fset,
	}
	r := newResult()
	checkNoJSONRawMessage(r, p)
	if r.failed != 0 {
		t.Errorf("expected pass (models.go skipped), got %d failures", r.failed)
	}
}

func TestCollectRawMessageViolations_EmbeddedAndSlice(t *testing.T) {
	f, fset := parseGo(t, `package p
import "encoding/json"
type S struct {
	json.RawMessage
	Items []json.RawMessage
}
`)
	// Decls[0] is the import; Decls[1] is the type.
	st := f.Decls[1].(*ast.GenDecl).Specs[0].(*ast.TypeSpec).Type.(*ast.StructType)
	var violations []string
	collectRawMessageViolations(fset, st, "S", "test.go", &violations)
	if len(violations) < 2 {
		t.Errorf("expected at least 2 violations, got %v", violations)
	}
}

func TestCollectRawMessageViolations_NestedStruct(t *testing.T) {
	f, fset := parseGo(t, `package p
import "encoding/json"
type S struct {
	Inner struct {
		Raw json.RawMessage
	}
}
`)
	// Decls[0] is the import; Decls[1] is the type.
	st := f.Decls[1].(*ast.GenDecl).Specs[0].(*ast.TypeSpec).Type.(*ast.StructType)
	var violations []string
	collectRawMessageViolations(fset, st, "S", "test.go", &violations)
	if len(violations) == 0 {
		t.Error("expected violation in nested struct")
	}
}

// =============================================================================
// checkNoBytesEqualProject
// =============================================================================

func TestCheckNoBytesEqualProject_Pass(t *testing.T) {
	f, _ := parseGo(t, `package p
import "crypto/subtle"
func fn(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 0 }
`)
	r := newResult()
	checkNoBytesEqualProject(r, []*ast.File{f}, []string{"test.go"})
	if r.failed != 0 {
		t.Errorf("expected pass, got %d failures", r.failed)
	}
}

func TestCheckNoBytesEqualProject_Fail(t *testing.T) {
	f, _ := parseGo(t, `package p
import "bytes"
func fn(a, b []byte) bool { return bytes.Equal(a, b) }
`)
	r := newResult()
	checkNoBytesEqualProject(r, []*ast.File{f}, []string{"bad.go"})
	if r.failed == 0 {
		t.Error("expected failure")
	}
}

// =============================================================================
// checkNoStringsEqualFold
// =============================================================================

func TestCheckNoStringsEqualFold_Pass(t *testing.T) {
	f, _ := parseGo(t, `package p; func fn() {}`)
	r := newResult()
	checkNoStringsEqualFold(r, []*ast.File{f}, []string{"test.go"})
	if r.failed != 0 {
		t.Errorf("expected pass")
	}
}

func TestCheckNoStringsEqualFold_Fail(t *testing.T) {
	f, _ := parseGo(t, `package p
import "strings"
func fn(a, b string) bool { return strings.EqualFold(a, b) }
`)
	r := newResult()
	checkNoStringsEqualFold(r, []*ast.File{f}, []string{"bad.go"})
	if r.failed == 0 {
		t.Error("expected failure")
	}
}

// =============================================================================
// checkNoLogImportProject
// =============================================================================

func TestCheckNoLogImportProject_Pass(t *testing.T) {
	f, _ := parseGo(t, `package p; import "log/slog"`)
	r := newResult()
	checkNoLogImportProject(r, []*ast.File{f}, []string{"test.go"})
	if r.failed != 0 {
		t.Errorf("expected pass")
	}
}

func TestCheckNoLogImportProject_Fail(t *testing.T) {
	f, _ := parseGo(t, `package p; import "log"`)
	r := newResult()
	checkNoLogImportProject(r, []*ast.File{f}, []string{"bad.go"})
	if r.failed == 0 {
		t.Error("expected failure")
	}
}

// =============================================================================
// checkNoMathRand
// =============================================================================

func TestCheckNoMathRand_Pass(t *testing.T) {
	f, _ := parseGo(t, `package p; import "crypto/rand"`)
	r := newResult()
	checkNoMathRand(r, []*ast.File{f}, []string{"test.go"})
	if r.failed != 0 {
		t.Errorf("expected pass")
	}
}

func TestCheckNoMathRand_Fail(t *testing.T) {
	f, _ := parseGo(t, `package p; import "math/rand"`)
	r := newResult()
	checkNoMathRand(r, []*ast.File{f}, []string{"bad.go"})
	if r.failed == 0 {
		t.Error("expected failure")
	}
}

// =============================================================================
// checkNoCryptoTLSImport
// =============================================================================

func TestCheckNoCryptoTLSImport_Pass(t *testing.T) {
	f, _ := parseGo(t, `package p; import "net/http"`)
	r := newResult()
	checkNoCryptoTLSImport(r, []*ast.File{f}, []string{"internal/proxy/proxy.go"})
	if r.failed != 0 {
		t.Errorf("expected pass, got %d failures", r.failed)
	}
}

func TestCheckNoCryptoTLSImport_Fail(t *testing.T) {
	f, _ := parseGo(t, `package p; import "crypto/tls"`)
	r := newResult()
	checkNoCryptoTLSImport(r, []*ast.File{f}, []string{"internal/other/file.go"})
	if r.failed == 0 {
		t.Error("expected failure")
	}
}

func TestCheckNoCryptoTLSImport_AllowTLSCT(t *testing.T) {
	f, _ := parseGo(t, `package p; import "crypto/tls"`)
	r := newResult()
	checkNoCryptoTLSImport(r, []*ast.File{f}, []string{"internal/tlsct/checker.go"})
	if r.failed != 0 {
		t.Errorf("expected pass for tlsct package, got %d failures", r.failed)
	}
}

func TestCheckNoCryptoTLSImport_RejectPinned(t *testing.T) {
	f, _ := parseGo(t, `package p; import "crypto/tls"`)
	// Pinned files must now use tlsct, not crypto/tls directly.
	r := newResult()
	checkNoCryptoTLSImport(r, []*ast.File{f}, []string{"internal/provider/neardirect/pinned.go"})
	if r.failed == 0 {
		t.Error("expected failure for neardirect/pinned.go using crypto/tls")
	}
	r = newResult()
	checkNoCryptoTLSImport(r, []*ast.File{f}, []string{"internal/provider/nearcloud/pinned.go"})
	if r.failed == 0 {
		t.Error("expected failure for nearcloud/pinned.go using crypto/tls")
	}
}

func TestCheckNoCryptoTLSImport_AllowCapture(t *testing.T) {
	f, _ := parseGo(t, `package p; import "crypto/tls"`)
	r := newResult()
	checkNoCryptoTLSImport(r, []*ast.File{f}, []string{"internal/capture/capture.go"})
	if r.failed != 0 {
		t.Errorf("expected pass for capture.go, got %d failures", r.failed)
	}
}

// =============================================================================
// checkNoHTTPClientLiteral
// =============================================================================

func TestCheckNoHTTPClientLiteral_Pass(t *testing.T) {
	f, _ := parseGo(t, `package p
import "net/http"
func fn() *http.Client { return tlsct.NewHTTPClient(0) }
`)
	r := newResult()
	checkNoHTTPClientLiteral(r, []*ast.File{f}, []string{"internal/proxy/proxy.go"})
	if r.failed != 0 {
		t.Errorf("expected pass, got %d failures", r.failed)
	}
}

func TestCheckNoHTTPClientLiteral_Fail(t *testing.T) {
	f, _ := parseGo(t, `package p
import "net/http"
func fn() *http.Client { return &http.Client{} }
`)
	r := newResult()
	checkNoHTTPClientLiteral(r, []*ast.File{f}, []string{"internal/other/file.go"})
	if r.failed == 0 {
		t.Error("expected failure")
	}
}

func TestCheckNoHTTPClientLiteral_AllowTLSCT(t *testing.T) {
	f, _ := parseGo(t, `package p
import "net/http"
func fn() *http.Client { return &http.Client{} }
`)
	r := newResult()
	checkNoHTTPClientLiteral(r, []*ast.File{f}, []string{"internal/tlsct/checker.go"})
	if r.failed != 0 {
		t.Errorf("expected pass for tlsct package, got %d failures", r.failed)
	}
}

func TestCheckNoHTTPClientLiteral_AllowVerify(t *testing.T) {
	f, _ := parseGo(t, `package p
import "net/http"
func fn() *http.Client { return &http.Client{} }
`)
	r := newResult()
	checkNoHTTPClientLiteral(r, []*ast.File{f}, []string{"internal/verify/verify.go"})
	if r.failed != 0 {
		t.Errorf("expected pass for verify.go, got %d failures", r.failed)
	}
}

// =============================================================================
// isAllowedPath
// =============================================================================

func TestIsAllowedPath_PrefixMatch(t *testing.T) {
	if !isAllowedPath("internal/tlsct/checker.go", []string{"internal/tlsct/"}) {
		t.Error("expected prefix match")
	}
}

func TestIsAllowedPath_ExactMatch(t *testing.T) {
	if !isAllowedPath("internal/capture/capture.go", []string{"internal/capture/capture.go"}) {
		t.Error("expected exact match")
	}
}

func TestIsAllowedPath_NoMatch(t *testing.T) {
	if isAllowedPath("internal/other/file.go", []string{"internal/tlsct/", "internal/capture/capture.go"}) {
		t.Error("expected no match")
	}
}

// =============================================================================
// containsCompositeLit
// =============================================================================

func TestContainsCompositeLit_Found(t *testing.T) {
	f, _ := parseGo(t, `package p
import "net/http"
func fn() { _ = http.Client{} }
`)
	if !containsCompositeLit(f, "net/http", "Client") {
		t.Error("expected to find http.Client{} literal")
	}
}

func TestContainsCompositeLit_FoundPointer(t *testing.T) {
	f, _ := parseGo(t, `package p
import "net/http"
func fn() { _ = &http.Client{Timeout: 0} }
`)
	if !containsCompositeLit(f, "net/http", "Client") {
		t.Error("expected to find &http.Client{} literal")
	}
}

func TestContainsCompositeLit_NotFound(t *testing.T) {
	f, _ := parseGo(t, `package p
import "net/http"
func fn() *http.Client { return nil }
`)
	if containsCompositeLit(f, "net/http", "Client") {
		t.Error("expected false: no composite literal")
	}
}

func TestContainsCompositeLit_Nil(t *testing.T) {
	if containsCompositeLit(nil, "net/http", "Client") {
		t.Error("expected false for nil node")
	}
}

func TestContainsCompositeLit_DifferentType(t *testing.T) {
	f, _ := parseGo(t, `package p
import "net/http"
func fn() { _ = http.Transport{} }
`)
	if containsCompositeLit(f, "net/http", "Client") {
		t.Error("expected false: different type name")
	}
}

func TestContainsCompositeLit_ImportAlias(t *testing.T) {
	f, _ := parseGo(t, `package p
import nethttp "net/http"
func fn() { _ = nethttp.Client{} }
`)
	if !containsCompositeLit(f, "net/http", "Client") {
		t.Error("expected to detect http.Client{} via import alias")
	}
}

func TestContainsCompositeLit_NoImport(t *testing.T) {
	f, _ := parseGo(t, `package p
func fn() {}
`)
	if containsCompositeLit(f, "net/http", "Client") {
		t.Error("expected false: net/http not imported")
	}
}

func TestContainsCompositeLit_DotImport(t *testing.T) {
	f, _ := parseGo(t, `package p
import . "net/http"
func fn() { _ = Client{} }
`)
	if !containsCompositeLit(f, "net/http", "Client") {
		t.Error("expected dot-import of net/http to be flagged")
	}
}

// =============================================================================
// checkNoJSONUnmarshalCLI
// =============================================================================

func TestCheckNoJSONUnmarshalCLI_Pass(t *testing.T) {
	f, fset := parseGo(t, `package main
import "encoding/json"
func fn() { _ = json.Marshal(nil) }
`)
	r := newResult()
	// File is named "cmd/teep/main.go" so it matches the target.
	checkNoJSONUnmarshalCLI(r, []*ast.File{f}, []string{"cmd/teep/main.go"}, fset)
	if r.failed != 0 {
		t.Errorf("expected pass")
	}
}

func TestCheckNoJSONUnmarshalCLI_Fail(t *testing.T) {
	f, fset := parseGo(t, `package main
import "encoding/json"
func fn(b []byte) { var x interface{}; json.Unmarshal(b, &x) }
`)
	r := newResult()
	checkNoJSONUnmarshalCLI(r, []*ast.File{f}, []string{"cmd/teep/main.go"}, fset)
	if r.failed == 0 {
		t.Error("expected failure")
	}
}

func TestCheckNoJSONUnmarshalCLI_IgnoresOtherFiles(t *testing.T) {
	f, fset := parseGo(t, `package p
import "encoding/json"
func fn(b []byte) { var x interface{}; json.Unmarshal(b, &x) }
`)
	r := newResult()
	// File is not cmd/teep/main.go — check should still pass.
	checkNoJSONUnmarshalCLI(r, []*ast.File{f}, []string{"internal/other/file.go"}, fset)
	if r.failed != 0 {
		t.Errorf("expected pass for non-target file")
	}
}

// =============================================================================
// checkFromConfigDefaultError
// =============================================================================

func TestCheckFromConfigDefaultError_Pass(t *testing.T) {
	f, _ := parseGo(t, `package p
import "fmt"
func fromConfig(s string) error {
	switch s {
	case "alpha":
		return nil
	default:
		return fmt.Errorf("unknown provider %q (want: alpha, beta)", s)
	}
}
`)
	fd := findFunc(f, "fromConfig")
	r := newResult()
	checkFromConfigDefaultError(r, fd, []string{"alpha", "beta"})
	if r.failed != 0 {
		t.Errorf("expected pass, got %d failures", r.failed)
	}
}

func TestCheckFromConfigDefaultError_NoDefault(t *testing.T) {
	f, _ := parseGo(t, `package p
func fromConfig(s string) {
	switch s {
	case "alpha":
	}
}
`)
	fd := findFunc(f, "fromConfig")
	r := newResult()
	checkFromConfigDefaultError(r, fd, []string{"alpha"})
	if r.failed == 0 {
		t.Error("expected failure: no default case")
	}
}

func TestCheckFromConfigDefaultError_MissingProvider(t *testing.T) {
	f, _ := parseGo(t, `package p
import "fmt"
func fromConfig(s string) error {
	switch s {
	default:
		return fmt.Errorf("unknown: alpha")
	}
}
`)
	fd := findFunc(f, "fromConfig")
	r := newResult()
	checkFromConfigDefaultError(r, fd, []string{"alpha", "beta"})
	// "beta" is not in the error string → fail.
	if r.failed == 0 {
		t.Error("expected failure for missing provider in error string")
	}
}

func TestCheckFromConfigDefaultError_NoErrorf(t *testing.T) {
	f, _ := parseGo(t, `package p
func fromConfig(s string) {
	switch s {
	default:
		_ = 1
	}
}
`)
	fd := findFunc(f, "fromConfig")
	r := newResult()
	checkFromConfigDefaultError(r, fd, []string{"alpha"})
	if r.failed == 0 {
		t.Error("expected failure: no fmt.Errorf in default")
	}
}

// =============================================================================
// checkFromConfigFieldAssignment
// =============================================================================

func TestCheckFromConfigFieldAssignment_Pass(t *testing.T) {
	f, _ := parseGo(t, `package p
func fromConfig(name string) {
	switch name {
	case "alpha":
		p.ChatPath = "/v1/chat"
	}
}
`)
	fd := findFunc(f, "fromConfig")
	r := newResult()
	checkFromConfigFieldAssignment(r, fd, []string{"alpha"}, "ChatPath")
	if r.failed != 0 {
		t.Errorf("expected pass, got %d failures", r.failed)
	}
}

func TestCheckFromConfigFieldAssignment_Fail(t *testing.T) {
	f, _ := parseGo(t, `package p
func fromConfig(name string) {
	switch name {
	case "alpha":
		_ = 1
	}
}
`)
	fd := findFunc(f, "fromConfig")
	r := newResult()
	checkFromConfigFieldAssignment(r, fd, []string{"alpha"}, "ChatPath")
	if r.failed == 0 {
		t.Error("expected failure")
	}
}

// =============================================================================
// Filesystem-dependent: discoverProviders, loadProvider
// =============================================================================

func TestDiscoverProviders(t *testing.T) {
	repoRoot(t)
	providers, err := discoverProviders()
	if err != nil {
		t.Fatalf("discoverProviders: %v", err)
	}
	if len(providers) == 0 {
		t.Fatal("expected at least one provider")
	}
	// Every provider must have a non-empty name and a valid archetype.
	for _, p := range providers {
		if p.name == "" {
			t.Error("provider with empty name")
		}
		switch p.archetype {
		case archetypeDirect, archetypeGateway, archetypeFixedGateway:
		default:
			t.Errorf("provider %s has unknown archetype %q", p.name, p.archetype)
		}
	}
}

func TestDiscoverProviders_BadDir(t *testing.T) {
	t.Chdir(t.TempDir())
	// No internal/provider dir here → error from os.ReadDir.
	_, err := discoverProviders()
	if err == nil {
		t.Error("expected error for missing providerDir")
	}
}

func TestLoadProvider_NonExistentDir(t *testing.T) {
	t.Chdir(t.TempDir())
	_, ok, err := loadProvider("does-not-exist")
	if err == nil || ok {
		t.Error("expected error and ok=false for non-existent dir")
	}
}

func TestLoadProvider_NoAttester(t *testing.T) {
	// Create a temp dir with a Go file that has no Attester struct.
	dir := t.TempDir()
	pDir := filepath.Join(dir, "internal", "provider", "util")
	if err := os.MkdirAll(pDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pDir, "util.go"), []byte("package util\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	_, ok, err := loadProvider("util")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected ok=false for package without Attester struct")
	}
}

func TestLoadProvider_ParseError(t *testing.T) {
	dir := t.TempDir()
	pDir := filepath.Join(dir, "internal", "provider", "bad")
	if err := os.MkdirAll(pDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pDir, "bad.go"), []byte("package bad\nINVALID{{{\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	_, _, err := loadProvider("bad")
	if err == nil {
		t.Error("expected parse error")
	}
}

// =============================================================================
// Filesystem-dependent: high-level checks against real project files
// =============================================================================

func TestCheckProviderStructure_RealProviders(t *testing.T) {
	repoRoot(t)
	providers, err := discoverProviders()
	if err != nil {
		t.Fatalf("discoverProviders: %v", err)
	}
	for i := range providers {
		r := newResult()
		checkProviderStructure(r, &providers[i])
		if r.failed != 0 {
			t.Errorf("provider %s: %d checks failed", providers[i].name, r.failed)
		}
	}
}

func TestCheckProjectWideBans_Pass(t *testing.T) {
	repoRoot(t)
	r := newResult()
	checkProjectWideBans(r)
	if r.failed != 0 {
		t.Errorf("expected all security ban checks to pass, got %d failures", r.failed)
	}
}

func TestCheckMakefile_Pass(t *testing.T) {
	repoRoot(t)
	providers, err := discoverProviders()
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(providers))
	for i, p := range providers {
		names[i] = p.name
	}
	r := newResult()
	checkMakefile(r, names)
	if r.failed != 0 {
		t.Errorf("expected Makefile checks to pass, got %d failures", r.failed)
	}
}

func TestCheckMakefile_MissingFile(t *testing.T) {
	t.Chdir(t.TempDir())
	r := newResult()
	checkMakefile(r, []string{"alpha"})
	if r.failed == 0 {
		t.Error("expected failure when Makefile is absent")
	}
}

func TestCheckMakefile_MissingTargets(t *testing.T) {
	dir := t.TempDir()
	// Write a minimal Makefile missing report-/integration- targets.
	if err := os.WriteFile(filepath.Join(dir, "Makefile"), []byte("integration: foo\nreports: bar\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	r := newResult()
	checkMakefile(r, []string{"alpha"})
	if r.failed == 0 {
		t.Error("expected failures for missing targets")
	}
}

func TestCheckProxyWiring_Pass(t *testing.T) {
	repoRoot(t)
	providers, err := discoverProviders()
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(providers))
	for i, p := range providers {
		names[i] = p.name
	}
	r := newResult()
	checkProxyWiring(r, names)
	if r.failed != 0 {
		t.Errorf("expected proxy wiring checks to pass, got %d failures", r.failed)
	}
}

func TestCheckProxyWiring_MissingFile(t *testing.T) {
	t.Chdir(t.TempDir())
	r := newResult()
	checkProxyWiring(r, []string{"alpha"})
	if r.failed == 0 {
		t.Error("expected failure when proxy.go is absent")
	}
}

func TestCheckCLIMain_Pass(t *testing.T) {
	repoRoot(t)
	providers, err := discoverProviders()
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(providers))
	for i, p := range providers {
		names[i] = p.name
	}
	r := newResult()
	checkCLIMain(r, names)
	if r.failed != 0 {
		t.Errorf("expected CLI main checks to pass, got %d failures", r.failed)
	}
}

func TestCheckCLIMain_MissingFile(t *testing.T) {
	t.Chdir(t.TempDir())
	r := newResult()
	checkCLIMain(r, []string{"alpha"})
	if r.failed == 0 {
		t.Error("expected failure when internal/verify/factory.go is absent")
	}
}

func TestCheckHelpText_Pass(t *testing.T) {
	repoRoot(t)
	providers, err := discoverProviders()
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(providers))
	for i, p := range providers {
		names[i] = p.name
	}
	envVars := readProviderEnvVars()
	r := newResult()
	checkHelpText(r, names, envVars)
	if r.failed != 0 {
		t.Errorf("expected help text checks to pass, got %d failures", r.failed)
	}
}

func TestCheckHelpText_MissingFile(t *testing.T) {
	t.Chdir(t.TempDir())
	r := newResult()
	checkHelpText(r, []string{"alpha"}, map[string]string{"alpha": "ALPHA_KEY"})
	if r.failed == 0 {
		t.Error("expected failure when help.go is absent")
	}
}

func TestReadProviderEnvVars(t *testing.T) {
	repoRoot(t)
	envVars := readProviderEnvVars()
	if len(envVars) == 0 {
		t.Error("expected non-empty providerEnvVars")
	}
}

func TestReadProviderEnvVars_MissingFile(t *testing.T) {
	t.Chdir(t.TempDir())
	// Should return nil without panic when file is missing.
	envVars := readProviderEnvVars()
	if envVars != nil {
		t.Errorf("expected nil, got %v", envVars)
	}
}

func TestCheckExternalTestPackage_Pass(t *testing.T) {
	repoRoot(t)
	providers, err := discoverProviders()
	if err != nil {
		t.Fatal(err)
	}
	for i := range providers {
		r := newResult()
		checkExternalTestPackage(r, &providers[i])
		if r.failed != 0 {
			t.Errorf("provider %s: expected external test package check to pass", providers[i].name)
		}
	}
}

func TestCheckExternalTestPackage_Fail(t *testing.T) {
	dir := t.TempDir()
	// Write a test file with the internal package name (not _test suffix).
	pDir := filepath.Join(dir, "internal", "provider", "myprov")
	if err := os.MkdirAll(pDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Write test file with same package name (internal, not myprov_test).
	if err := os.WriteFile(filepath.Join(pDir, "myprov_test.go"), []byte("package myprov\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	p := &providerInfo{name: "myprov", dir: filepath.Join("internal", "provider", "myprov")}
	r := newResult()
	checkExternalTestPackage(r, p)
	if r.failed == 0 {
		t.Error("expected failure: test file uses internal package name")
	}
}

func TestCheckExternalTestPackage_NoTestFiles(t *testing.T) {
	dir := t.TempDir()
	pDir := filepath.Join(dir, "internal", "provider", "myprov")
	if err := os.MkdirAll(pDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	p := &providerInfo{name: "myprov", dir: filepath.Join("internal", "provider", "myprov")}
	r := newResult()
	checkExternalTestPackage(r, p)
	if r.failed == 0 {
		t.Error("expected failure: no test files at all")
	}
}

func TestCheckProjectWideBans_WalkError(t *testing.T) {
	// Run from a temp dir that has an internal/ dir but with an unreadable file.
	dir := t.TempDir()
	internalDir := filepath.Join(dir, "internal")
	if err := os.MkdirAll(internalDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(internalDir, "bad.go"), []byte("package p\nINVALID{{{\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	r := newResult()
	// This should fail due to parse error.
	checkProjectWideBans(r)
	if r.failed == 0 {
		t.Error("expected failure due to parse error in walked file")
	}
}

// =============================================================================
// main() — call directly from repo root when all checks pass (no os.Exit).
// =============================================================================

func TestMain_AllPass(t *testing.T) {
	repoRoot(t)
	// main() only calls os.Exit(1) when r.failed > 0. Since the project
	// should pass all teeplint checks, calling main() here returns normally.
	main()
}

// =============================================================================
// discoverProviders — error path from loadProvider
// =============================================================================

func TestDiscoverProviders_LoadError(t *testing.T) {
	dir := t.TempDir()
	pDir := filepath.Join(dir, "internal", "provider", "bad")
	if err := os.MkdirAll(pDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Unparseable Go file causes loadProvider to return an error.
	if err := os.WriteFile(filepath.Join(pDir, "bad.go"), []byte("package bad\nINVALID{{{\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	_, err := discoverProviders()
	if err == nil {
		t.Error("expected error from discoverProviders when a provider fails to parse")
	}
}

// =============================================================================
// checkProxyWiring — fromConfig not found
// =============================================================================

func TestCheckProxyWiring_NoFromConfig(t *testing.T) {
	dir := t.TempDir()
	proxyDir := filepath.Join(dir, "internal", "proxy")
	if err := os.MkdirAll(proxyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	src := "package proxy\nfunc otherFunc() {}\n"
	if err := os.WriteFile(filepath.Join(proxyDir, "proxy.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	r := newResult()
	checkProxyWiring(r, []string{"alpha"})
	if r.failed == 0 {
		t.Error("expected failure: fromConfig not found")
	}
}

// =============================================================================
// checkCLIMain — missing function paths
// =============================================================================

func writeCLIMainDir(t *testing.T, src string) {
	t.Helper()
	dir := t.TempDir()
	factoryDir := filepath.Join(dir, "internal", "verify")
	if err := os.MkdirAll(factoryDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(factoryDir, "factory.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
}

func TestCheckCLIMain_MissingNewAttester(t *testing.T) {
	writeCLIMainDir(t, `package verify
var ProviderEnvVars = map[string]string{"alpha": "ALPHA_KEY"}
func newReportDataVerifier(p string) {}
func supplyChainPolicy(p string) {}
`)
	r := newResult()
	checkCLIMain(r, []string{"alpha"})
	if r.failed == 0 {
		t.Error("expected failure: newAttester not found")
	}
}

func TestCheckCLIMain_MissingRDV(t *testing.T) {
	writeCLIMainDir(t, `package verify
var ProviderEnvVars = map[string]string{"alpha": "ALPHA_KEY"}
func newAttester(p string) {
	switch p {
	case "alpha":
	}
}
func supplyChainPolicy(p string) {}
`)
	r := newResult()
	checkCLIMain(r, []string{"alpha"})
	if r.failed == 0 {
		t.Error("expected failure: newReportDataVerifier not found")
	}
}

func TestCheckCLIMain_MissingSCP(t *testing.T) {
	writeCLIMainDir(t, `package verify
var ProviderEnvVars = map[string]string{"alpha": "ALPHA_KEY"}
func newAttester(p string) {
	switch p {
	case "alpha":
	}
}
func newReportDataVerifier(p string) {
	switch p {
	case "alpha":
	}
}
`)
	r := newResult()
	checkCLIMain(r, []string{"alpha"})
	if r.failed == 0 {
		t.Error("expected failure: supplyChainPolicy not found")
	}
}

func TestCheckCLIMain_MissingProviderInSwitches(t *testing.T) {
	writeCLIMainDir(t, `package verify
var ProviderEnvVars = map[string]string{"alpha": "ALPHA_KEY"}
func newAttester(p string) {
	switch p {
	case "other":
	}
}
func newReportDataVerifier(p string) {
	switch p {
	case "other":
	}
}
func supplyChainPolicy(p string) {
	switch p {
	case "other":
	}
}
`)
	r := newResult()
	checkCLIMain(r, []string{"alpha"})
	// alpha is missing from all three switches.
	if r.failed == 0 {
		t.Error("expected failures: provider missing from switches")
	}
}

// =============================================================================
// checkHelpText — skip path when envVar is empty
// =============================================================================

func writeHelpDir(t *testing.T, src string) {
	t.Helper()
	dir := t.TempDir()
	mainDir := filepath.Join(dir, "cmd", "teep")
	if err := os.MkdirAll(mainDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mainDir, "help.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
}

func TestCheckHelpText_SkipEmptyEnvVar(t *testing.T) {
	writeHelpDir(t, `package main
func printOverview() { println(`+"`"+`alpha`+"`"+`) }
func printServeHelp() { println(`+"`"+`alpha`+"`"+`) }
func printVerifyHelp() { println(`+"`"+`alpha`+"`"+`) }
`)
	r := newResult()
	// Empty string for envVar triggers the skip path.
	checkHelpText(r, []string{"alpha"}, map[string]string{"alpha": ""})
	if r.skipped == 0 {
		t.Error("expected skip when envVar is empty")
	}
}

func TestCheckHelpText_MissingEnvVarInText(t *testing.T) {
	writeHelpDir(t, `package main
func printOverview() { println(`+"`"+`no vars here`+"`"+`) }
func printServeHelp() { println(`+"`"+`alpha`+"`"+`) }
func printVerifyHelp() { println(`+"`"+`alpha`+"`"+`) }
`)
	r := newResult()
	checkHelpText(r, []string{"alpha"}, map[string]string{"alpha": "ALPHA_KEY"})
	if r.failed == 0 {
		t.Error("expected failure: env var not in overview text")
	}
}

func TestCheckHelpText_MissingProviderInServe(t *testing.T) {
	writeHelpDir(t, `package main
func printOverview() { println(`+"`"+`ALPHA_KEY`+"`"+`) }
func printServeHelp() { println(`+"`"+`no providers`+"`"+`) }
func printVerifyHelp() { println(`+"`"+`alpha`+"`"+`) }
`)
	r := newResult()
	checkHelpText(r, []string{"alpha"}, map[string]string{"alpha": "ALPHA_KEY"})
	if r.failed == 0 {
		t.Error("expected failure: provider not in serve help text")
	}
}

func TestCheckHelpText_MissingProviderInVerify(t *testing.T) {
	writeHelpDir(t, `package main
func printOverview() { println(`+"`"+`ALPHA_KEY`+"`"+`) }
func printServeHelp() { println(`+"`"+`alpha`+"`"+`) }
func printVerifyHelp() { println(`+"`"+`no providers`+"`"+`) }
`)
	r := newResult()
	checkHelpText(r, []string{"alpha"}, map[string]string{"alpha": "ALPHA_KEY"})
	if r.failed == 0 {
		t.Error("expected failure: provider not in verify help text")
	}
}

// =============================================================================
// collectCompositeLitKeys — non-BasicLit key is skipped
// =============================================================================

func TestCollectCompositeLitKeys_NonLitKey(t *testing.T) {
	// A map literal with an identifier key (not a string literal) — should be skipped.
	f, _ := parseGo(t, `package p
const k = "x"
var myMap = map[string]string{k: "val"}
`)
	keys := collectCompositeLitKeys(f, "myMap")
	if len(keys) != 0 {
		t.Errorf("expected no keys from non-literal key, got %v", keys)
	}
}

// =============================================================================
// collectSwitchCases — non-string case literal
// =============================================================================

func TestCollectSwitchCases_IntCase(t *testing.T) {
	f, _ := parseGo(t, `package p
func fn(n int) {
	switch n {
	case 1:
	case 2:
	}
}
`)
	fd := findFunc(f, "fn")
	cases := collectSwitchCases(fd.Body)
	// Integer literals should not be collected.
	if len(cases) != 0 {
		t.Errorf("expected no cases for int switch, got %v", cases)
	}
}

// =============================================================================
// readProviderEnvVars — non-BasicLit key/value paths
// =============================================================================

func TestReadProviderEnvVars_NonLitKeyVal(t *testing.T) {
	dir := t.TempDir()
	factoryDir := filepath.Join(dir, "internal", "verify")
	if err := os.MkdirAll(factoryDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// ProviderEnvVars with identifier (non-literal) key — should be skipped.
	src := `package verify
const k = "alpha"
var ProviderEnvVars = map[string]string{k: "ALPHA_KEY"}
`
	if err := os.WriteFile(filepath.Join(factoryDir, "factory.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	envVars := readProviderEnvVars()
	if len(envVars) != 0 {
		t.Errorf("expected no entries from non-literal key, got %v", envVars)
	}
}

func TestReadProviderEnvVars_NonLitValue(t *testing.T) {
	dir := t.TempDir()
	factoryDir := filepath.Join(dir, "internal", "verify")
	if err := os.MkdirAll(factoryDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// ProviderEnvVars with identifier (non-literal) value — should be skipped.
	src := `package verify
const v = "ALPHA_KEY"
var ProviderEnvVars = map[string]string{"alpha": v}
`
	if err := os.WriteFile(filepath.Join(factoryDir, "factory.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	envVars := readProviderEnvVars()
	if len(envVars) != 0 {
		t.Errorf("expected no entries from non-literal value, got %v", envVars)
	}
}

// =============================================================================
// checkExternalTestPackage — export_test.go is skipped
// =============================================================================

func TestCheckExternalTestPackage_ExportTestSkipped(t *testing.T) {
	dir := t.TempDir()
	pDir := filepath.Join(dir, "internal", "provider", "myprov")
	if err := os.MkdirAll(pDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// export_test.go uses internal package name — should be skipped.
	// The real test file uses the external package name.
	if err := os.WriteFile(filepath.Join(pDir, "export_test.go"), []byte("package myprov\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pDir, "myprov_test.go"), []byte("package myprov_test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	p := &providerInfo{name: "myprov", dir: filepath.Join("internal", "provider", "myprov")}
	r := newResult()
	checkExternalTestPackage(r, p)
	if r.failed != 0 {
		t.Errorf("expected pass: myprov_test.go uses external package, export_test.go should be skipped")
	}
}

// =============================================================================
// hasStruct — non-struct type in TYPE decl
// =============================================================================

func TestHasStruct_NonStructTypeDecl(t *testing.T) {
	// TYPE decl exists with the right name but not a struct (interface).
	f, _ := parseGo(t, `package p; type Attester interface{ Attest() }`)
	if hasStruct([]*ast.File{f}, "Attester") {
		t.Error("expected false: Attester is an interface, not a struct")
	}
}

// =============================================================================
// checkFromConfigFieldAssignment — non-string case (skipped)
// =============================================================================

func TestCheckFromConfigFieldAssignment_IntCase(t *testing.T) {
	f, _ := parseGo(t, `package p
func fromConfig(n int) {
	switch n {
	case 1:
		p.ChatPath = "/v1"
	}
}
`)
	fd := findFunc(f, "fromConfig")
	r := newResult()
	// "alpha" is not an int case, so the assignment won't be found.
	checkFromConfigFieldAssignment(r, fd, []string{"alpha"}, "ChatPath")
	if r.failed == 0 {
		t.Error("expected failure: provider not found in int-cased switch")
	}
}
