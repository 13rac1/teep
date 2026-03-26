// Command teeplint is an architectural linter for the teep project.
// It discovers providers from internal/provider/*/ and enforces structural
// consistency (AST checks) and architectural completeness (every provider
// wired into all integration points).
//
// Usage:
//
//	go run ./cmd/teeplint
//
// Exit 0 if all checks pass, 1 if any fail.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// result tracks pass/fail/skip counts and whether any check failed.
type result struct {
	passed  int
	failed  int
	skipped int
}

//nolint:goprintffuncname // pass/fail/skip read better than passf/failf/skipf for linter output
func (r *result) pass(format string, args ...any) {
	r.passed++
	fmt.Printf("    [PASS] %s\n", fmt.Sprintf(format, args...))
}

//nolint:goprintffuncname // see pass() above
func (r *result) fail(format string, args ...any) {
	r.failed++
	fmt.Printf("    [FAIL] %s\n", fmt.Sprintf(format, args...))
}

//nolint:goprintffuncname // see pass() above
func (r *result) skip(format string, args ...any) {
	r.skipped++
	fmt.Printf("    [SKIP] %s\n", fmt.Sprintf(format, args...))
}

// providerException encodes known structural deviations for specific providers.
type providerException struct {
	// responseStructName overrides "attestationResponse" for checkResponseStruct.
	responseStructName string
	// parseFunc overrides "ParseAttestationResponse" for checkParseFunc.
	parseFunc string
}

var exceptions = map[string]providerException{
	"nearcloud": {
		responseStructName: "gatewayResponse",
		parseFunc:          "ParseGatewayResponse",
	},
}

const providerDir = "internal/provider"

func main() {
	providers, err := discoverProviders()
	if err != nil {
		fmt.Fprintf(os.Stderr, "teeplint: discover providers: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("teeplint: discovered %d providers: %s\n\n", len(providers), strings.Join(providers, ", "))

	var r result

	// Category 1: Provider package structure.
	fmt.Println("teeplint: checking provider package structure...")
	fmt.Println()
	for _, prov := range providers {
		checkProviderStructure(&r, prov)
		fmt.Println()
	}

	// Category 2: Project-wide security bans.
	fmt.Println("teeplint: checking project-wide security bans...")
	fmt.Println()
	checkProjectWideBans(&r)

	// Category 3: Architectural completeness.
	fmt.Println("teeplint: checking architectural completeness...")
	fmt.Println()

	// Read providerEnvVars from cmd/teep/main.go for help text checks.
	envVars := readProviderEnvVars()

	checkMakefile(&r, providers)
	checkProxyWiring(&r, providers)
	checkCLIMain(&r, providers)
	checkHelpText(&r, providers, envVars)

	// Summary.
	total := r.passed + r.failed + r.skipped
	fmt.Printf("teeplint: %d providers, %d checks: %d passed, %d skipped, %d FAILED\n",
		len(providers), total, r.passed, r.skipped, r.failed)

	if r.failed > 0 {
		os.Exit(1)
	}
}

// discoverProviders scans internal/provider/*/ for directories containing .go files.
func discoverProviders() ([]string, error) {
	entries, err := os.ReadDir(providerDir)
	if err != nil {
		return nil, err
	}
	var providers []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		goFiles, _ := filepath.Glob(filepath.Join(providerDir, e.Name(), "*.go"))
		if len(goFiles) > 0 {
			providers = append(providers, e.Name())
		}
	}
	return providers, nil
}

// =============================================================================
// Category 1: Provider package structure checks
// =============================================================================

func checkProviderStructure(r *result, prov string) {
	dir := filepath.Join(providerDir, prov)
	fmt.Printf("  %s/\n", dir)

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool { //nolint:staticcheck // ParseDir is fine for our use
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ParseComments)
	if err != nil {
		r.fail("parse package: %v", err)
		return
	}

	// Collect all files from all packages in the directory.
	var files []*ast.File
	var fileNames []string
	for _, pkg := range pkgs {
		for name, f := range pkg.Files {
			files = append(files, f)
			fileNames = append(fileNames, name)
		}
	}

	exc := exceptions[prov]

	checkAttestationPathConst(r, fset, files, prov)
	checkResponseStruct(r, fset, files, prov, exc)
	checkAttesterClientField(r, fset, files, prov)
	parseFunc := checkParseFunc(r, fset, files, prov, exc)
	checkParseFuncUsesJSONStrict(r, fset, parseFunc, prov)
	checkFetchUsesLimitReader(r, fset, files, prov)
	checkNoSlogAPIKeyArgs(r, fset, files, prov)
	checkNoJSONRawMessage(r, fset, files, fileNames, prov)
	checkExternalTestPackage(r, dir, prov)
}

// attestationPath string constant.
func checkAttestationPathConst(r *result, fset *token.FileSet, files []*ast.File, prov string) {
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, name := range vs.Names {
					if name.Name == "attestationPath" {
						pos := fset.Position(name.Pos())
						r.pass("attestationPath constant (%s:%d)", filepath.Base(pos.Filename), pos.Line)
						return
					}
				}
			}
		}
	}
	r.fail("attestationPath constant not found in %s", prov)
}

// attestationResponse (or exception) unexported struct.
func checkResponseStruct(r *result, fset *token.FileSet, files []*ast.File, prov string, exc providerException) {
	want := "attestationResponse"
	if exc.responseStructName != "" {
		want = exc.responseStructName
	}
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				if ts.Name.Name == want {
					if _, isStruct := ts.Type.(*ast.StructType); isStruct {
						pos := fset.Position(ts.Name.Pos())
						if exc.responseStructName != "" {
							r.pass("%s struct — %s uses %s (%s:%d)", want, prov, want, filepath.Base(pos.Filename), pos.Line)
						} else {
							r.pass("%s struct (%s:%d)", want, filepath.Base(pos.Filename), pos.Line)
						}
						return
					}
				}
			}
		}
	}
	r.fail("%s struct not found in %s", want, prov)
}

// Attester.client *http.Client field.
func checkAttesterClientField(r *result, fset *token.FileSet, files []*ast.File, prov string) {
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok || ts.Name.Name != "Attester" {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				for _, field := range st.Fields.List {
					for _, name := range field.Names {
						if name.Name == "client" && typeString(field.Type) == "*http.Client" {
							pos := fset.Position(name.Pos())
							r.pass("Attester.client *http.Client (%s:%d)", filepath.Base(pos.Filename), pos.Line)
							return
						}
					}
				}
			}
		}
	}
	r.fail("Attester.client *http.Client field not found in %s", prov)
}

// ParseAttestationResponse (or exception) exists.
func checkParseFunc(r *result, fset *token.FileSet, files []*ast.File, prov string, exc providerException) *ast.FuncDecl {
	want := "ParseAttestationResponse"
	if exc.parseFunc != "" {
		want = exc.parseFunc
	}
	for _, f := range files {
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil {
				continue
			}
			if fd.Name.Name == want {
				pos := fset.Position(fd.Name.Pos())
				if exc.parseFunc != "" {
					r.pass("%s exists — %s uses %s (%s:%d)", want, prov, want, filepath.Base(pos.Filename), pos.Line)
				} else {
					r.pass("%s exists (%s:%d)", want, filepath.Base(pos.Filename), pos.Line)
				}
				return fd
			}
		}
	}
	r.fail("%s function not found in %s", want, prov)
	return nil
}

// Parse function calls jsonstrict.UnmarshalWarn.
func checkParseFuncUsesJSONStrict(r *result, fset *token.FileSet, fd *ast.FuncDecl, prov string) {
	if fd == nil {
		r.fail("%s uses jsonstrict.UnmarshalWarn — no parse function in %s", prov, prov)
		return
	}
	if containsCall(fd.Body, "jsonstrict", "UnmarshalWarn") {
		pos := fset.Position(fd.Name.Pos())
		r.pass("%s uses jsonstrict.UnmarshalWarn (%s:%d)", fd.Name.Name, filepath.Base(pos.Filename), pos.Line)
		return
	}
	pos := fset.Position(fd.Name.Pos())
	r.fail("%s does not call jsonstrict.UnmarshalWarn (%s:%d)", fd.Name.Name, filepath.Base(pos.Filename), pos.Line)
}

// FetchAttestation calls io.LimitReader.
func checkFetchUsesLimitReader(r *result, fset *token.FileSet, files []*ast.File, prov string) {
	for _, f := range files {
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv == nil {
				continue
			}
			if fd.Name.Name == "FetchAttestation" {
				if containsCall(fd.Body, "io", "LimitReader") {
					pos := fset.Position(fd.Name.Pos())
					r.pass("FetchAttestation uses io.LimitReader (%s:%d)", filepath.Base(pos.Filename), pos.Line)
					return
				}
				pos := fset.Position(fd.Name.Pos())
				r.fail("FetchAttestation does not call io.LimitReader (%s:%d)", filepath.Base(pos.Filename), pos.Line)
				return
			}
		}
	}
	r.fail("FetchAttestation method not found in %s", prov)
}

// No slog calls with API key field names.
func checkNoSlogAPIKeyArgs(r *result, fset *token.FileSet, files []*ast.File, prov string) {
	badNames := []string{"apiKey", "api_key", "APIKey", "apikey"}
	for _, f := range files {
		found := false
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "slog" {
				return true
			}
			for _, arg := range call.Args {
				lit, ok := arg.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				val := strings.Trim(lit.Value, `"`)
				for _, bad := range badNames {
					if val == bad {
						pos := fset.Position(lit.Pos())
						r.fail("slog call with %q arg in %s (%s:%d)", bad, prov, filepath.Base(pos.Filename), pos.Line)
						found = true
						return false
					}
				}
			}
			return true
		})
		if found {
			return
		}
	}
	r.pass("no slog calls with API key args")
}

// No json.RawMessage in provider response structs.
// Skips models.go which uses json.RawMessage for pass-through relay (not attestation parsing).
func checkNoJSONRawMessage(r *result, fset *token.FileSet, files []*ast.File, fileNames []string, prov string) {
	var violations []string
	for i, f := range files {
		if filepath.Base(fileNames[i]) == "models.go" {
			continue
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				collectRawMessageViolations(fset, st, ts.Name.Name, fileNames[i], &violations)
			}
		}
	}
	if len(violations) == 0 {
		r.pass("no json.RawMessage in response structs")
		return
	}
	for _, v := range violations {
		r.fail("json.RawMessage field %s in %s", v, prov)
	}
}

func collectRawMessageViolations(fset *token.FileSet, st *ast.StructType, structName, fileName string, violations *[]string) {
	for _, field := range st.Fields.List {
		ts := typeString(field.Type)
		if ts == "json.RawMessage" || ts == "[]json.RawMessage" {
			for _, name := range field.Names {
				pos := fset.Position(name.Pos())
				*violations = append(*violations, fmt.Sprintf("%s.%s (%s:%d)", structName, name.Name, filepath.Base(pos.Filename), pos.Line))
			}
			if len(field.Names) == 0 {
				pos := fset.Position(field.Pos())
				*violations = append(*violations, fmt.Sprintf("%s (embedded) (%s:%d)", structName, filepath.Base(fileName), pos.Line))
			}
		}
		// Recurse into anonymous struct types (inline structs).
		if st2, ok := field.Type.(*ast.StructType); ok {
			fieldName := structName
			if len(field.Names) > 0 {
				fieldName = structName + "." + field.Names[0].Name
			}
			collectRawMessageViolations(fset, st2, fieldName, fileName, violations)
		}
	}
}

// At least one test file uses external package.
func checkExternalTestPackage(r *result, dir, prov string) {
	testFiles, _ := filepath.Glob(filepath.Join(dir, "*_test.go"))
	wantPkg := prov + "_test"
	for _, tf := range testFiles {
		if strings.HasSuffix(filepath.Base(tf), "export_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, tf, nil, parser.PackageClauseOnly)
		if err != nil {
			continue
		}
		if f.Name.Name == wantPkg {
			r.pass("test file uses external package (%s)", filepath.Base(tf))
			return
		}
	}
	r.fail("no test file uses external package %q in %s", wantPkg, prov)
}

// =============================================================================
// Category 2: Project-wide security bans
// =============================================================================

// checkProjectWideBans parses all non-test Go files under internal/ and cmd/
// and runs security ban checks across the full codebase.
func checkProjectWideBans(r *result) {
	dirs := []string{"internal", "cmd"}
	var files []*ast.File
	var names []string
	fset := token.NewFileSet()

	for _, root := range dirs {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return fmt.Errorf("parse %s: %w", path, err)
			}
			files = append(files, f)
			names = append(names, path)
			return nil
		})
		if err != nil {
			r.fail("walk %s: %v", root, err)
			return
		}
	}

	checkNoBytesEqualProject(r, files, names)
	checkNoStringsEqualFold(r, files, names)
	checkNoLogImportProject(r, files, names)
	checkNoMathRand(r, files, names)
	fmt.Println()
}

// No bytes.Equal anywhere in the project (use subtle.ConstantTimeCompare).
func checkNoBytesEqualProject(r *result, files []*ast.File, names []string) {
	var violations []string
	for i, f := range files {
		if containsCall(f, "bytes", "Equal") {
			violations = append(violations, names[i])
		}
	}
	if len(violations) == 0 {
		r.pass("no bytes.Equal (use subtle.ConstantTimeCompare)")
		return
	}
	for _, v := range violations {
		r.fail("bytes.Equal in %s (use subtle.ConstantTimeCompare)", v)
	}
}

// No strings.EqualFold anywhere in the project (use constant-time comparison).
func checkNoStringsEqualFold(r *result, files []*ast.File, names []string) {
	var violations []string
	for i, f := range files {
		if containsCall(f, "strings", "EqualFold") {
			violations = append(violations, names[i])
		}
	}
	if len(violations) == 0 {
		r.pass("no strings.EqualFold (use constant-time comparison)")
		return
	}
	for _, v := range violations {
		r.fail("strings.EqualFold in %s (use constant-time comparison)", v)
	}
}

// No "log" package import (use log/slog).
func checkNoLogImportProject(r *result, files []*ast.File, names []string) {
	var violations []string
	for i, f := range files {
		for _, imp := range f.Imports {
			if strings.Trim(imp.Path.Value, `"`) == "log" {
				violations = append(violations, names[i])
				break
			}
		}
	}
	if len(violations) == 0 {
		r.pass("no \"log\" import (use log/slog)")
		return
	}
	for _, v := range violations {
		r.fail("\"log\" imported in %s (use log/slog)", v)
	}
}

// No math/rand import (use crypto/rand).
func checkNoMathRand(r *result, files []*ast.File, names []string) {
	var violations []string
	for i, f := range files {
		for _, imp := range f.Imports {
			if strings.Trim(imp.Path.Value, `"`) == "math/rand" {
				violations = append(violations, names[i])
				break
			}
		}
	}
	if len(violations) == 0 {
		r.pass("no math/rand import (use crypto/rand)")
		return
	}
	for _, v := range violations {
		r.fail("math/rand imported in %s (use crypto/rand)", v)
	}
}

// =============================================================================
// Category 3: Architectural completeness checks
// =============================================================================

func checkMakefile(r *result, providers []string) {
	fmt.Println("  Makefile")
	data, err := os.ReadFile("Makefile")
	if err != nil {
		r.fail("read Makefile: %v", err)
		return
	}
	content := string(data)
	lines := strings.Split(content, "\n")

	// Find the integration: and reports: dependency lines.
	var integrationLine, reportsLine string
	for _, line := range lines {
		if strings.HasPrefix(line, "integration:") {
			integrationLine = line
		}
		if strings.HasPrefix(line, "reports:") {
			reportsLine = line
		}
	}

	for _, prov := range providers {
		// report-{provider}: target exists.
		targetRe := regexp.MustCompile(`(?m)^report-` + regexp.QuoteMeta(prov) + `:`)
		if targetRe.MatchString(content) {
			r.pass("report-%s target exists", prov)
		} else {
			r.fail("report-%s target missing", prov)
		}

		// reports: target includes report-{provider}.
		if strings.Contains(reportsLine, "report-"+prov) {
			r.pass("reports: includes report-%s", prov)
		} else {
			r.fail("reports: missing report-%s", prov)
		}

		// integration-{provider}: target exists.
		intTargetRe := regexp.MustCompile(`(?m)^integration-` + regexp.QuoteMeta(prov) + `:`)
		if intTargetRe.MatchString(content) {
			r.pass("integration-%s target exists", prov)
		} else {
			r.fail("integration-%s target missing", prov)
		}

		// integration: target includes integration-{provider}.
		if strings.Contains(integrationLine, "integration-"+prov) {
			r.pass("integration: includes integration-%s", prov)
		} else {
			r.fail("integration: missing integration-%s", prov)
		}
	}
	fmt.Println()
}

func checkProxyWiring(r *result, providers []string) {
	fmt.Println("  internal/proxy/proxy.go")
	path := "internal/proxy/proxy.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		r.fail("parse %s: %v", path, err)
		return
	}

	fd := findFunc(f, "fromConfig")
	if fd == nil {
		r.fail("fromConfig function not found in %s", path)
		return
	}

	checkFromConfigDefaultError(r, fd, providers)
	checkFromConfigFieldAssignment(r, fd, providers, "ChatPath")
	checkFromConfigFieldAssignment(r, fd, providers, "Attester")
	checkFromConfigFieldAssignment(r, fd, providers, "ReportDataVerifier")
	checkFromConfigFieldAssignment(r, fd, providers, "SupplyChainPolicy")
	fmt.Println()
}

func checkCLIMain(r *result, providers []string) {
	fmt.Println("  cmd/teep/main.go")
	path := "cmd/teep/main.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		r.fail("parse %s: %v", path, err)
		return
	}

	// providerEnvVars map has key for each provider.
	envVarKeys := collectCompositeLitKeys(f, "providerEnvVars")
	for _, prov := range providers {
		if envVarKeys[prov] {
			r.pass("providerEnvVars has key %q", prov)
		} else {
			r.fail("providerEnvVars missing key %q", prov)
		}
	}

	// newAttester() switch has case for each provider.
	newAttesterFunc := findFunc(f, "newAttester")
	if newAttesterFunc == nil {
		r.fail("newAttester function not found")
	} else {
		cases := collectSwitchCases(newAttesterFunc.Body)
		for _, prov := range providers {
			if cases[prov] {
				r.pass("newAttester switch includes %q", prov)
			} else {
				r.fail("newAttester switch missing %q", prov)
			}
		}
	}

	// newReportDataVerifier() switch has case for each provider.
	rdvFunc := findFunc(f, "newReportDataVerifier")
	if rdvFunc == nil {
		r.fail("newReportDataVerifier function not found")
	} else {
		cases := collectSwitchCases(rdvFunc.Body)
		for _, prov := range providers {
			if cases[prov] {
				r.pass("newReportDataVerifier switch includes %q", prov)
			} else {
				r.fail("newReportDataVerifier switch missing %q", prov)
			}
		}
	}

	// supplyChainPolicy() switch has case for each provider.
	scpFunc := findFunc(f, "supplyChainPolicy")
	if scpFunc == nil {
		r.fail("supplyChainPolicy function not found")
	} else {
		cases := collectSwitchCases(scpFunc.Body)
		for _, prov := range providers {
			if cases[prov] {
				r.pass("supplyChainPolicy switch includes %q", prov)
			} else {
				r.fail("supplyChainPolicy switch missing %q", prov)
			}
		}
	}
	fmt.Println()
}

func checkHelpText(r *result, providers []string, envVars map[string]string) {
	fmt.Println("  cmd/teep/help.go")
	path := "cmd/teep/help.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		r.fail("parse %s: %v", path, err)
		return
	}

	// Extract raw string literal bodies from the three functions.
	overviewText := extractFuncStringLiterals(f, "printOverview")
	serveText := extractFuncStringLiterals(f, "printServeHelp")
	verifyText := extractFuncStringLiterals(f, "printVerifyHelp")

	for _, prov := range providers {
		// printOverview environment section mentions provider env var.
		envVar := envVars[prov]
		if envVar != "" {
			if strings.Contains(overviewText, envVar) {
				r.pass("printOverview mentions %s", envVar)
			} else {
				r.fail("printOverview missing %s for provider %s", envVar, prov)
			}
		} else {
			r.skip("no env var known for %s", prov)
		}

		// printServeHelp PROVIDER line lists provider.
		if strings.Contains(serveText, prov) {
			r.pass("printServeHelp mentions %q", prov)
		} else {
			r.fail("printServeHelp missing %q", prov)
		}

		// printVerifyHelp PROVIDER line lists provider.
		if strings.Contains(verifyText, prov) {
			r.pass("printVerifyHelp mentions %q", prov)
		} else {
			r.fail("printVerifyHelp missing %q", prov)
		}
	}
	fmt.Println()
}

// =============================================================================
// AST helpers
// =============================================================================

// typeString returns a simple string representation of a type expression.
func typeString(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		if x, ok := t.X.(*ast.Ident); ok {
			return x.Name + "." + t.Sel.Name
		}
	case *ast.StarExpr:
		return "*" + typeString(t.X)
	case *ast.ArrayType:
		if t.Len == nil {
			return "[]" + typeString(t.Elt)
		}
	}
	return ""
}

// containsCall checks if the AST node contains a call to pkg.funcName.
func containsCall(node ast.Node, pkg, funcName string) bool {
	if node == nil {
		return false
	}
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		x, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if x.Name == pkg && sel.Sel.Name == funcName {
			found = true
			return false
		}
		return true
	})
	return found
}

// findFunc finds a top-level FuncDecl by name (no receiver).
func findFunc(f *ast.File, name string) *ast.FuncDecl {
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Recv != nil {
			continue
		}
		if fd.Name.Name == name {
			return fd
		}
	}
	return nil
}

// collectSwitchCases collects all string literal case clause values from
// switch statements in a function body.
func collectSwitchCases(body *ast.BlockStmt) map[string]bool {
	cases := make(map[string]bool)
	if body == nil {
		return cases
	}
	ast.Inspect(body, func(n ast.Node) bool {
		cc, ok := n.(*ast.CaseClause)
		if !ok {
			return true
		}
		for _, expr := range cc.List {
			lit, ok := expr.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			val := strings.Trim(lit.Value, `"`)
			cases[val] = true
		}
		return true
	})
	return cases
}

// checkFromConfigDefaultError finds the default case in fromConfig's switch and
// verifies its fmt.Errorf format string mentions every provider name.
func checkFromConfigDefaultError(r *result, fd *ast.FuncDecl, providers []string) {
	var defaultClause *ast.CaseClause
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		cc, ok := n.(*ast.CaseClause)
		if !ok {
			return true
		}
		if cc.List == nil { // default case
			defaultClause = cc
		}
		return true
	})
	if defaultClause == nil {
		r.fail("fromConfig switch has no default case")
		return
	}

	// Find the fmt.Errorf format string in the default body.
	var fmtStr string
	ast.Inspect(defaultClause, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		x, ok := sel.X.(*ast.Ident)
		if !ok || x.Name != "fmt" || sel.Sel.Name != "Errorf" {
			return true
		}
		if len(call.Args) > 0 {
			if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				fmtStr = strings.Trim(lit.Value, `"`)
			}
		}
		return true
	})
	if fmtStr == "" {
		r.fail("fromConfig default case has no fmt.Errorf with string literal")
		return
	}

	for _, prov := range providers {
		if strings.Contains(fmtStr, prov) {
			r.pass("fromConfig default error mentions %q", prov)
		} else {
			r.fail("fromConfig default error missing %q (update the error message)", prov)
		}
	}
}

// checkFromConfigFieldAssignment verifies that each provider's case clause in
// fromConfig assigns p.{field}.
func checkFromConfigFieldAssignment(r *result, fd *ast.FuncDecl, providers []string, field string) {
	// Build a map of provider name → whether p.{field} is assigned.
	assigned := make(map[string]bool)
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		for _, stmt := range sw.Body.List {
			cc, ok := stmt.(*ast.CaseClause)
			if !ok || cc.List == nil {
				continue
			}
			// Extract the provider name from the case literal.
			var provName string
			for _, expr := range cc.List {
				lit, ok := expr.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				provName = strings.Trim(lit.Value, `"`)
			}
			if provName == "" {
				continue
			}
			// Walk the case body for p.{field} assignment.
			for _, s := range cc.Body {
				ast.Inspect(s, func(n ast.Node) bool {
					assign, ok := n.(*ast.AssignStmt)
					if !ok {
						return true
					}
					for _, lhs := range assign.Lhs {
						sel, ok := lhs.(*ast.SelectorExpr)
						if !ok {
							continue
						}
						x, ok := sel.X.(*ast.Ident)
						if !ok {
							continue
						}
						if x.Name == "p" && sel.Sel.Name == field {
							assigned[provName] = true
						}
					}
					return true
				})
			}
		}
		return false // don't recurse into nested switches
	})

	for _, prov := range providers {
		if assigned[prov] {
			r.pass("fromConfig %q sets p.%s", prov, field)
		} else {
			r.fail("fromConfig %q missing p.%s assignment", prov, field)
		}
	}
}

// collectCompositeLitKeys finds a top-level var with the given name and collects
// string keys from its composite literal value.
func collectCompositeLitKeys(f *ast.File, varName string) map[string]bool {
	keys := make(map[string]bool)
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if name.Name != varName || i >= len(vs.Values) {
					continue
				}
				cl, ok := vs.Values[i].(*ast.CompositeLit)
				if !ok {
					continue
				}
				for _, elt := range cl.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					lit, ok := kv.Key.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					keys[strings.Trim(lit.Value, `"`)] = true
				}
			}
		}
	}
	return keys
}

// extractFuncStringLiterals concatenates all raw string literals found in a
// named function's body. Used to scan help text content.
func extractFuncStringLiterals(f *ast.File, funcName string) string {
	fd := findFunc(f, funcName)
	if fd == nil {
		return ""
	}
	var b strings.Builder
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		val := lit.Value
		if strings.HasPrefix(val, "`") {
			b.WriteString(strings.Trim(val, "`"))
		} else {
			b.WriteString(strings.Trim(val, `"`))
		}
		return true
	})
	return b.String()
}

// readProviderEnvVars extracts the providerEnvVars map from cmd/teep/main.go.
func readProviderEnvVars() map[string]string {
	path := "cmd/teep/main.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil
	}
	envVars := make(map[string]string)
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if name.Name != "providerEnvVars" || i >= len(vs.Values) {
					continue
				}
				cl, ok := vs.Values[i].(*ast.CompositeLit)
				if !ok {
					continue
				}
				for _, elt := range cl.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, ok := kv.Key.(*ast.BasicLit)
					if !ok || key.Kind != token.STRING {
						continue
					}
					val, ok := kv.Value.(*ast.BasicLit)
					if !ok || val.Kind != token.STRING {
						continue
					}
					envVars[strings.Trim(key.Value, `"`)] = strings.Trim(val.Value, `"`)
				}
			}
		}
	}
	return envVars
}
