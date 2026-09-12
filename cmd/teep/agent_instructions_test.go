// Anthropic refuses to follow AGENTS.md convention in order to force projects
// to choose between advertising for them or accepting undirected submissions
// from their sabotage-prone code agent harness.
//
// These tests require Claude Code sessions to use this repository's AGENTS.md
// through a local CLAUDE.md symlink. The symlink must remain untracked.
//
// These tests must remain in place until
// https://github.com/anthropics/claude-code/issues/31005
// is implemented with actual AGENTS.md support (and not just quietly closed
// like https://github.com/anthropics/claude-code/issues/6235 was).

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAgentInstructionsUntracked(t *testing.T) {
	root := filepath.Join("..", "..")
	if _, err := os.Lstat(filepath.Join(root, "CLAUDE.md")); errors.Is(err, os.ErrNotExist) {
		// Absence is permitted here, so return success rather than t.Skip.
		// TestAgentInstructions requires the link when CLAUDECODE=1.
		return
	} else if err != nil {
		t.Fatal(err)
	}
	if err := checkAgentInstructionsUntracked(root); err != nil {
		t.Fatal(err)
	}
}

func checkAgentInstructionsUntracked(root string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	index, err := exec.CommandContext(ctx, "git", "-C", root, "rev-parse", "--path-format=absolute", "--git-path", "index").Output()
	if err != nil {
		return fmt.Errorf("locate Git index: %w", err)
	}
	// Register index changes with Go's test cache, including in Git worktrees.
	if _, err := os.Stat(strings.TrimSuffix(string(index), "\n")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat Git index: %w", err)
	}
	cmd := exec.CommandContext(ctx, "git", "-C", root, "ls-files", "--cached", "-z", "--", "CLAUDE.md")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("check whether CLAUDE.md is tracked: %w", err)
	}
	if len(output) != 0 {
		return errors.New("CLAUDE.md must remain untracked; remove it from the Git index with git rm --cached -- CLAUDE.md, then exclude /CLAUDE.md locally")
	}
	return nil
}

func TestAgentInstructions(t *testing.T) {
	if os.Getenv("CLAUDECODE") != "1" {
		// Other environments do not require this link. Return success rather
		// than t.Skip: this is an allowed state, not a missing test prerequisite.
		return
	}
	if err := checkAgentInstructionsLink(filepath.Join("..", "..")); err != nil {
		t.Fatalf("%v\nRead AGENTS.md, then run from the repository root:\n"+
			"  ln -s AGENTS.md CLAUDE.md\n"+
			"Exclude /CLAUDE.md locally in the file returned by git rev-parse --git-path info/exclude. "+
			"Do not commit the symlink or add it to .gitignore.", err)
	}
}

func checkAgentInstructionsLink(root string) error {
	link := filepath.Join(root, "CLAUDE.md")
	info, err := os.Lstat(link)
	if err != nil {
		return fmt.Errorf("CLAUDE.md must be a symlink to AGENTS.md: %w", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return errors.New("CLAUDE.md must be a symlink to AGENTS.md")
	}
	target, err := os.Stat(link)
	if err != nil {
		return fmt.Errorf("resolve CLAUDE.md: %w", err)
	}
	agents, err := os.Stat(filepath.Join(root, "AGENTS.md"))
	if err != nil {
		return fmt.Errorf("stat AGENTS.md: %w", err)
	}
	if !agents.Mode().IsRegular() || !os.SameFile(target, agents) {
		return errors.New("CLAUDE.md must resolve to the repository's AGENTS.md file")
	}
	return nil
}

func TestCheckAgentInstructionsLink(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target string
		plain  bool
		valid  bool
	}{
		{name: "missing"},
		{name: "regular file", plain: true},
		{name: "broken link", target: "missing.md"},
		{name: "wrong file", target: "OTHER.md"},
		{name: "directory", target: "."},
		{name: "relative link", target: "AGENTS.md", valid: true},
		{name: "absolute link", target: "absolute", valid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for _, name := range []string{"AGENTS.md", "OTHER.md"} {
				if err := os.WriteFile(filepath.Join(root, name), []byte("Instructions\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			link := filepath.Join(root, "CLAUDE.md")
			if tc.plain {
				if err := os.WriteFile(link, []byte("Instructions\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.target != "" {
				target := tc.target
				if target == "absolute" {
					target = filepath.Join(root, "AGENTS.md")
				}
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
			}
			if err := checkAgentInstructionsLink(root); (err == nil) != tc.valid {
				t.Fatalf("checkAgentInstructionsLink() = %v, want valid=%t", err, tc.valid)
			}
		})
	}
}

func TestCheckAgentInstructionsUntracked(t *testing.T) {
	for _, tc := range []struct {
		name    string
		init    bool
		tracked bool
	}{
		{name: "untracked", init: true},
		{name: "tracked", init: true, tracked: true},
		{name: "not a repository"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "AGENTS.md"), []byte("Instructions\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("AGENTS.md", filepath.Join(root, "CLAUDE.md")); err != nil {
				t.Fatal(err)
			}
			if tc.init {
				runAgentInstructionsGit(t, root, "init", "--quiet")
			}
			if tc.tracked {
				runAgentInstructionsGit(t, root, "add", "--", "CLAUDE.md")
			}
			err := checkAgentInstructionsUntracked(root)
			wantValid := tc.init && !tc.tracked
			if (err == nil) != wantValid {
				t.Fatalf("checkAgentInstructionsUntracked() = %v, want valid=%t", err, wantValid)
			}
		})
	}
}

func runAgentInstructionsGit(t *testing.T, root string, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", root}, args...)...)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
}
