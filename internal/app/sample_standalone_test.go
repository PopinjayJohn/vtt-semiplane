//go:build integration

package app

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestStandaloneBinaryRunsInEmptyDir is the claim the whole sample campaign
// rests on, and the only test that makes it about a binary rather than about
// this repository.
//
// Everything else in this package boots the app in process, with the campaign
// tree sitting in the source directory. That cannot tell a shipped binary from
// a development one, and the difference is the entire point: an operator
// downloads one file, and that file has to carry a campaign. So this builds
// cmd/semiplane with CGO_ENABLED=0 into a temporary directory, runs it from a
// third temporary directory with no repository anywhere near it, points it at an
// empty vault, and asks the resulting HTTP server for a page.
//
// It is behind the `integration` build tag because it shells out to the Go
// toolchain and then runs a server: `make test-integration` runs it, and
// `make test` does not. That is the tag AGENTS.md §9 documents and the Makefile
// already passes; this is its first user.
//
// The port is probed rather than parsed out of the banner, because the banner's
// format belongs to internal/app/banner.go and a formatting change there should
// not fail a test about the campaign. The campaign assertions are the ones that
// matter: 200 on the dashboard, and 200 on a page of the campaign with that
// page's own title in the body.
func TestStandaloneBinaryRunsInEmptyDir(t *testing.T) {
	// No t.Parallel: this builds a binary, and a cold build of the whole tree
	// under a race detector is minutes of CPU that other tests would rather
	// have.
	if testing.Short() {
		t.Skip("builds and runs a binary")
	}
	root := moduleRoot(t)
	dir := t.TempDir()
	exe := filepath.Join(dir, "semiplane")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	build := exec.CommandContext(ctx, "go", "build", "-o", exe, "./cmd/semiplane")
	build.Dir = root
	// CGO_ENABLED=0 is the release configuration and the one that catches an
	// accidental cgo dependency the development build would hide.
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the binary: %v\n%s", err, out)
	}
	if _, err := os.Stat(exe); err != nil {
		t.Fatalf("the build produced no binary: %v", err)
	}

	// A vault the test owns, in a directory with no repository in it, and a
	// working directory that has never seen this source tree. --vault is
	// absolute, so the binary never has to consult the directory it lives in.
	vaultDir := t.TempDir()
	work := t.TempDir()
	port := freePort(t)

	run := exec.CommandContext(ctx, exe,
		"--vault", vaultDir, "--host", "127.0.0.1", "--port", strconv.Itoa(port), "--no-open")
	run.Dir = work
	var banner strings.Builder
	run.Stdout = &banner
	run.Stderr = &banner
	if err := run.Start(); err != nil {
		t.Fatalf("start the binary: %v", err)
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		// SIGTERM, not Kill: main.go traps it and shuts the app down, so the
		// vault is released and the test does not leave a lock behind that
		// makes the next run of the whole suite fail.
		_ = run.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = run.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			_ = run.Process.Kill()
			<-done
		}
	}
	defer stop()

	base := "http://127.0.0.1:" + strconv.Itoa(port)
	waitForServer(t, ctx, base, run, &banner)

	resp := get(t, base+"/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / answered %d, want 200\n%s", resp.StatusCode, banner.String())
	}
	body := readBody(t, resp)
	if strings.Contains(body, "no pages") || strings.Contains(body, "Nothing here yet") {
		t.Errorf("the dashboard reports an empty vault, so the campaign was not extracted:\n%s", truncate(body))
	}

	// The dashboard showing a count is weaker than the campaign being there, so
	// a page of it is fetched directly. The path is the one the campaign's own
	// attachment references assume, which is the coupling TestSampleCampaign-
	// ExercisesEveryFeature pins and this exercises end to end.
	page := base + "/p/" + strings.ReplaceAll("Campaigns/Ashes of the Hollow Crown/Overview.md", " ", "%20")
	resp = get(t, page)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET the campaign's overview answered %d, want 200\n%s", resp.StatusCode, banner.String())
	}
	html := readBody(t, resp)
	if !strings.Contains(html, "Ashes of the Hollow Crown") {
		t.Errorf("the campaign's overview rendered without its own title:\n%s", truncate(html))
	}
	// The public half of a page that also has a hidden half: the title is
	// public, and this is where a leak would show. The fences on it name an
	// author that no account has yet, so on a fresh vault the hidden halves are
	// hidden from everybody including the DM — which is the fail-closed
	// behaviour and is asserted in internal/sample, not here. What is asserted
	// here is that the binary got far enough to serve the page at all.
}

// moduleRoot finds the repository from this test's own source file, so the test
// does not depend on the working directory it was run from.
func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate this test's source file")
	}
	// internal/app/<this file> → the module root is two directories up.
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("no go.mod above %s: %v", root, err)
	}
	return root
}

// freePort asks the kernel for a port and gives it back. The window between the
// close and the binary's bind is the usual one for this trick and is why the
// port is not asserted to be the same one later: nothing here depends on it
// being a particular number, only on it being a free one.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatalf("release the port: %v", err)
	}
	return port
}

// waitForServer polls the root until it answers, and fails with the process's
// output if the process died first — which is what a boot failure looks like
// from out here.
func waitForServer(t *testing.T, ctx context.Context, base string, run *exec.Cmd, banner *strings.Builder) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if run.ProcessState != nil && run.ProcessState.Exited() {
			t.Fatalf("the binary exited before it served anything:\n%s", banner.String())
		}
		resp, err := http.Get(base + "/")
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("the context expired before the server answered: %v\n%s", ctx.Err(), banner.String())
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatalf("the server did not answer within the deadline:\n%s", banner.String())
}

func get(t *testing.T, url string) *http.Response {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("read the response: %v", err)
	}
	return string(b)
}

// truncate keeps a failing message readable. It is a length, not a
// redaction: the response body here is a page this test just fetched, and
// printing it is how a failure is diagnosed.
func truncate(s string) string {
	const max = 2000
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n... (truncated)"
}
