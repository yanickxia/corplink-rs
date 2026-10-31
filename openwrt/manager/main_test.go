package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) *manager {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "corplink-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	m := &manager{configDir: filepath.Join(dir, "config"), runDir: filepath.Join(dir, "run"), service: func(string) error { return errors.New("stopped") }}
	c := defaults()
	c["company_name"], c["device_id"], c["device_name"], c["state"] = "example", strings.Repeat("A", 40), "Test+device", "Login"
	c["private_key"], c["code"], c["password"] = "PRIVATE_SENTINEL", "OTP_SENTINEL", "PASSWORD_SENTINEL"
	if err := writeJSON(m.configPath(), c); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(m.cookiePath(), []byte("ORIGINAL_SESSION")); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestPublicConfigDoesNotExposeCredentials(t *testing.T) {
	m := fixture(t)
	r, err := m.call("get_config", object{})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r)
	for _, secret := range []string{"PRIVATE_SENTINEL", "OTP_SENTINEL", "PASSWORD_SENTINEL", "ORIGINAL_SESSION", "private_key"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("public RPC exposed %s", secret)
		}
	}
}

func TestExistingConfigAllowsOmittedOrNullStrategy(t *testing.T) {
	for _, omitted := range []bool{true, false} {
		m := fixture(t)
		c, _ := m.config()
		c["vpn_select_strategy"] = nil
		if omitted {
			delete(c, "vpn_select_strategy")
		}
		if err := writeJSON(m.configPath(), c); err != nil {
			t.Fatal(err)
		}
		before := fingerprint(m.configPath())
		r, err := m.call("status", object{})
		if err != nil || r["configured"] != true {
			t.Fatalf("existing valid config rejected: %v %v", r, err)
		}
		if publicConfig(c)["vpn_select_strategy"] != "default" {
			t.Fatal("missing strategy did not render the core's default")
		}
		if fingerprint(m.configPath()) != before {
			t.Fatal("read-only status changed existing config")
		}
		if _, err := m.save(object{"port": float64(1190)}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPortChangePreservesSessionAndIdentityChangeInvalidatesIt(t *testing.T) {
	m := fixture(t)
	r, err := m.save(object{"port": float64(1190)})
	if err != nil || r["login_required"] != false {
		t.Fatalf("port save: %v %v", r, err)
	}
	c, _ := m.config()
	if text(c["private_key"]) != "PRIVATE_SENTINEL" || !m.loggedIn(c) {
		t.Fatal("port edit altered credentials")
	}
	r, err = m.save(object{"device_id": strings.Repeat("B", 40)})
	if err != nil || r["login_required"] != true {
		t.Fatalf("identity save: %v %v", r, err)
	}
	c, _ = m.config()
	if c["code"] != nil || text(c["state"]) != "Init" {
		t.Fatal("identity edit retained old authentication")
	}
	if _, err := os.Stat(m.cookiePath()); !os.IsNotExist(err) {
		t.Fatal("identity edit retained old cookie")
	}
	backups, _ := filepath.Glob(filepath.Join(m.configDir, "backups", "*", "corplink-n5100_cookies.json"))
	if len(backups) == 0 {
		t.Fatal("no session backup")
	}
	info, _ := os.Stat(m.configPath())
	if info.Mode().Perm() != 0600 {
		t.Fatal("config permissions")
	}
}

func TestRejectUnsafeOrUnsupportedConfiguration(t *testing.T) {
	for _, input := range []object{
		{"auto_setup_routes": true}, {"private_key": "replacement"}, {"port": float64(22)}, {"port": float64(1188.5)},
		{"server": "http://vpn.example"}, {"server": "https://user:secret@vpn.example"},
		{"device_id": "random-device"}, {"device_name": "line\nbreak"}, {"platform": "$(touch /tmp/unsafe)"},
	} {
		m := fixture(t)
		before := fingerprint(m.configPath())
		if _, err := m.save(input); err == nil {
			t.Fatalf("accepted unsafe configuration: %v", input)
		}
		if fingerprint(m.configPath()) != before {
			t.Fatal("rejected edit changed configuration")
		}
	}
}

func TestRunningServiceCannotBeReauthenticatedOrReconfigured(t *testing.T) {
	m := fixture(t)
	m.service = func(string) error { return nil }
	if _, err := m.save(object{"port": float64(1189)}); err == nil {
		t.Fatal("saved while running")
	}
	if _, err := m.begin(); err == nil {
		t.Fatal("reauthenticated while running")
	}
	if _, err := m.call("control", object{"action": "stop; touch /tmp/unsafe"}); err == nil {
		t.Fatal("accepted arbitrary command")
	}
}

func TestLogsExcludeCredentialsAndLimitOutput(t *testing.T) {
	raw := "corplink_rs cookie SECRET\ncorplink_rs 2fa code generated: 123456\ncorplink_rs otp OTP_SENTINEL\ncorplink_rs password PASSWORD_SENTINEL\ncorplink_rs config={value:danger}\n" +
		"corplink_rs ERROR request https://vpn.example/api?code=CALLBACK_SECRET failed\ncorplink_rs connection failed for somebody@example.test\n"
	result := strings.Join(sanitizeLog(raw), "\n")
	for _, secret := range []string{"SECRET", "123456", "PASSWORD_SENTINEL", "somebody@example.test", "config="} {
		if strings.Contains(result, secret) {
			t.Fatalf("log exposed %s", secret)
		}
	}
	if !strings.Contains(result, "connection failed") {
		t.Fatal("lost useful diagnostic")
	}
	if len(sanitizeLog(strings.Repeat("corplink_rs connection ready\n", 100))) != 60 {
		t.Fatal("log bound")
	}
}

func prepareWorker(t *testing.T, m *manager, success bool) (string, <-chan error) {
	t.Helper()
	id := randomID()
	dir := filepath.Join(m.runDir, "auth-"+id)
	c, _ := m.config()
	c["state"] = "Init"
	if err := writeJSON(filepath.Join(dir, "config.json"), c); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(dir, "baseline"), []byte(fingerprint(m.configPath()))); err != nil {
		t.Fatal(err)
	}
	finished, _ := m.config()
	finished["code"] = "NEW_OTP"
	finished["state"] = "Login"
	if err := writeJSON(filepath.Join(dir, "completed.json"), finished); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
set -eu
dir=${2%/*}
printf '%s\n' '{"event":"authorize","url":"https://sso.example/authorize?state=demo"}' '{"event":"prompt","kind":"callback","prompt":"Callback"}'
IFS= read -r callback
printf '%s\n' '{"event":"prompt","kind":"code","prompt":"Code"}'
IFS= read -r code
`
	if success {
		script += `cp "$dir/completed.json" "$dir/config.json"
printf '%s\n' 'NEW_SESSION' > "$dir/corplink-n5100_cookies.json"
printf '%s\n' '{"event":"done"}'
`
	} else {
		script += "exit 1\n"
	}
	m.core = filepath.Join(m.runDir, "fake-core")
	if err := os.WriteFile(m.core, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(m.statePath(), authState{ID: id, Stage: "starting", Expires: time.Now().Add(time.Minute).Unix()}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- m.worker(id) }()
	return id, done
}

func waitPrompt(t *testing.T, m *manager, kind string) authState {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s := m.authState()
		if s.Stage == "waiting" && s.Kind == kind {
			return s
		}
		if s.Stage == "error" {
			t.Fatalf("unexpected auth failure: %s", s.Message)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s: %+v", kind, m.authState())
	return authState{}
}

func submit(t *testing.T, m *manager, s authState) {
	t.Helper()
	r, err := m.authRequest("login_submit", object{"id": s.ID, "prompt_id": float64(s.PromptID), "value": "INPUT_SECRET"})
	if err != nil || r["ok"] != true {
		t.Fatalf("submit failed: %v %v", r, err)
	}
}

func TestLoginWorkerMFAAndAtomicPromotion(t *testing.T) {
	m := fixture(t)
	_, done := prepareWorker(t, m, true)
	first := waitPrompt(t, m, "callback")
	submit(t, m, first)
	second := waitPrompt(t, m, "code")
	r, err := m.authRequest("login_submit", object{"id": first.ID, "prompt_id": float64(first.PromptID), "value": "REPLAY"})
	if err == nil && r["ok"] == true {
		t.Fatal("accepted stale callback replay")
	}
	submit(t, m, second)
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not finish")
	}
	c, _ := m.config()
	if text(c["code"]) != "NEW_OTP" || !m.loggedIn(c) {
		t.Fatal("new session not promoted")
	}
	s := m.authState()
	if s.Stage != "done" || s.URL != "" || s.Prompt != "" {
		t.Fatalf("completion leaked pending state: %+v", s)
	}
	b, _ := os.ReadFile(m.statePath())
	if strings.Contains(string(b), "INPUT_SECRET") {
		t.Fatal("input persisted in status")
	}
	dirs, _ := filepath.Glob(filepath.Join(m.runDir, "auth-*"))
	if len(dirs) != 0 {
		t.Fatal("temporary credential directory left behind")
	}
}

func TestCancelledOrFailedLoginKeepsExistingSession(t *testing.T) {
	for _, cancel := range []bool{true, false} {
		m := fixture(t)
		original := fingerprint(m.configPath())
		id, done := prepareWorker(t, m, false)
		first := waitPrompt(t, m, "callback")
		if cancel {
			r, err := m.authRequest("login_cancel", object{"id": id})
			if err != nil || r["ok"] != true {
				t.Fatalf("cancel: %v %v", r, err)
			}
		} else {
			submit(t, m, first)
			submit(t, m, waitPrompt(t, m, "code"))
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("worker did not exit")
		}
		if fingerprint(m.configPath()) != original {
			t.Fatal("failed auth changed configuration")
		}
		b, _ := os.ReadFile(m.cookiePath())
		if string(b) != "ORIGINAL_SESSION" {
			t.Fatal("failed auth replaced session")
		}
	}
}

func TestConcurrentConfigChangePreventsPromotion(t *testing.T) {
	m := fixture(t)
	_, done := prepareWorker(t, m, true)
	first := waitPrompt(t, m, "callback")
	submit(t, m, first)
	second := waitPrompt(t, m, "code")
	c, _ := m.config()
	c["vpn_server_name"] = "CHANGED_EXTERNALLY"
	_ = writeJSON(m.configPath(), c)
	submit(t, m, second)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not exit")
	}
	c, _ = m.config()
	if text(c["vpn_server_name"]) != "CHANGED_EXTERNALLY" || text(c["code"]) != "OTP_SENTINEL" {
		t.Fatal("external change overwritten")
	}
	if m.authState().Stage != "error" {
		t.Fatal("expected conflict")
	}
}
