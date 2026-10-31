package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type authState struct {
	ID       string `json:"id"`
	Stage    string `json:"stage"`
	URL      string `json:"url,omitempty"`
	Prompt   string `json:"prompt,omitempty"`
	Kind     string `json:"kind,omitempty"`
	PromptID int    `json:"prompt_id"`
	Message  string `json:"message,omitempty"`
	Expires  int64  `json:"expires"`
}

func (s authState) Active() bool {
	return s.Expires > time.Now().Unix() && (s.Stage == "starting" || s.Stage == "waiting" || s.Stage == "processing")
}

func (m *manager) authState() authState {
	s := authState{Stage: "idle"}
	b, err := os.ReadFile(m.statePath())
	if err == nil {
		_ = json.Unmarshal(b, &s)
	}
	if s.Stage != "idle" && s.Expires <= time.Now().Unix() && (s.Stage == "starting" || s.Stage == "waiting" || s.Stage == "processing") {
		s.Stage, s.Message, s.URL, s.Prompt = "expired", "登录已超时，请重新开始", "", ""
	}
	return s
}

type authCommand struct {
	args  object
	reply chan object
	sent  chan struct{}
}
type coreEvent struct {
	Event   string `json:"event"`
	URL     string `json:"url"`
	Prompt  string `json:"prompt"`
	Kind    string `json:"kind"`
	Message string `json:"message"`
	ExitOK  bool
}

func (m *manager) promote(dir, id string) error {
	lock, err := m.lock()
	if err != nil {
		return err
	}
	defer lock.Close()
	if m.running() || m.authState().ID != id {
		return errors.New("服务或登录状态已变化，未覆盖现有会话")
	}
	baseline, err := os.ReadFile(filepath.Join(dir, "baseline"))
	if err != nil || string(baseline) != fingerprint(m.configPath()) {
		return errors.New("登录期间配置已被修改，请使用最新配置重新登录")
	}
	c, err := readObject(filepath.Join(dir, "config.json"))
	if err != nil || text(c["state"]) != "Login" {
		return errors.New("登录未完成，未替换原有会话")
	}
	if err = validate(c); err != nil {
		return err
	}
	cookie, err := os.ReadFile(filepath.Join(dir, "corplink-n5100_cookies.json"))
	if err != nil || len(cookie) == 0 || len(cookie) > 1024*1024 {
		return errors.New("登录没有生成有效会话")
	}
	if err = m.backup(); err != nil {
		return errors.New("备份原有会话失败，未应用登录结果")
	}
	old, oldErr := os.ReadFile(m.cookiePath())
	if err = atomicWrite(m.cookiePath(), cookie); err != nil {
		return errors.New("保存会话失败")
	}
	if err = writeJSON(m.configPath(), c); err != nil {
		if oldErr == nil {
			_ = atomicWrite(m.cookiePath(), old)
		} else {
			_ = os.Remove(m.cookiePath())
		}
		return errors.New("保存登录配置失败，已恢复原会话")
	}
	return nil
}

func (m *manager) worker(id string) error {
	if !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(id) {
		return errors.New("invalid login id")
	}
	s := m.authState()
	if s.ID != id || !s.Active() {
		return errors.New("inactive login")
	}
	dir := filepath.Join(m.runDir, "auth-"+id)
	defer os.RemoveAll(dir)
	finish := func(stage, message string) {
		s.Stage, s.Message, s.URL, s.Prompt, s.Kind = stage, message, "", "", ""
		_ = writeJSON(m.statePath(), s)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(s.Expires, 0))
	defer cancel()
	_ = os.Remove(m.socketPath())
	listener, err := net.Listen("unix", m.socketPath())
	if err != nil {
		finish("error", "无法创建本地登录通道")
		return err
	}
	defer listener.Close()
	defer os.Remove(m.socketPath())
	if err = os.Chmod(m.socketPath(), 0600); err != nil {
		finish("error", "无法保护登录通道")
		return err
	}
	commands := make(chan authCommand)
	go func() {
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			var args object
			if e = json.NewDecoder(io.LimitReader(conn, 16384)).Decode(&args); e != nil {
				conn.Close()
				continue
			}
			reply := make(chan object, 1)
			sent := make(chan struct{})
			select {
			case commands <- authCommand{args, reply, sent}:
			case <-ctx.Done():
				conn.Close()
				return
			}
			select {
			case result := <-reply:
				json.NewEncoder(conn).Encode(result)
			case <-ctx.Done():
			}
			conn.Close()
			close(sent)
		}
	}()
	cmd := exec.CommandContext(ctx, m.core, "--login-json", filepath.Join(dir, "config.json"))
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "RUST_LOG=error", "LANG=C.UTF-8"}
	input, err := cmd.StdinPipe()
	if err != nil {
		finish("error", "无法创建登录输入")
		return err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		finish("error", "无法创建登录输出")
		return err
	}
	cmd.Stderr = io.Discard // Never forward credential-bearing core diagnostics to LuCI.
	if err = cmd.Start(); err != nil {
		finish("error", "无法运行 Corplink 登录程序")
		return err
	}
	defer input.Close()
	events := make(chan coreEvent, 16)
	go func() {
		scan := bufio.NewScanner(output)
		scan.Buffer(make([]byte, 4096), 16384)
		for scan.Scan() {
			var event coreEvent
			if json.Unmarshal(scan.Bytes(), &event) != nil {
				continue
			}
			select {
			case events <- event:
			case <-ctx.Done():
			}
		}
		if scan.Err() != nil {
			cancel()
		}
		err := cmd.Wait()
		events <- coreEvent{Event: "exit", ExitOK: err == nil}
	}()
	completed := false
	for {
		select {
		case <-ctx.Done():
			finish("expired", "登录已超时，请重新开始")
			return nil
		case command := <-commands:
			a := command.args
			fail := func(message string) { command.reply <- object{"ok": false, "error": message} }
			if text(a["id"]) != id {
				fail("登录页面已过期")
				continue
			}
			if text(a["method"]) == "login_cancel" {
				finish("cancelled", "登录已取消，原有会话已保留")
				command.reply <- object{"ok": true}
				// Let the RPC response flush before closing its private socket.
				select {
				case <-command.sent:
				case <-time.After(2 * time.Second):
				}
				input.Close()
				return nil
			}
			if text(a["method"]) != "login_submit" || s.Stage != "waiting" {
				fail("当前没有待提交的登录步骤")
				continue
			}
			n, ok := a["prompt_id"].(float64)
			if !ok || n != float64(s.PromptID) {
				fail("此步骤已提交或已过期，请刷新状态")
				continue
			}
			value := text(a["value"])
			if value == "" || len(value) > 8192 || strings.ContainsAny(value, "\r\n\x00") {
				fail("输入格式无效")
				continue
			}
			s.Stage, s.Prompt, s.Message = "processing", "", ""
			_ = writeJSON(m.statePath(), s)
			if _, err = io.WriteString(input, value+"\n"); err != nil {
				fail("登录进程已退出，请重新开始")
				finish("error", "登录进程已退出")
				return nil
			}
			command.reply <- object{"ok": true}
		case event := <-events:
			switch event.Event {
			case "authorize":
				if !safeURL(event.URL) {
					finish("error", "登录服务返回的授权地址无效")
					return nil
				}
				s.URL = event.URL
			case "prompt":
				if event.Kind != "callback" && event.Kind != "code" {
					finish("error", "当前登录步骤暂不支持")
					return nil
				}
				s.Stage, s.Prompt, s.Kind = "waiting", event.Prompt, event.Kind
				s.PromptID++
			case "error":
				s.Message = event.Message
			case "done":
				completed = true
			case "exit":
				if !event.ExitOK || !completed {
					message := s.Message
					if message == "" {
						message = "登录失败，请重试并确认核心支持网页登录"
					}
					finish("error", message)
					return nil
				}
				if err = m.promote(dir, id); err != nil {
					finish("error", err.Error())
					return nil
				}
				finish("done", "登录成功，可以启动代理服务")
				return nil
			default:
				continue
			}
			if err = writeJSON(m.statePath(), s); err != nil {
				return err
			}
		}
	}
}
