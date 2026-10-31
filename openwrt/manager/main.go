// Corplink's local LuCI RPC plugin. Authentication is delegated to the core;
// no VPN protocol, password exchange, or request signing is implemented here.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type object = map[string]any

type manager struct {
	configDir, runDir, core, init, self string
	service                             func(string) error
}

func production() *manager {
	m := &manager{"/etc/corplink-rs-dev", "/var/run/corplink-rs-dev", "/usr/bin/corplink-rs-dev", "/etc/init.d/corplink-rs-dev", "", nil}
	m.self, _ = os.Executable()
	m.service = func(action string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		return exec.CommandContext(ctx, m.init, action).Run()
	}
	return m
}

func main() {
	syscall.Umask(0077)
	m := production()
	if len(os.Args) == 2 && os.Args[1] == "shutdown" {
		s := m.authState()
		if s.Active() {
			_, _ = m.authRequest("login_cancel", object{"id": s.ID})
		}
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "login-worker" {
		if err := m.worker(os.Args[2]); err != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "list" {
		json.NewEncoder(os.Stdout).Encode(object{
			"status": object{}, "get_config": object{}, "logs": object{},
			"save_config": object{"config": object{}}, "control": object{"action": ""},
			"login_begin": object{}, "login_status": object{},
			"login_submit": object{"id": "", "prompt_id": 0, "value": ""},
			"login_cancel": object{"id": ""},
		})
		return
	}
	if len(os.Args) != 3 || os.Args[1] != "call" {
		os.Exit(1)
	}
	var args object
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 32769)).Decode(&args); err != nil {
		json.NewEncoder(os.Stdout).Encode(object{"ok": false, "error": "无效的请求"})
		return
	}
	result, err := m.call(os.Args[2], args)
	if err != nil {
		result = object{"ok": false, "error": err.Error()}
	}
	json.NewEncoder(os.Stdout).Encode(result)
}

func (m *manager) configPath() string { return filepath.Join(m.configDir, "config.json") }
func (m *manager) cookiePath() string {
	return filepath.Join(m.configDir, "corplink-n5100_cookies.json")
}
func (m *manager) statePath() string  { return filepath.Join(m.runDir, "login.json") }
func (m *manager) socketPath() string { return filepath.Join(m.runDir, "login.sock") }
func text(v any) string               { s, _ := v.(string); return s }

func defaults() object {
	return object{"company_name": "", "username": "", "server": nil, "platform": "bytedance_sso",
		"device_id": "", "device_name": "", "login_flow": "device", "state": "Init",
		"interface_name": "corplink-n5100", "socks5_listen": "127.0.0.1:1188",
		"auto_setup_routes": false, "use_vpn_dns": false, "debug_wg": false,
		"vpn_server_name": nil, "vpn_select_strategy": "default"}
}

func readObject(path string) (object, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v object
	err = json.Unmarshal(b, &v)
	if v == nil && err == nil {
		err = errors.New("object required")
	}
	return v, err
}

func (m *manager) config() (object, error) {
	c, err := readObject(m.configPath())
	if os.IsNotExist(err) {
		return defaults(), nil
	}
	if err != nil {
		return nil, errors.New("无法读取配置，请检查配置文件格式")
	}
	return c, nil
}

func atomicWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".corplink-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}

func writeJSON(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, append(b, '\n'))
}

func (m *manager) lock() (*os.File, error) {
	if err := os.MkdirAll(m.runDir, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(m.runDir, "control.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("另一个操作正在执行，请稍后重试")
	}
	return f, nil
}

func (m *manager) running() bool { return m.service("status") == nil }
func (m *manager) loggedIn(c object) bool {
	f, err := os.Stat(m.cookiePath())
	return text(c["state"]) == "Login" && err == nil && f.Size() > 0
}

var editable = []string{"company_name", "username", "server", "platform", "device_id", "device_name", "vpn_server_name", "vpn_select_strategy", "port"}
var deviceID = regexp.MustCompile(`^(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$`)
var alias = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func publicConfig(c object) object {
	r := object{}
	for _, k := range editable {
		if k != "port" {
			r[k] = text(c[k])
		}
	}
	if c["vpn_select_strategy"] == nil {
		r["vpn_select_strategy"] = "default"
	}
	_, p, _ := net.SplitHostPort(text(c["socks5_listen"]))
	r["port"], _ = strconv.Atoi(p)
	if r["port"] == 0 {
		r["port"] = 1188
	}
	return r
}

func validate(c object) error {
	if !alias.MatchString(text(c["company_name"])) {
		return errors.New("请填写有效的企业标识")
	}
	if !alias.MatchString(text(c["platform"])) {
		return errors.New("请填写有效的登录平台标识")
	}
	if !deviceID.MatchString(text(c["device_id"])) {
		return errors.New("设备 ID 必须是官方已注册设备的完整十六进制 ID（32、40 或 64 位）")
	}
	if s := text(c["device_name"]); s == "" || len(s) > 256 || strings.ContainsAny(s, "\r\n\x00") {
		return errors.New("请填写官方设备名称")
	}
	if s := text(c["server"]); s != "" {
		u, err := url.Parse(s)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return errors.New("服务地址必须是 HTTPS 根地址，也可以留空自动发现")
		}
	}
	host, p, err := net.SplitHostPort(text(c["socks5_listen"]))
	port, _ := strconv.Atoi(p)
	if err != nil || host != "127.0.0.1" || port < 1024 || port > 65535 {
		return errors.New("代理端口必须在 1024–65535 之间，并仅监听本机")
	}
	if c["auto_setup_routes"] != false || c["use_vpn_dns"] != false {
		return errors.New("此插件使用纯代理模式，请关闭系统路由和 DNS 接管")
	}
	if text(c["interface_name"]) != "corplink-n5100" {
		return errors.New("配置中的 interface_name 需要为 corplink-n5100")
	}
	if s := c["vpn_select_strategy"]; s != nil && text(s) != "default" && text(s) != "latency" {
		return errors.New("节点选择方式无效")
	}
	return nil
}

func (m *manager) backup() error {
	dir := filepath.Join(m.configDir, "backups", time.Now().UTC().Format("20060102T150405.000000000"))
	for _, p := range []string{m.configPath(), m.cookiePath()} {
		b, err := os.ReadFile(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if err = atomicWrite(filepath.Join(dir, filepath.Base(p)), b); err != nil {
			return err
		}
	}
	entries, _ := os.ReadDir(filepath.Dir(dir))
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for len(entries) > 5 {
		os.RemoveAll(filepath.Join(filepath.Dir(dir), entries[0].Name()))
		entries = entries[1:]
	}
	return nil
}

func (m *manager) save(input object) (object, error) {
	if m.running() {
		return nil, errors.New("请先停止服务，再修改配置")
	}
	if m.authState().Active() {
		return nil, errors.New("请先完成或取消正在进行的登录")
	}
	c, err := m.config()
	if err != nil {
		return nil, err
	}
	identityChanged := false
	identity := map[string]bool{"company_name": true, "username": true, "server": true, "platform": true, "device_id": true, "device_name": true}
	for k, v := range input {
		allowed := false
		for _, name := range editable {
			allowed = allowed || name == k
		}
		if !allowed {
			return nil, errors.New("配置包含不支持的字段")
		}
		if k == "port" {
			n, ok := v.(float64)
			if !ok || n != float64(int(n)) || n < 1024 || n > 65535 {
				return nil, errors.New("代理端口必须是 1024–65535 的整数")
			}
			c["socks5_listen"] = "127.0.0.1:" + strconv.Itoa(int(n))
			continue
		}
		s, ok := v.(string)
		if !ok || len(s) > 512 || strings.ContainsAny(s, "\r\n\x00") {
			return nil, errors.New("配置字段格式无效")
		}
		s = strings.TrimSpace(s)
		if identity[k] && text(c[k]) != s {
			identityChanged = true
		}
		if (k == "server" || k == "vpn_server_name") && s == "" {
			c[k] = nil
		} else {
			c[k] = s
		}
	}
	c["auto_setup_routes"], c["use_vpn_dns"], c["debug_wg"], c["login_flow"] = false, false, false, "device"
	if err = validate(c); err != nil {
		return nil, err
	}
	if identityChanged {
		c["state"], c["code"] = "Init", nil
	}
	if err = m.backup(); err != nil {
		return nil, errors.New("无法备份配置，未保存修改")
	}
	if err = writeJSON(m.configPath(), c); err != nil {
		return nil, errors.New("保存配置失败")
	}
	if identityChanged {
		os.Remove(m.cookiePath())
	}
	return object{"ok": true, "login_required": !m.loggedIn(c)}, nil
}

func (m *manager) call(method string, args object) (object, error) {
	switch method {
	case "get_config":
		c, err := m.config()
		if err != nil {
			return nil, err
		}
		return object{"ok": true, "config": publicConfig(c)}, nil
	case "status":
		c, err := m.config()
		if err != nil {
			return nil, err
		}
		return object{"ok": true, "running": m.running(), "enabled": m.service("enabled") == nil, "logged_in": m.loggedIn(c), "listen": text(c["socks5_listen"]), "server": text(c["vpn_server_name"]), "login_active": m.authState().Active(), "configured": validate(c) == nil}, nil
	case "logs":
		return object{"ok": true, "lines": m.logs()}, nil
	case "login_status":
		return object{"ok": true, "login": m.authState()}, nil
	case "login_submit", "login_cancel":
		return m.authRequest(method, args)
	case "save_config", "control", "login_begin":
		lock, err := m.lock()
		if err != nil {
			return nil, err
		}
		defer lock.Close()
		if method == "save_config" {
			c, ok := args["config"].(map[string]any)
			if !ok {
				return nil, errors.New("缺少配置")
			}
			return m.save(c)
		}
		if method == "login_begin" {
			return m.begin()
		}
		action := text(args["action"])
		switch action {
		case "start", "stop", "restart", "enable", "disable":
		default:
			return nil, errors.New("不支持的服务操作")
		}
		if action == "start" || action == "restart" {
			if m.authState().Active() {
				return nil, errors.New("请先完成登录")
			}
			c, err := m.config()
			if err != nil {
				return nil, err
			}
			if err = validate(c); err != nil {
				return nil, err
			}
			if !m.loggedIn(c) {
				return nil, errors.New("请先完成网页登录")
			}
		}
		if err := m.service(action); err != nil {
			return nil, errors.New("服务操作失败，请查看运行日志")
		}
		return object{"ok": true}, nil
	default:
		return nil, errors.New("未知操作")
	}
}

var secretLine = regexp.MustCompile(`(?i)cookie|token|secret|password|private.?key|public.?key|authorization|otp|config\s*[:=]|回调|验证码`)
var longToken = regexp.MustCompile(`[A-Za-z0-9_+/=-]{32,}`)
var queryString = regexp.MustCompile(`(https?://[^\s?]+)\?[^\s]+`)
var email = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+`)

func sanitizeLog(raw string) []string {
	lines := []string{}
	for _, line := range strings.Split(raw, "\n") {
		if !strings.Contains(line, "corplink_rs") || strings.Contains(line, "] skip ") || strings.Contains(line, "2fa code generated") || secretLine.MatchString(line) {
			continue
		}
		if len(line) > 1024 {
			continue
		}
		line = queryString.ReplaceAllString(line, "$1?<hidden>")
		line = longToken.ReplaceAllString(line, "<hidden>")
		line = email.ReplaceAllString(line, "<hidden>")
		lines = append(lines, line)
	}
	if len(lines) > 60 {
		lines = lines[len(lines)-60:]
	}
	return lines
}

func (m *manager) logs() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	b, _ := exec.CommandContext(ctx, "/sbin/logread").Output()
	return sanitizeLog(string(b))
}

func randomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func fingerprint(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "missing"
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (m *manager) begin() (object, error) {
	if m.running() {
		return nil, errors.New("请先停止服务，再重新登录")
	}
	if m.authState().Active() {
		return nil, errors.New("已有登录正在进行")
	}
	c, err := m.config()
	if err != nil {
		return nil, err
	}
	if err = validate(c); err != nil {
		return nil, err
	}
	if _, err = os.Stat(m.core); err != nil {
		return nil, errors.New("未安装 Corplink 核心")
	}
	id := randomID()
	dir := filepath.Join(m.runDir, "auth-"+id)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, errors.New("无法创建登录目录")
	}
	c["state"], c["code"], c["login_flow"] = "Init", nil, "device"
	if err = writeJSON(filepath.Join(dir, "config.json"), c); err != nil {
		os.RemoveAll(dir)
		return nil, errors.New("无法准备登录配置")
	}
	if err = atomicWrite(filepath.Join(dir, "baseline"), []byte(fingerprint(m.configPath()))); err != nil {
		os.RemoveAll(dir)
		return nil, errors.New("无法准备登录配置")
	}
	s := authState{ID: id, Stage: "starting", Expires: time.Now().Add(10 * time.Minute).Unix()}
	if err = writeJSON(m.statePath(), s); err != nil {
		os.RemoveAll(dir)
		return nil, errors.New("无法准备登录状态")
	}
	cmd := exec.Command(m.self, "login-worker", id)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err = cmd.Start(); err != nil {
		os.RemoveAll(dir)
		os.Remove(m.statePath())
		return nil, errors.New("无法启动登录进程")
	}
	cmd.Process.Release()
	return object{"ok": true, "login": s}, nil
}

func (m *manager) authRequest(method string, args object) (object, error) {
	s := m.authState()
	if !s.Active() || text(args["id"]) != s.ID {
		return nil, errors.New("登录已结束或页面已过期，请重新登录")
	}
	value := text(args["value"])
	if method == "login_submit" && (value == "" || len(value) > 8192 || strings.ContainsAny(value, "\r\n\x00")) {
		return nil, errors.New("请输入完整的单行授权结果")
	}
	c, err := net.DialTimeout("unix", m.socketPath(), time.Second)
	if err != nil {
		return nil, errors.New("登录进程正在准备或已退出，请刷新状态")
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	args["method"] = method
	if err = json.NewEncoder(c).Encode(args); err != nil {
		return nil, errors.New("提交失败，请刷新登录状态")
	}
	var reply object
	if err = json.NewDecoder(c).Decode(&reply); err != nil {
		return nil, errors.New("无法确认提交结果，请刷新状态，不要重复提交")
	}
	return reply, nil
}

func safeURL(s string) bool {
	u, e := url.Parse(s)
	return e == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil
}
func errorText(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprint(err)
}
