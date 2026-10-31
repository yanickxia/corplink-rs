const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

(async () => {
  const browser = await chromium.launch({ headless: true, executablePath: process.env.CHROME_BIN });
  try {
    const page = await browser.newPage({ viewport: { width: 1280, height: 1000 } });
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.setContent('<html lang="zh-CN"><meta charset="utf-8"><style>body{font:14px system-ui;max-width:1080px;margin:24px auto;padding:0 16px}button,input,select,textarea{font:inherit;padding:8px;border:1px solid #ccd3db;border-radius:4px}button:disabled{opacity:.45}button,a{cursor:pointer}a{color:#1978aa}h2{font-size:26px}</style><main></main></html>');
    await page.evaluate(() => {
      window.E = function(tag, attrs, children) {
        const el = document.createElement(tag);
        for (const [key, value] of Object.entries(attrs || {})) {
          if (typeof value === 'function') el.addEventListener(key, value);
          else el.setAttribute(key, value);
        }
        for (const child of Array.isArray(children) ? children : children == null ? [] : [children]) el.append(child);
        return el;
      };
      window.calls = [];
      window.notifications = [];
      window.pollers = [];
      window.mock = {
        state: { ok: true, running: true, enabled: false, logged_in: true, listen: '127.0.0.1:1188', server: 'CN-IT-SH', configured: true, login_active: false },
        config: { company_name: 'example', server: 'https://vpn.example', platform: 'bytedance_sso', username: '', device_id: 'A'.repeat(40), device_name: 'Android+SDK+built+for+arm64', port: 1188, vpn_server_name: 'CN-IT-SH', vpn_select_strategy: 'default' },
        auth: { stage: 'idle' }
      };
      window.rpc = { declare: spec => async (...args) => {
        window.calls.push([spec.method, ...args]);
        const m = window.mock;
        switch (spec.method) {
          case 'status': return { ...m.state };
          case 'get_config': return { ok: true, config: { ...m.config } };
          case 'logs': return { ok: true, lines: ['corplink_rs start wg-corplink (netstack/socks5) on 127.0.0.1:1188'] };
          case 'control':
            if (args[0] === 'stop') m.state.running = false;
            if (args[0] === 'start' || args[0] === 'restart') m.state.running = true;
            if (args[0] === 'enable' || args[0] === 'disable') m.state.enabled = args[0] === 'enable';
            return { ok: true };
          case 'save_config': m.config = args[0]; return { ok: true, login_required: false };
          case 'login_status': return { ok: true, login: { ...m.auth } };
          case 'login_begin':
            m.state.login_active = true;
            m.auth = { id: 'attempt', stage: 'waiting', kind: 'callback', prompt_id: 1, prompt: '请粘贴授权完成后的完整回调地址，然后按回车：', url: 'https://sso.example/authorize?state=mock' };
            return { ok: true, login: { ...m.auth } };
          case 'login_submit':
            if (args[1] !== m.auth.prompt_id) return { ok: false, error: '过期步骤' };
            if (m.auth.kind === 'callback') m.auth = { ...m.auth, kind: 'code', prompt_id: 2, prompt: '邮箱验证码已发送，请输入验证码后按回车：' };
            else { m.auth = { stage: 'done' }; m.state.login_active = false; m.state.logged_in = true; }
            return { ok: true };
          case 'login_cancel': m.auth = { stage: 'cancelled', message: '登录已取消，原有会话已保留' }; m.state.login_active = false; return { ok: true };
        }
        throw new Error('unexpected RPC ' + spec.method);
      } };
      window.view = { extend: x => x };
      window.ui = { addNotification: (_, node) => window.notifications.push(node.textContent) };
      window.poll = { add: fn => window.pollers.push(fn) };
    });
    const code = fs.readFileSync(path.join(__dirname, '../luci-app-corplink-rs/htdocs/luci-static/resources/view/corplink/overview.js'), 'utf8');
    await page.evaluate(async source => {
      window.screenView = new Function('view', 'rpc', 'ui', 'poll', 'E', source)(view, rpc, ui, poll, E);
      document.querySelector('main').append(screenView.render(await screenView.load()));
    }, code);
    await page.getByText('正在运行', { exact: true }).waitFor();
    assert(await page.getByRole('button', { name: '启动', exact: true }).isDisabled());
    assert(await page.getByRole('button', { name: '重新登录', exact: true }).isDisabled());
    await page.getByRole('button', { name: '停止', exact: true }).click();
    await page.getByText('已停止', { exact: true }).waitFor();
    await page.locator('#cp-port').fill('1190');
    await page.getByRole('button', { name: '保存配置', exact: true }).click();
    await page.waitForFunction(() => calls.some(c => c[0] === 'save_config'));
    const save = await page.evaluate(() => calls.find(c => c[0] === 'save_config')[1]);
    assert.equal(save.port, 1190);
    assert(!('private_key' in save));
    await page.getByRole('button', { name: '重新登录', exact: true }).click();
    const callback = page.getByRole('textbox', { name: '完整回调地址' });
    await callback.fill('https://vpn.example/multiple-pages/device-callback.html?code=example');
    await page.evaluate(() => pollers[0]());
    assert((await callback.inputValue()).includes('code=example'), 'polling erased a typed callback');
    await page.getByRole('button', { name: '提交授权结果', exact: true }).dblclick();
    await page.getByLabel('验证码', { exact: true }).fill('123456');
    await page.getByRole('button', { name: '提交验证码', exact: true }).click();
    await page.getByText('登录成功。会话已保存，点击「启动」即可连接。').waitFor();
    assert.equal(await page.evaluate(() => calls.filter(c => c[0] === 'login_submit').length), 2, 'duplicate submission');
    await page.getByRole('button', { name: '启用开机自启', exact: true }).click();
    await page.getByRole('button', { name: '关闭开机自启', exact: true }).waitFor();
    await page.getByRole('button', { name: '启动', exact: true }).click();
    await page.getByText('正在运行', { exact: true }).waitFor();
    if (process.env.UI_SCREENSHOT) await page.screenshot({ path: process.env.UI_SCREENSHOT, fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'mobile layout overflows');
    assert.deepEqual(errors, []);
    console.log('PASS: service controls, config save, callback/MFA flow, duplicate-submit guard, poll input preservation, boot toggle, responsive layout');
  } finally { await browser.close(); }
})().catch(e => { console.error(e); process.exit(1); });
