// Read-only integration test against the router's actual LuCI/rpcd stack.
// Creates and destroys dedicated short-lived sessions; never reads user sessions.
const assert = require('node:assert/strict');
const { execFileSync, spawn } = require('node:child_process');
const net = require('node:net');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const crypto = require('node:crypto');

const host = process.env.CORPLINK_SSH || 'n5100';
const port = Number(process.env.LUCI_TEST_PORT || 18767);
function session(method, value) {
  const output = execFileSync('ssh', [host, 'ubus call session ' + method + ' "$(cat)"'], {
    input: JSON.stringify(value), encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe']
  });
  return JSON.parse(output || '{}');
}
async function ready() {
  for (let i = 0; i < 100; i++) {
    if (await new Promise(resolve => {
      const s = net.connect(port, '127.0.0.1');
      s.once('connect', () => { s.destroy(); resolve(true); });
      s.once('error', () => resolve(false));
    })) return;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error('SSH HTTP forward did not start');
}

(async () => {
  process.umask(0o077);
  const sessions = [];
  let browser;
  const tunnel = spawn('ssh', ['-N', '-o', 'ExitOnForwardFailure=yes', '-L', `127.0.0.1:${port}:127.0.0.1:80`, host], { stdio: 'ignore' });
  try {
    await ready();
    const sid = session('create', { timeout: 300 }).ubus_rpc_session;
    sessions.push(sid);
    session('set', { ubus_rpc_session: sid, values: { username: 'root', token: crypto.randomBytes(16).toString('hex') } });
    session('grant', { ubus_rpc_session: sid, scope: 'ubus', objects: [['*', '*']] });
    session('grant', { ubus_rpc_session: sid, scope: 'uci', objects: [['*', 'read']] });
    // LuCI checks exact group names in session.access's returned map; a literal
    // wildcard grant is sufficient for ubus, but not for menu dependency checks.
    session('grant', { ubus_rpc_session: sid, scope: 'access-group', objects: [
      ['luci-app-corplink-rs', 'read'], ['luci-app-corplink-rs', 'write'], ['luci-base', 'read']
    ] });
    browser = await chromium.launch({ headless: true, executablePath: process.env.CHROME_BIN });
    const context = await browser.newContext({ viewport: { width: 1440, height: 1050 } });
    await context.addCookies([{ name: 'sysauth_http', value: sid, domain: '127.0.0.1', path: '/cgi-bin/luci/', httpOnly: true }]);
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.goto(`http://127.0.0.1:${port}/cgi-bin/luci/admin/services/corplink`, { waitUntil: 'networkidle' });
    await page.locator('.corplink').waitFor();
    await page.getByText('正在运行', { exact: true }).waitFor();
    assert.equal(await page.locator('#cp-port').inputValue(), '1188');
    assert(await page.getByRole('button', { name: '启动', exact: true }).isDisabled());
    assert(await page.getByRole('button', { name: '重新登录', exact: true }).isDisabled());
    assert(await page.getByRole('button', { name: '保存配置', exact: true }).isDisabled());
    await page.getByRole('button', { name: '刷新日志', exact: true }).click();
    await page.waitForTimeout(3500);
    assert.equal(await page.locator('.corplink [role=status]').textContent(), '');
    assert.deepEqual(errors, []);
    if (process.env.UI_SCREENSHOT) await page.screenshot({ path: process.env.UI_SCREENSHOT, fullPage: true });

    const readonly = session('create', { timeout: 60 }).ubus_rpc_session;
    sessions.push(readonly);
    session('grant', { ubus_rpc_session: readonly, scope: 'ubus', objects: [['luci.corplink', 'status']] });
    async function rpc(id, method, args) {
      const r = await fetch(`http://127.0.0.1:${port}/ubus/`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'call', params: [id, 'luci.corplink', method, args] }) });
      return r.json();
    }
    const read = await rpc(readonly, 'status', {});
    assert.equal(read.result?.[0], 0);
    assert.equal(read.result?.[1]?.running, true);
    // Invalid action is harmless even if the ACL assertion fails.
    const denied = await rpc(readonly, 'control', { action: 'test-invalid-action' });
    function assertDenied(reply, message) {
      // uhttpd rejects the request before dispatch as JSON-RPC -32002;
      // other transports return ubus's permission-denied status (6).
      assert(reply.result?.[0] === 6 || reply.error?.code === -32002,
        message + '; returned code=' + (reply.error?.code ?? reply.result?.[0]));
    }
    assertDenied(denied, 'read-only RPC session was allowed to call control');
    const anonymous = await rpc('0'.repeat(32), 'get_config', {});
    assertDenied(anonymous, 'anonymous session accessed configuration');
    console.log('PASS: actual LuCI page, config/status/log RPC, polling, running-service controls disabled, read-only and anonymous ACL enforcement; no service changes');
  } finally {
    try {
      if (browser) await browser.close();
      for (const id of sessions) {
        try { session('destroy', { ubus_rpc_session: id }); }
        catch { console.error('Failed to destroy a test session; it will expire within five minutes'); }
      }
    } finally { tunnel.kill(); }
  }
})().catch(e => { console.error(e.message); process.exit(1); });
