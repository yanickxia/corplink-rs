#!/usr/bin/env python3
"""Exercise the actual core's JSON login CLI against a local fake gateway.

No corporate endpoint or real credential is used. --ssh supports the native
router executable via a temporary loopback-only SSH reverse forward.
"""
import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import queue
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit, parse_qs

parser = argparse.ArgumentParser()
parser.add_argument('--binary', required=True)
parser.add_argument('--ssh')
parser.add_argument('--remote-port', type=int, default=18766)
args = parser.parse_args()
requests = []
failures = []
challenge = ''

class Gateway(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def handle_request(self):
        global challenge
        u = urlsplit(self.path)
        requests.append(u.path)
        body = json.loads(self.rfile.read(int(self.headers.get('content-length', 0))) or '{}')
        cookies = []
        try:
            if u.path == '/api/login/setting':
                data = {'login_enable': True, 'login_enable_ldap': False, 'login_orders': ['bytedance_sso']}
            elif u.path == '/api/tpslogin/link':
                challenge = parse_qs(u.query)['code_challenge'][0]
                data = [{'alias': 'bytedance_sso', 'alias_key': 'bytedance_sso', 'login_url': 'https://sso.example/authorize?state=this-attempt'}]
            elif u.path == '/api/tpslogin/device/callback':
                assert body['code'] == 'fresh-code'
                assert base64.urlsafe_b64encode(hashlib.sha256(body['code_verifier'].encode()).digest()).decode().rstrip('=') == challenge
                data = {'result': 'success', 'next': {'action': '2FA', 'auth_list': ['email']}}
                cookies = ['session=partial; Path=/; Max-Age=3600', 'csrf-token=partial; Path=/; Max-Age=3600']
            elif u.path == '/api/v1/login/mfa/send':
                assert body['mfa_type'] == 'email'
                data = {}
            elif u.path == '/api/v1/login/mfa/verify':
                assert body['code'] == '123456'
                data = {'result': 'success', 'next': {'action': 'GoToLink'}}
                cookies = ['session=fresh; Path=/; Max-Age=3600', 'csrf-token=fresh; Path=/; Max-Age=3600']
            elif u.path == '/api/v2/p/otp':
                data = {'url': 'otpauth://totp/mock?secret=JBSWY3DPEHPK3PXP', 'code': ''}
            else:
                raise AssertionError('unexpected request: ' + u.path)
            response = {'code': 0, 'data': data}
        except Exception as e:
            failures.append(str(e))
            response = {'code': 500, 'message': 'mock assertion failed'}
        raw = json.dumps(response).encode()
        self.send_response(200)
        for value in cookies:
            self.send_header('Set-Cookie', value)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

server = ThreadingHTTPServer(('127.0.0.1', 0), Gateway)
threading.Thread(target=server.serve_forever, daemon=True).start()
local = Path(tempfile.mkdtemp(prefix='corplink-login-test-'))
remote = None
process = None
try:
    if args.ssh:
        remote = subprocess.check_output(['ssh', args.ssh, 'umask 077; mktemp -d /tmp/corplink-login-test-XXXXXX'], text=True).strip()
    port = args.remote_port if args.ssh else server.server_port
    config = {'company_name': 'example', 'username': '', 'server': 'http://127.0.0.1:' + str(port),
              'login_flow': 'device', 'platform': 'bytedance_sso', 'device_id': 'A' * 40,
              'device_name': 'Mock+device', 'state': 'Init', 'interface_name': 'mock-login',
              'auto_setup_routes': False, 'use_vpn_dns': False, 'socks5_listen': '127.0.0.1:21888'}
    (local / 'config.json').write_text(json.dumps(config))
    (local / 'config.json').chmod(0o600)
    if args.ssh:
        subprocess.run(['scp', '-O', '-q', str(local / 'config.json'), args.ssh + ':' + remote + '/config.json'], check=True)
        command = ['ssh', '-o', 'ExitOnForwardFailure=yes', '-R', f'127.0.0.1:{args.remote_port}:127.0.0.1:{server.server_port}', args.ssh,
                   'umask 077; exec ' + shlex.quote(args.binary) + ' --login-json ' + shlex.quote(remote + '/config.json')]
    else:
        command = [args.binary, '--login-json', str(local / 'config.json')]
    with (local / 'stderr.log').open('w') as stderr:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, text=True, bufsize=1)
        events = []
        bad_callback_tested = False
        deadline = time.monotonic() + 30
        lines = queue.Queue()
        def read_lines():
            for line in process.stdout: lines.put(line)
            lines.put(None)
        threading.Thread(target=read_lines, daemon=True).start()
        while time.monotonic() < deadline:
            try: line = lines.get(timeout=1)
            except queue.Empty: continue
            if not line: break
            event = json.loads(line)
            events.append(event)
            if event['event'] == 'prompt':
                if event['kind'] == 'callback' and not bad_callback_tested:
                    value = 'https://wrong.example/?code=DO_NOT_ECHO'
                    bad_callback_tested = True
                elif event['kind'] == 'callback':
                    value = 'corplink://login/callback?alias_key=bytedance_sso&code=fresh-code&state=this-attempt'
                else:
                    value = '123456'
                process.stdin.write(value + '\n')
                process.stdin.flush()
        rc = process.wait(timeout=5)
    assert rc == 0, f'login CLI exit={rc}; events={[e["event"] for e in events]}'
    assert events[-1]['event'] == 'done', events
    assert any(e['event'] == 'error' for e in events), 'invalid callback did not yield a recoverable event'
    output = json.dumps(events)
    for value in ['DO_NOT_ECHO', 'fresh-code', '123456', 'JBSWY3DPEHPK3PXP']:
        assert value not in output, 'credential echoed in event output'
    assert not failures, failures
    assert not any(p.startswith('/vpn/') or p == '/api/vpn/list' for p in requests), 'login-only touched VPN APIs'
    if args.ssh:
        saved = json.loads(subprocess.check_output(['ssh', args.ssh, 'cat ' + shlex.quote(remote + '/config.json')], text=True))
    else:
        saved = json.loads((local / 'config.json').read_text())
    assert saved['state'] == 'Login'
    print(json.dumps({'ok': True, 'events': [e['event'] for e in events], 'auth_requests': requests, 'vpn_requests': 0, 'credentials_not_echoed': True}))
finally:
    if process and process.poll() is None:
        process.kill()
        process.wait()
    server.shutdown()
    if remote:
        subprocess.run(['ssh', args.ssh, 'rm -rf ' + shlex.quote(remote)], check=True)
    shutil.rmtree(local)
