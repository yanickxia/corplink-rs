#!/usr/bin/env python3
"""Compare installation invariants without reading or printing credentials."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--ssh', default='n5100')
mode = parser.add_mutually_exclusive_group(required=True)
mode.add_argument('--save', type=Path)
mode.add_argument('--compare', type=Path)
args = parser.parse_args()
os.umask(0o077)

def ssh(command):
    return subprocess.check_output(['ssh', args.ssh, command], text=True).strip()

def digest(command):
    value = re.sub(r'expires \d+sec', 'expires <dynamic>', ssh(command))
    return hashlib.sha256('\n'.join(sorted(value.splitlines())).encode()).hexdigest()

service = json.loads(ssh('ubus call service list \'{"name":"corplink-rs-dev"}\''))
instances = service.get('corplink-rs-dev', {}).get('instances', {})
state = {
    'pids': sorted(v['pid'] for v in instances.values() if v.get('running')),
    'config_and_session': ssh('sha256sum /etc/corplink-rs-dev/config.json /etc/corplink-rs-dev/corplink-n5100_cookies.json'),
    'routes': digest('ip route show table all'),
    'ipv6_routes': digest('ip -6 route show table all'),
    'rules': digest('ip rule show'),
    'ipv6_rules': digest('ip -6 rule show'),
    'dns': ssh('sha256sum /etc/resolv.conf /tmp/resolv.conf.d/resolv.conf.auto'),
    'enabled': subprocess.run(['ssh', args.ssh, '/etc/init.d/corplink-rs-dev enabled'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0,
}
assert state['pids'], 'the existing VPN service is not running'
code = ssh('curl --max-time 20 --socks5-hostname 127.0.0.1:1188 -sS -o /dev/null -w "%{http_code}" https://code.byted.org/')
assert code == '302', 'proxy connectivity check returned HTTP ' + code
if args.save:
    args.save.write_text(json.dumps(state, indent=2) + '\n')
    print('Saved installation baseline; proxy returned HTTP 302')
else:
    before = json.loads(args.compare.read_text())
    checks = {key: state[key] == before[key] for key in state}
    print(json.dumps({'unchanged': checks, 'proxy_http': code}))
    assert all(checks.values()), 'installation invariant changed'
