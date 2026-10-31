#!/usr/bin/env python3
"""Build the Linux/amd64 musl core and RPC helper in a separate output directory.

Docker honors DOCKER_HOST (including ssh://n5100). The source tree and existing
installed binaries are never modified. Rust dependencies and libwg are locked.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('--work-dir', type=Path, required=True)
parser.add_argument('--wireguard-source', type=Path)
parser.add_argument('--offline', action='store_true', help='Use the local Cargo cache only')
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
work = args.work_dir.resolve()
work.mkdir(parents=True, exist_ok=True)
source = work / 'source'
source.mkdir(exist_ok=True)
out = work / 'out'
out.mkdir(exist_ok=True)

def run(command, **kwargs):
    return subprocess.run(command, check=True, **kwargs)

wg_revision = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD:libwg/wireguard-go'], text=True).strip()
# The static constructor adapter is deliberately tied to this validated pair.
if wg_revision != 'a73b9f07989a647ad7f4d84184efb3b1b8ea77a4':
    raise SystemExit('WireGuard revision changed; review the pinned musl adapter before building')
wg = (args.wireguard_source or root / 'libwg/wireguard-go').resolve()
run(['git', '-C', str(wg), 'cat-file', '-e', wg_revision + '^{commit}'])
for path in (root / 'openwrt/build').iterdir():
    shutil.copy2(path, work / path.name)
for name in ['Cargo.toml', 'Cargo.lock', 'build.rs']:
    shutil.copy2(root / name, source / name)
for name in ['src', 'libwg']:
    target = source / name
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(root / name, target, ignore=shutil.ignore_patterns('wireguard-go', '*.a'))
wg_target = source / 'libwg/wireguard-go'
wg_target.mkdir()
with tempfile.TemporaryFile() as archive:
    run(['git', '-C', str(wg), 'archive', wg_revision], stdout=archive)
    archive.seek(0)
    with tarfile.open(fileobj=archive) as tar:
        tar.extractall(wg_target, filter='data')
vendor_command = ['cargo', 'vendor', '--respect-source-config', '--locked']
if args.offline:
    vendor_command.append('--offline')
vendor_command.append(str(source / 'vendor'))
config = subprocess.check_output(vendor_command, cwd=root, text=True)
config = config.replace(str(source / 'vendor'), 'vendor')
(source / '.cargo').mkdir(exist_ok=True)
(source / '.cargo/config.toml').write_text(config)

image = 'corplink-luci-builder:local'
run(['docker', 'build', '--platform', 'linux/amd64', '--target', 'build', '-t', image, str(work)])
container = subprocess.check_output(['docker', 'create', image], text=True).strip()
try:
    for name in ['corplink-rs-dev', 'luci.corplink']:
        if (out / name).exists():
            backup = out / (name + '.bak-' + hashlib.sha256((out / name).read_bytes()).hexdigest()[:12])
            shutil.copy2(out / name, backup)
    run(['docker', 'cp', container + ':/out/corplink-rs-dev', str(out / 'corplink-rs-dev')])
finally:
    run(['docker', 'rm', container], stdout=subprocess.DEVNULL)

manager = root / 'openwrt/manager'
run(['go', 'test', '-race', './...'], cwd=manager)
env = dict(os.environ, GOOS='linux', GOARCH='amd64', CGO_ENABLED='0')
run(['go', 'build', '-trimpath', '-ldflags=-s -w', '-o', str(out / 'luci.corplink'), '.'], cwd=manager, env=env)
hashes = {name: hashlib.sha256((out / name).read_bytes()).hexdigest() for name in ['corplink-rs-dev', 'luci.corplink']}
source_files = sorted((source / 'src').rglob('*.rs')) + [source / x for x in ['Cargo.toml', 'Cargo.lock', 'build.rs']]
source_hash = hashlib.sha256()
for path in sorted(source_files):
    source_hash.update(str(path.relative_to(source)).encode() + b'\0' + path.read_bytes())
info = {
    'base_commit': subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip(),
    'variant': 'dev + LuCI login-only JSON interface (working tree source)',
    'wireguard_commit': wg_revision,
    'core_source_sha256': source_hash.hexdigest(),
    'target': 'x86_64-linux-musl', 'sha256': hashes,
    'rust': '1.96.0', 'libwg_go': '1.25.5',
    'manager_go': subprocess.check_output(['go', 'version'], text=True).strip(),
    'checks': ['cargo build --release --locked', 'cargo test --release --locked', 'go test ./libwg ./conn', 'go test -race ./...'],
}
(out / 'BUILD-INFO.json').write_text(json.dumps(info, indent=2) + '\n')
print('Build output: ' + str(out))
