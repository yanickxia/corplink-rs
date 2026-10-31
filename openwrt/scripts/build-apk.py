#!/usr/bin/env python3
"""Package prebuilt static executables using apk-tools 3, without an SDK.

The standard OpenWrt Makefiles are also provided for SDK/feed integration.
No user configuration is copied into either package.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--binaries', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--arch', default='x86_64')
parser.add_argument('--image', default='alpine:3.23.3')
args = parser.parse_args()
base = Path(__file__).resolve().parents[1]
out = args.output.resolve()
out.mkdir(parents=True, exist_ok=True)
stage = out / 'package-root'
if stage.exists():
    shutil.rmtree(stage)
core = stage / 'core'
gui = stage / 'gui'

def install(source, target, mode=0o644):
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    target.chmod(mode)

install(args.binaries / 'corplink-rs-dev', core / 'usr/bin/corplink-rs-dev', 0o755)
install(args.binaries / 'luci.corplink', core / 'usr/libexec/rpcd/luci.corplink', 0o755)
install(args.binaries / 'BUILD-INFO.json', core / 'usr/share/corplink-rs-dev/BUILD-INFO.json')
install(base / 'corplink-rs-dev/files/corplink-rs-dev.init', core / 'etc/init.d/corplink-rs-dev', 0o755)
conffiles = core / 'lib/apk/packages/corplink-rs-dev.conffiles'
conffiles.parent.mkdir(parents=True, exist_ok=True)
conffiles.write_text('/etc/corplink-rs-dev/\n')
keep = core / 'lib/upgrade/keep.d/corplink-rs-dev'
keep.parent.mkdir(parents=True, exist_ok=True)
keep.write_text('/etc/corplink-rs-dev/\n')
for source, destination in [(base / 'luci-app-corplink-rs/root', gui), (base / 'luci-app-corplink-rs/htdocs', gui / 'www')]:
    shutil.copytree(source, destination, dirs_exist_ok=True)
scripts = stage / 'scripts'
shutil.copytree(base / 'scripts', scripts, ignore=shutil.ignore_patterns('*.py'), dirs_exist_ok=True)
# Normalize ownership inside the container, without chowning the developer's
# bind-mounted files (which would make the next local rebuild unwritable).
mount = ['docker', 'run', '--rm', '-v', str(out) + ':/out', args.image]

def package(name, version, arch, root, dependencies, hooks):
    command = mount + ['sh', '-ec',
        'cp -a /out/package-root /tmp/package-root; chown -R 0:0 /tmp/package-root; exec "$@"',
        'package', 'apk', 'mkpkg', '--info', 'name:' + name,
        '--info', 'version:' + version, '--info', 'arch:' + arch,
        '--info', 'license:GPL-2.0-or-later', '--info', 'origin:corplink-rs',
        '--info', 'description:Corplink local SOCKS5 proxy with LuCI device login',
        '--info', 'depends:' + dependencies,
        '--files', '/tmp/package-root/' + root,
        '--output', '/out/' + name + '-' + version + '.apk']
    for kind, file in hooks.items():
        command += ['--script', kind + ':/out/package-root/scripts/' + file]
    subprocess.run(command, check=True)

package('corplink-rs-dev', '6.6.0-r2', args.arch, 'core', 'ca-bundle jsonfilter rpcd', {
    'pre-install': 'core-pre-install.sh', 'pre-upgrade': 'core-pre-install.sh',
    'post-install': 'core-post-install.sh', 'post-upgrade': 'core-post-install.sh',
    'pre-deinstall': 'core-pre-remove.sh'})
package('luci-app-corplink-rs', '1.0.0-r2', 'noarch', 'gui', 'luci-base corplink-rs-dev>=6.6.0-r2', {
    'post-install': 'gui-post-install.sh', 'post-upgrade': 'gui-post-install.sh',
    'post-deinstall': 'gui-post-install.sh'})
manifest = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.glob('*.apk'))}
(out / 'SHA256SUMS').write_text(''.join(v + '  ' + k + '\n' for k, v in manifest.items()))
print(json.dumps({'packages': manifest}, indent=2))
