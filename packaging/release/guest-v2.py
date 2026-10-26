#!/usr/bin/env python3
"""Mutable-system lifecycle qualification. Run only inside a disposable guest.

The host authenticates artifacts, performs installed-scope probes/protocol tests,
reboots, and assembles the matrix receipt. This reports only completed checks.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time


class GuestError(RuntimeError):
    pass


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def save(path, value):
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix='.guest-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w') as output:
            os.fchmod(output.fileno(), 0o600)
            json.dump(value, output, indent=2, sort_keys=True)
            output.write('\n')
            output.flush(); os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


class Controller:
    def __init__(self, spec, work):
        self.spec, self.work = spec, Path(work)
        self.row, self.manifest = spec['row'], spec['manifest']
        self.route, self.init = self.row['route'], self.row['init']
        if self.route not in ('portable', 'deb', 'rpm'):
            raise GuestError('this controller handles only mutable portable/DEB/RPM routes')
        self.release_id = self.manifest['release_id']
        if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+-[0-9]+', self.release_id):
            raise GuestError('invalid candidate release id')
        self.baseline = spec['baseline']
        if self.baseline['kind'] not in ('previous-stable', 'first-release-fixture'):
            raise GuestError('baseline identity is required')
        self.allowed = set(self.row['checks'])
        self.report = {'schema': 2, 'checks': {}, 'baseline_kind': self.baseline['kind']}
        self.state_file = self.work / 'guest-lifecycle-state.json'

    def relative(self, value):
        path = Path(value)
        if path.is_absolute() or '..' in path.parts:
            raise GuestError('fixture paths must stay beneath the qualification directory')
        result = self.work / path
        result.resolve().relative_to(self.work.resolve())
        return result

    def command(self, arguments, check=True, timeout=240, capture=False):
        environment = dict(os.environ, DEBIAN_FRONTEND='noninteractive', LC_ALL='C')
        result = subprocess.run([str(value) for value in arguments], check=False,
                                stdin=subprocess.DEVNULL, env=environment, timeout=timeout,
                                text=True, capture_output=capture)
        if check and result.returncode:
            raise GuestError('command failed: ' + str(arguments[0]) + ' (exit ' + str(result.returncode) + ')')
        return result

    def mark(self, name):
        if name in self.allowed:
            self.report['checks'][name] = 'passed'
            print('HTTPJET_GUEST_CHECK ' + name + ' passed', flush=True)

    def reset_budget(self):
        if self.init == 'systemd':
            # Multiple healthy lifecycle transitions intentionally happen within
            # one minute. Clear the test's previous start count before each;
            # an unexpected failed start still aborts, never gets retried here.
            self.command(['systemctl', 'reset-failed', 'httpjet.service'], check=False)

    def bootstrap(self, version=None, check=True, capture=False):
        arguments = ['/bin/sh', self.relative(self.spec.get('bootstrap', 'install.sh')),
                     '--method', 'binary' if self.route == 'portable' else 'package', '--init', self.init]
        if version: arguments += ['--version', version]
        return self.command(arguments, check=check, capture=capture, timeout=600)

    def service_action(self, action):
        if self.route == 'portable':
            self.command(['/usr/local/sbin/httpjetctl', action])
        elif self.init == 'systemd':
            self.command(['systemctl', action, 'httpjet.service'])
        else:
            raise GuestError('native packages require their systemd integration')

    def active(self):
        if self.init == 'systemd':
            return self.command(['systemctl', 'is-active', '--quiet', 'httpjet.service'], check=False, capture=True).returncode == 0
        if not Path('/usr/local/sbin/httpjetctl').exists(): return False
        return self.command(['/usr/local/sbin/httpjetctl', 'status'], check=False, capture=True).returncode == 0

    def enabled(self):
        if self.init == 'systemd':
            return self.command(['systemctl', 'is-enabled', '--quiet', 'httpjet.service'], check=False, capture=True).returncode == 0
        if self.init == 'openrc':
            result = self.command(['rc-update', 'show', 'default'], capture=True)
            return re.search(r'^\s*httpjet\s', result.stdout, re.M) is not None
        if self.init == 'runit':
            return not Path('/etc/sv/httpjet/down').exists() and any((Path(directory)/'httpjet').is_symlink() for directory in ('/var/service', '/service', '/run/runit/service'))
        if self.init == 'sysv':
            if Path('/etc/rc.d/rc.M').exists():
                path = Path('/etc/rc.d/rc.local')
                return os.access(path, os.X_OK) and '# BEGIN HTTPJET MANAGED START' in path.read_text()
            return any(Path('/etc').glob('rc[2345].d/S*httpjet'))
        raise GuestError('unknown service enablement adapter')

    def request(self, path):
        connection = http.client.HTTPConnection('127.0.0.1', 80, timeout=3)
        try:
            connection.request('GET', path, headers={'Connection':'close'})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def wait_http(self):
        expected = self.relative(self.spec['expected_welcome']).read_bytes()
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            try:
                if self.active() and self.request('/') == (200, expected): return
            except (OSError, GuestError):
                pass
            time.sleep(0.2)
        raise GuestError('installed service did not return the authenticated expected welcome')

    def inspect(self):
        if self.init == 'systemd':
            pid = int(self.command(['systemctl','show','--value','--property=MainPID','httpjet.service'],capture=True).stdout.strip())
        else:
            pid = int(Path('/run/httpjet/ready').read_text())
        if pid <= 0: raise GuestError('installed init service has no main PID')
        proc = Path('/proc') / str(pid)
        status = proc.joinpath('status').read_text().splitlines()
        uids = list(map(int,next(line for line in status if line.startswith('Uid:')).split()[1:]))
        gids = list(map(int,next(line for line in status if line.startswith('Gid:')).split()[1:]))
        if uids[0] <= 0 or len(set(uids)) != 1 or len(set(gids)) != 1:
            raise GuestError('service is privileged or has inconsistent identities')
        executable = proc.joinpath('exe').resolve(strict=True)
        arguments = proc.joinpath('cmdline').read_bytes().split(b'\0')
        actual_hash = sha(executable)
        expected = self.manifest['binaries'][self.row['architecture']]['binary_sha256']
        if actual_hash != expected: raise GuestError('running init service is not the authenticated ELF')
        no_multishot = b'--no-multishot-accept' in arguments
        if self.row.get('no_multishot_accept') and not no_multishot:
            raise GuestError('installed service omitted its qualified single-shot accept flag')
        if b'--no-php' not in arguments or any(value.startswith(b'--page-cache') for value in arguments):
            raise GuestError('fresh service unexpectedly enabled PHP or page cache')
        if self.route == 'portable':
            if int(Path('/run/httpjet/ready').read_text()) != pid: raise GuestError('readiness PID differs from init main PID')
        groups = list(map(int,next(line for line in status if line.startswith('Groups:')).split()[1:]))
        service = {'scope':'installed-init-service','uid':uids[0],'gid':gids[0],'groups':groups,'pid':pid,
                   'executable':str(executable),'binary_sha256':actual_hash,'init':self.init,
                   'no_multishot_accept':no_multishot,'arguments':[os.fsdecode(value) for value in arguments if value]}
        self.report['service'] = service
        self.mark('unprivileged')
        self.mark('no-php-no-cache')
        return service

    def installed_version(self):
        if self.route == 'portable':
            return json.loads(Path('/var/lib/httpjet-installer/state.json').read_text())['current']
        if self.route == 'deb':
            return self.command(['dpkg-query','-W','-f=${Version}','httpjet'],capture=True).stdout.strip()
        return self.command(['rpm','-q','--qf','%{VERSION}-%{RELEASE}','httpjet'],capture=True).stdout.strip()

    def setup_ca(self):
        certificate = self.relative(self.spec.get('certificate','test-ca.crt'))
        if not certificate.is_file(): raise GuestError('test repository CA is missing')
        # Store locations are distribution APIs, not interchangeable despite
        # the shared updater name (SUSE differs from Debian/Alpine).
        if Path('/etc/pki/trust').is_dir() or Path('/usr/share/pki/trust').is_dir():
            target, update = Path('/etc/pki/trust/anchors/httpjet-qualification.crt'), ['update-ca-certificates']
        elif Path('/etc/ca-certificates/trust-source').is_dir() or self.row['distro']=='arch':
            target, update = Path('/etc/ca-certificates/trust-source/anchors/httpjet-qualification.crt'), ['update-ca-trust']
        elif Path('/etc/pki/ca-trust/source').is_dir():
            target, update = Path('/etc/pki/ca-trust/source/anchors/httpjet-qualification.crt'), ['update-ca-trust','extract']
        elif shutil.which('update-ca-certificates'):
            target, update = Path('/usr/local/share/ca-certificates/httpjet-qualification.crt'), ['update-ca-certificates']
        else:
            raise GuestError('qualification image must provide its distribution CA update tool')
        if not shutil.which(update[0]): raise GuestError('qualification recipe is missing '+update[0])
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(certificate,target)
        self.command(update)

    def install(self):
        self.setup_ca()
        if self.route != 'portable':
            for tool in ('curl',):
                if not shutil.which(tool): raise GuestError('qualification recipe must install ' + tool)
        with socket.socket() as blocker:
            blocker.bind(('0.0.0.0',80));blocker.listen(4)
            attempt = self.bootstrap(self.release_id, check=False, capture=True)
            if attempt.returncode == 0 or 'port 80' not in (attempt.stdout + attempt.stderr):
                raise GuestError('bootstrap did not specifically refuse the occupied port')
        self.mark('occupied-port')
        self.bootstrap(self.release_id)
        if self.installed_version() != self.release_id: raise GuestError('wrong initial package version')
        self.wait_http(); self.inspect()
        if not self.enabled(): raise GuestError('fresh init integration is not enabled')
        self.mark('install');self.mark('http')
        self.bootstrap(self.release_id)
        self.wait_http();self.mark('rerun')
        marker = b'HTTPJET QUALIFICATION TEST SOURCE'
        for suffix in ('php','PHP','php8','phtml','phar','phps','php.gz.br'):
            name = '__httpjet_qualification.' + suffix
            Path('/var/www/httpjet',name).write_bytes(b'<?php '+marker+b' ?>')
            for tail in ('','/path-info'):
                code, body = self.request('/'+name+tail)
                if code != 403 or marker in body: raise GuestError('script source denial failed')
        self.mark('scripts-denied')
        content = os.urandom(1048576)
        Path('/var/www/httpjet/__httpjet_qualification.bin').write_bytes(content)
        if self.request('/__httpjet_qualification.bin') != (200,content): raise GuestError('large bridge transfer mismatch')
        self.mark('bridged-transfer')
        first = self.report['service']['pid']
        self.reset_budget();self.service_action('restart');self.wait_http()
        if self.inspect()['pid'] == first: raise GuestError('restart retained the old main PID')
        self.mark('restart')
        configuration = Path('/etc/httpjet/conf/vhosts/default.xml')
        configuration.write_text(configuration.read_text()+'\n<!-- operator qualification edit -->\n')
        operator = Path('/var/www/httpjet/operator-content.txt')
        operator.write_text('operator-owned\n')
        save(self.state_file, {'schema':2,'configuration_sha256':sha(configuration),'uid':self.report['service']['uid'],
                               'binary_sha256':self.report['service']['binary_sha256'],'content':'operator-owned\n'})

    def preserved(self, configuration=True):
        state = json.loads(self.state_file.read_text())
        if Path('/var/www/httpjet/operator-content.txt').read_text() != state['content']:
            raise GuestError('administrator content changed during lifecycle transaction')
        if configuration and sha('/etc/httpjet/conf/vhosts/default.xml') != state['configuration_sha256']:
            raise GuestError('administrator configuration changed during lifecycle transaction')

    def local_baseline(self):
        field = 'deb' if self.route == 'deb' else 'rpm'
        path = self.relative(self.baseline[field])
        if sha(path) != self.baseline[field+'_sha256']:
            raise GuestError('baseline package hash differs from its authenticated identity')
        if self.route == 'rpm':
            verifier = shutil.which('rpmkeys') or shutil.which('rpm')
            result = self.command([verifier,'--checksig','--verbose',path],capture=True)
            text = result.stdout + result.stderr
            if (re.search(r'\b(?:NOKEY|NOT\s+OK)\b', text, re.IGNORECASE)
                or not re.search(r'\bsignature[^\n]*:\s*OK\s*$', text, re.IGNORECASE | re.MULTILINE)):
                raise GuestError('local RPM baseline signature did not verify')
        return path

    def target(self, release_id, local=False):
        if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+-[0-9]+',release_id):
            raise GuestError('invalid lifecycle target release id')
        self.reset_budget()
        if self.route == 'portable':
            self.command(['/usr/local/sbin/httpjetctl','update','--version',release_id],timeout=600)
        elif self.route == 'deb':
            target = str(self.local_baseline()) if local else 'httpjet='+release_id
            self.command(['apt-get','install','-y','--allow-downgrades','-o','Dpkg::Options::=--force-confdef','-o','Dpkg::Options::=--force-confold',target],timeout=600)
        elif local:
            package = self.local_baseline()
            manager = next((tool for tool in ('dnf','yum','zypper') if shutil.which(tool)),None)
            if manager == 'zypper':
                self.command([manager,'--non-interactive','install','--oldpackage',package],timeout=600)
            elif manager:
                self.command([manager,'-y','--setopt=gpgcheck=1','--setopt=localpkg_gpgcheck=1','--setopt=httpjet.repo_gpgcheck=1',
                              'downgrade',package],timeout=600)
            else: raise GuestError('native RPM manager is missing')
        else:
            self.bootstrap(release_id)
        if self.installed_version() != release_id:
            raise GuestError('package manager did not perform the requested real version transition')

    def remove_native(self, purge=False):
        if self.route == 'deb':
            self.command(['apt-get','purge' if purge else 'remove','-y','httpjet'],timeout=600)
        else:
            manager = next((tool for tool in ('dnf','yum','zypper') if shutil.which(tool)),None)
            if manager == 'zypper': self.command([manager,'--non-interactive','remove','httpjet'],timeout=600)
            elif manager:self.command([manager,'-y','remove','httpjet'],timeout=600)
            else:raise GuestError('native RPM manager is missing')

    def install_native_current(self):
        if self.route == 'deb':
            self.command(['apt-get','install','-y','-o','Dpkg::Options::=--force-confdef','-o','Dpkg::Options::=--force-confold',
                          'httpjet='+self.release_id,'httpjet-archive-keyring'],timeout=600)
        else:
            manager = next((tool for tool in ('dnf','yum','zypper') if shutil.which(tool)),None)
            if manager == 'zypper':self.command([manager,'--non-interactive','install','httpjet='+self.release_id,'httpjet-archive-keyring'],timeout=600)
            elif manager:self.command([manager,'-y','--setopt=httpjet.gpgcheck=1','--setopt=httpjet.repo_gpgcheck=1','install','httpjet-'+self.release_id,'httpjet-archive-keyring'],timeout=600)
            else:raise GuestError('native RPM manager is missing')

    def denial(self):
        if 'io-uring-denied' not in self.allowed:return
        if self.init != 'systemd':raise GuestError('installed service denial fixture is not implemented for this init')
        self.service_action('stop')
        path = Path('/run/systemd/system/httpjet.service.d/httpjet-qualification-deny.conf')
        if path.exists():raise GuestError('qualification denial drop-in already exists')
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text('[Service]\nRestart=no\nSystemCallFilter=~io_uring_setup io_uring_enter io_uring_register\nSystemCallErrorNumber=EPERM\n')
        try:
            self.command(['systemctl','daemon-reload']);self.reset_budget()
            since=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f UTC')
            denied = self.command(['systemctl','start','httpjet.service'],check=False,capture=True)
            log = self.command(['journalctl','-u','httpjet.service','--since',since,'--no-pager'],capture=True).stdout
            if denied.returncode == 0 or self.active() or not ('io_uring_setup' in log or 'build monoio runtime' in log) or not ('Operation not permitted' in log or 'os error 1' in log):
                raise GuestError('installed service did not fail specifically on denied io_uring')
            (self.work/'installed-io-uring-denial.log').write_text(log)
            self.mark('io-uring-denied')
        finally:
            path.unlink(missing_ok=True)
            self.command(['systemctl','daemon-reload']);self.reset_budget()
            self.service_action('start');self.wait_http()

    def exercise(self):
        if not self.state_file.is_file():raise GuestError('install mode must complete before lifecycle exercise')
        if self.installed_version()!=self.release_id:raise GuestError('exercise must begin on authenticated current release')
        alternate = self.baseline.get('forward_release_id') if self.route=='portable' and self.baseline['kind']=='first-release-fixture' else self.baseline['release_id']
        if not alternate or alternate==self.release_id:raise GuestError('lifecycle needs an actual different release id')
        if self.route=='portable':
            if self.baseline['kind']=='previous-stable':
                self.target(alternate);self.wait_http();self.preserved()
                self.target(self.release_id);self.wait_http();self.preserved();self.mark('update')
                self.reset_budget()
                self.command(['/usr/local/sbin/httpjetctl','rollback','--version',alternate]);self.wait_http();self.preserved();self.mark('rollback')
                self.target(self.release_id);self.wait_http()
            else:
                self.target(alternate);self.wait_http();self.preserved();self.mark('update')
                self.reset_budget()
                self.command(['/usr/local/sbin/httpjetctl','rollback','--version',self.release_id])
                if self.installed_version()!=self.release_id:raise GuestError('offline rollback did not restore current release')
                self.wait_http();self.preserved();self.mark('rollback')
        else:
            self.target(alternate,local=True);self.wait_http();self.preserved()
            self.mark('downgrade' if self.route=='deb' else 'rollback')
            self.target(self.release_id);self.wait_http();self.preserved()
            self.mark('upgrade' if self.route=='deb' else 'update')
        self.service_action('disable');self.service_action('stop')
        self.target(alternate,local=self.route!='portable')
        if self.active() or self.enabled():raise GuestError('real update restarted or enabled an opted-out service')
        self.preserved()
        self.service_action('enable')
        self.target(self.release_id)
        if self.active() or not self.enabled():raise GuestError('real update failed to retain enabled-but-stopped state')
        self.preserved()
        self.report['optouts']={'disabled_stopped_real_transition':True,'enabled_stopped_real_transition':True}
        self.service_action('start');self.wait_http();self.inspect()
        self.mark('config-preserved');self.mark('content-preserved')
        self.denial()
        if self.route=='portable':
            self.command(['/usr/local/sbin/httpjetctl','uninstall'])
            if Path('/usr/local/bin/httpjet').exists() or self.active():raise GuestError('generic uninstall left a live/installed service')
            self.preserved();self.mark('uninstall')
            self.bootstrap(self.release_id)
            self.service_action('enable');self.reset_budget();self.service_action('start')
        else:
            self.remove_native()
            if self.active():raise GuestError('package removal left the service active')
            self.preserved(configuration=self.route=='deb')
            if self.route=='rpm':
                saved=json.loads(self.state_file.read_text())['configuration_sha256']
                options=(Path('/etc/httpjet/conf/vhosts/default.xml'),Path('/etc/httpjet/conf/vhosts/default.xml.rpmsave'))
                if not any(path.is_file() and sha(path)==saved for path in options):
                    raise GuestError('RPM removal discarded edited configuration instead of preserving it/rpmsave')
            self.mark('remove' if self.route=='deb' else 'uninstall')
            if self.route=='deb':
                self.remove_native(purge=True)
                if Path('/etc/httpjet/conf/vhosts/default.xml').exists():raise GuestError('purge retained packaged conffile')
                if not Path('/usr/share/keyrings/httpjet-archive-keyring.asc').is_file():raise GuestError('server purge removed independent APT trust')
                self.preserved(configuration=False);self.mark('purge')
            self.reset_budget();self.install_native_current()
        self.wait_http();self.mark('reinstall')
        self.preserved(configuration=self.route=='portable')
        state=json.loads(self.state_file.read_text())
        state['configuration_sha256']=sha('/etc/httpjet/conf/vhosts/default.xml')
        save(self.state_file,state)
        service=self.inspect()
        if service['uid']!=state['uid']:raise GuestError('reinstall changed the dedicated service identity')

    def inspect_after_boot(self):
        self.wait_http();self.preserved();service=self.inspect()
        state=json.loads(self.state_file.read_text())
        if service['uid']!=state['uid'] or service['binary_sha256']!=state['binary_sha256']:
            raise GuestError('reboot changed the installed service identity/payload')
        self.mark('content-preserved')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('install','exercise','inspect'))
    parser.add_argument('--spec',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    if os.geteuid()!=0:raise GuestError('guest qualification requires root inside its disposable VM')
    work=Path.cwd()
    if not work.name.startswith('httpjet-qualification-'):
        raise GuestError('refusing execution outside a disposable guest qualification directory')
    controller=Controller(json.loads(args.spec.read_text()),work)
    try:
        getattr(controller,{'install':'install','exercise':'exercise','inspect':'inspect_after_boot'}[args.mode])()
        controller.report['status']='passed'
    except Exception:
        controller.report['status']='failed'
        save(args.output,controller.report)
        raise
    save(args.output,controller.report)
    save(work/'service.json',controller.report['service'])


if __name__=='__main__':
    try:main()
    except (GuestError,OSError,ValueError,KeyError,subprocess.SubprocessError) as error:
        raise SystemExit('guest qualification: '+str(error))
