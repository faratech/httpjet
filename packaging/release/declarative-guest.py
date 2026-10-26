#!/usr/bin/env python3
"""Exercise native system generations using declarative inputs, never /etc edits."""
import argparse,hashlib,http.client,json,os,subprocess,time
from pathlib import Path

def run(command,env=None):
    result=subprocess.run([str(x) for x in command],env=env,check=True,text=True,capture_output=True,timeout=3600)
    print(result.stdout,end='',flush=True);print(result.stderr,end='',flush=True)
    return result.stdout.strip()
def http():
    connection=http.client.HTTPConnection('127.0.0.1',80,timeout=3)
    try:
        connection.request('GET','/');response=connection.getresponse();body=response.read(2*1024*1024)
        return body if response.status==200 else None
    finally:connection.close()
def ready(timeout=60):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        try:
            if http() is not None:return
        except (OSError,http.client.HTTPException):pass
        time.sleep(.5)
    raise RuntimeError('native declarative service did not become ready')
def service(spec):
    import pwd,re
    account=pwd.getpwnam('httpjet');route=spec['row']['route'];pids=[]
    if route=='nixos':pids=[int(run(['systemctl','show','--property=MainPID','--value','httpjet']))]
    else:
        for marker in Path('/run/httpjet').glob('launch-*/ready'):
            try:
                if re.fullmatch(rb'[1-9][0-9]*\n',marker.read_bytes()):pids.append(int(marker.read_text()))
            except OSError:pass
    for pid in pids:
        try:
            proc=Path('/proc')/str(pid);status=(proc/'status').read_text().splitlines()
            uid=int(next(line for line in status if line.startswith('Uid:')).split()[2])
            gid=int(next(line for line in status if line.startswith('Gid:')).split()[2])
            exe=proc/'exe'
            with exe.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
            argv=(proc/'cmdline').read_bytes().split(b'\0')
            if uid!=account.pw_uid or uid<=0 or digest!=spec['manifest']['binaries'][spec['row']['architecture']]['binary_sha256'] or b'--no-multishot-accept' not in argv:continue
            return {'schema':2,'scope':'installed-init-service','uid':uid,'gid':gid,'pid':pid,'executable':str(exe.resolve()),'binary_sha256':digest,
                    'init':spec['row']['init'],'init_pid1':Path('/proc/1/comm').read_text().strip(),'no_multishot_accept':True}
        except (OSError,ValueError,StopIteration):pass
    raise ValueError('native init did not expose the expected service UID/executable')

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--mode',choices=('install','inspect','exercise'),default='exercise');parser.add_argument('--spec',required=True,type=Path);parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args();spec=json.loads(args.spec.read_text());row=spec['row'];work=args.spec.parent
    if os.geteuid()!=0 or row['route'] not in ('nixos','guix'):raise ValueError('native controller requires its disposable guest root')
    if args.mode in ('install','inspect'):
        ready();observed=service(spec);checks={}
        if args.mode=='install':
            if http()!=(work/spec['expected_welcome']).read_bytes():raise ValueError('native first welcome differs from authenticated payload')
            checks={name:'passed' for name in ('declarative-install','http','unprivileged') if name in row['checks']}
        else:
            state=json.loads((work/'native-state.json').read_text())
            if observed['uid']!=state['uid'] or observed['binary_sha256']!=state['binary_sha256'] or hashlib.sha256(Path('/var/www/httpjet/operator-content.txt').read_bytes()).hexdigest()!=state['operator_content_sha256']:
                raise ValueError('native reboot changed identity or user content')
            checks={name:'passed' for name in ('content-preserved',) if name in row['checks']}
        args.output.write_text(json.dumps({'schema':2,'status':'passed','checks':checks,'service':observed},indent=2,sort_keys=True)+'\n');return
    checks={};events=[]
    def mark(name):
        if name in row['checks']:checks[name]='passed';print('HTTPJET_CHECK '+name+' passed',flush=True)
    ready();mark('declarative-install')
    site=Path('/var/www/httpjet/operator-content.txt');site.write_text('operator-owned persistent native data\n');expected=hashlib.sha256(site.read_bytes()).hexdigest()
    before=str(Path('/run/current-system').resolve())
    if row['route']=='nixos':
        candidate=Path('/run/booted-system').resolve();baseline=candidate/'specialisation/httpjet-baseline';disabled=candidate/'specialisation/httpjet-disabled'
        def activate(path):
            run(['nix-env','--profile','/nix/var/nix/profiles/system','--set',path]);run([path/'bin/switch-to-configuration','switch']);events.append(str(path))
        activate(baseline);ready();activate(candidate);ready();mark('declarative-update')
        run(['nix-env','--profile','/nix/var/nix/profiles/system','--rollback'])
        selected=Path('/nix/var/nix/profiles/system').resolve()
        if selected!=baseline.resolve():raise ValueError('Nix rollback did not select the declared baseline generation')
        run([selected/'bin/switch-to-configuration','switch']);ready();mark('declarative-rollback')
        activate(disabled)
        if subprocess.run(['systemctl','is-active','--quiet','httpjet']).returncode==0:raise ValueError('disabled Nix generation retained service')
        mark('declarative-uninstall');activate(candidate);ready()
    else:
        definition=spec['declarative'];source=(work/definition['source']).resolve()
        environment=os.environ.copy()
        environment.update(HTTPJET_GUIX_RELEASE_LOCK=str((work/definition['release_lock']).resolve()),
                           HTTPJET_QUALIFICATION_SSH_KEY=str((work/definition['ssh_key']).resolve()),
                           HTTPJET_GUIX_TEST_CA=str((work/definition['ca']).resolve()),
                           HTTPJET_GUIX_SYSTEM=definition['system'],
                           GUIX_TLS_CERTIFICATE_DIRECTORY='/etc/httpjet-qualification/certs')
        if definition.get('previous_lock'):environment['HTTPJET_GUIX_BASELINE_LOCK']=str((work/definition['previous_lock']).resolve())
        def activate(variant):
            environment['HTTPJET_GUIX_VARIANT']=variant
            run(['guix','system','-L',source,'reconfigure',source/'qualification.scm'],environment)
            selected=str(Path('/run/current-system').resolve());events.append(selected);return selected
        baseline=activate('baseline');ready();candidate=activate('candidate');ready()
        if baseline==candidate:raise ValueError('Guix package update did not create a different generation')
        mark('declarative-update')
        run(['guix','system','roll-back'],environment)
        if str(Path('/run/current-system').resolve())!=baseline:raise ValueError('Guix rollback did not activate the baseline generation')
        ready();mark('declarative-rollback')
        activate('disabled')
        if subprocess.run(['herd','status','httpjet']).returncode==0:raise ValueError('disabled Guix generation retained service')
        mark('declarative-uninstall');activate('candidate');ready()
    if hashlib.sha256(site.read_bytes()).hexdigest()!=expected:raise ValueError('native generation transition modified operator data')
    mark('content-preserved')
    run(['systemctl','restart','httpjet'] if row['route']=='nixos' else ['herd','restart','httpjet']);ready();mark('restart')
    observed=service(spec)
    (work/'native-state.json').write_text(json.dumps({**observed,'operator_content_sha256':expected})+'\n')
    args.output.write_text(json.dumps({'schema':2,'checks':checks,'service':observed,'baseline_kind':spec['baseline']['kind'],
         'system_before':before,'system_after':str(Path('/run/current-system').resolve()),'generation_events':events,
         'operator_content_sha256':expected},indent=2,sort_keys=True)+'\n')
if __name__=='__main__':main()
