#!/usr/bin/env python3
"""Apply an explicitly locked operator policy only inside a disposable test image."""
import argparse,json,os,pwd
from pathlib import Path
import probe

def prepare(spec,qualifier):
    if os.geteuid()!=0:raise ValueError('image preparation needs disposable guest root')
    desired=spec['image_lock'].get('operator_configuration')
    before=probe.policy()
    report={'schema':1,'scope':'disposable-qualification-image','before':before,'after':before,'changed':False}
    if not desired:return report
    if desired!={'scope':'disposable-qualification-image','io_uring_disabled':0,'record_stock_policy':True}:
        raise ValueError('operator setup is outside the locked qualification policy')
    marker=Path('/run/httpjet-disposable-qualification')
    if not marker.is_file() or marker.stat().st_uid!=0:raise ValueError('refusing operator preparation outside the declared disposable image')
    if before in ('1','2'):
        try:account=pwd.getpwnam('nobody')
        except KeyError:raise ValueError('stock policy check needs its non-root nobody account')
        report['stock_probe']=probe.positive(qualifier,account.pw_uid,account.pw_gid)
        if before=='2' and report['stock_probe']['status']!='failed':raise ValueError('stock disabled policy did not fail as expected')
        path=Path('/proc/sys/kernel/io_uring_disabled')
        path.write_text('0\n')
        # This is the explicit operator's disposable image configuration, not
        # installer/probe behavior. Preserve it for the required guest reboot.
        target=Path('/etc/sysctl.d/99-httpjet-qualification-operator.conf');target.parent.mkdir(parents=True,exist_ok=True)
        target.write_text('# Disposable qualification image operator choice only\nkernel.io_uring_disabled=0\n')
        report.update(after=probe.policy(),changed=True)
        if report['after']!='0':raise ValueError('locked operator image configuration was not applied')
    return report

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--spec',required=True,type=Path);parser.add_argument('--probe',required=True,type=Path);parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args();result=prepare(json.loads(args.spec.read_text()),args.probe)
    args.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
if __name__=='__main__':main()
