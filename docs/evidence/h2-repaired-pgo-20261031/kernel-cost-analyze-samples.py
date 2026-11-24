import json,re,collections,hashlib
from pathlib import Path
ROOT=Path('/var/tmp/h2-kernel-cost-analysis-v2')
HEADER=re.compile(r'^(.*?)\s+(\d+)/(\d+)\s+\[(\d+)\]\s+(\d+)\.(\d+):\s*(.*)$')
FRAME=re.compile(r'^\s+([0-9a-f]+)\s+(.*?)\s+\((.*)\)$')
FORK=re.compile(r'PERF_RECORD_FORK\((\d+):(\d+)\):\((\d+):(\d+)\)')
IDLE={'pv_native_safe_halt','native_safe_halt','acpi_idle_enter','intel_idle','poll_idle','default_idle'}

def parse(path):
 samples=[];tasks={};forks=[];current=None
 for line in path.read_text().splitlines():
  m=HEADER.match(line)
  if m:
   if current:samples.append(current);current=None
   comm,pid,tid,cpu,sec,fraction,event=m.groups();ns=int(sec)*10**9+int(fraction.ljust(9,'0'))
   f=FORK.search(event)
   if f:
    tgid,t,pgid,pt=map(int,f.groups());tasks[t]=tgid;forks.append({'tgid':tgid,'tid':t,'parent_tgid':pgid,'parent_tid':pt,'time_ns':ns})
   if event.startswith('cpu-clock:k:'):
    current={'comm':comm.strip(),'pid':int(pid),'tid':int(tid),'cpu':int(cpu),'ns':ns,'frames':[]}
   continue
  f=FRAME.match(line)
  if current and f:current['frames'].append({'ip':int(f.group(1),16),'symbol':f.group(2),'dso':f.group(3)})
 if current:samples.append(current)
 return samples,tasks,forks

def counters(values,n=20):return [{'name':k,'samples':v} for k,v in values.most_common(n)]
results=[]
for directory in sorted((ROOT/'results').glob('h2c-*')):
 receipt=json.loads((directory/'kernel-profile/receipt.json').read_text());raw=json.loads((directory/'result.json').read_text())
 stats=json.loads((directory/'bpf-runtime/stats.json').read_text())
 begin,end=receipt['client_start_monotonic_ns'],receipt['client_complete_monotonic_ns']
 samples,tasks,forks=parse(directory/'kernel-profile/script.txt')
 selected=[s for s in samples if begin<=s['ns']<=end]
 ranges=[]
 for p in stats['programs']:
  before=p['before'];assert sum(before['jited_func_lens'])==before['jited_prog_len']
  for i,(address,length) in enumerate(zip(before['jited_ksyms'],before['jited_func_lens'])):ranges.append((address,address+length,p['name'],i))
 def owner(frame):
  return next(((p,i) for lo,hi,p,i in ranges if lo<=frame['ip']<hi),None)
 def role(sample):
  for name,value in receipt['targets'].items():
   if sample['pid']==value['pid']:return name
  return 'pid0-context' if sample['pid']==0 else 'other'
 active=[s for s in selected if s['frames'] and s['frames'][0]['symbol'] not in IDLE]
 leaf=collections.Counter();families=collections.Counter();contexts=collections.Counter();context_leaves=collections.defaultdict(collections.Counter);bpf_leaf=collections.Counter();bpf_offsets=collections.Counter();bpfcalls=collections.Counter();client_tids=collections.Counter();softirq_context=collections.Counter();family_context=collections.defaultdict(collections.Counter);examples={}
 for s in active:
  r=role(s);symbols=[f['symbol'] for f in s['frames']];first=symbols[0];leaf[first]+=1;contexts[r]+=1;context_leaves[r][first]+=1
  owned=[(j,o) for j,f in enumerate(s['frames']) if (o:=owner(f))]
  if r=='client':client_tids[s['tid']]+=1
  softirq=any(x in symbols for x in ['__do_softirq','handle_softirqs','net_rx_action','irq_exit_rcu'])
  if softirq:softirq_context[r]+=1
  flags={
   'owned_bpf_ancestor':bool(owned),
   'owned_bpf_leaf':owner(s['frames'][0]) is not None,
   'bpf_iterator':any(x.startswith('bpf_iter_num_') for x in symbols),
   'bpf_pull_helper':any(x=='bpf_msg_pull_data' for x in symbols),
   'probe_read_helper':any(x.startswith(('bpf_probe_read','copy_from_kernel_nofault')) for x in symbols),
   'tcp_psock_network':any(x.startswith(('tcp_','__tcp','sk_psock','ip_','__ip','inet_','sock_','__sock','skb_','__dev_','net_rx','process_backlog','__net')) for x in symbols),
   'poll_readiness':any(x.startswith(('io_poll','__io_poll','io_uring_poll','tcp_poll','sock_poll','vfs_poll','sk_msg_is_readable')) for x in symbols),
   'timer':any('hrtimer' in x or x in ['run_timer_softirq','__run_timers','timerqueue_add','timerqueue_del'] for x in symbols),
   'scheduler_wakeup':any(x.startswith(('try_to_wake_up','ttwu_','schedule','__schedule','finish_task_switch','wake_up','__wake_up')) for x in symbols),
   'io_uring':any(x.startswith(('io_','__io_')) for x in symbols),
   'softirq':softirq,
  }
  for k,value in flags.items():
   if value:families[k]+=1;family_context[k][r]+=1
  if owned:
   program,index=owned[0][1];bpfcalls[program]+=1;bpf_leaf[(program,first)]+=1
   if owner(s['frames'][0]):
    program,index=owner(s['frames'][0]);lo=next(lo for lo,hi,p,i in ranges if p==program and i==index);bpf_offsets[(program,index,s['frames'][0]['ip']-lo)]+=1
   examples.setdefault(program,{'context':r,'tid':s['tid'],'symbols':symbols})
 report={'arm':directory.name,'client_window_ns':[begin,end],'sample_total':len(samples),'within_window':len(selected),'active_nonidle':len(active),'idle_leaf':len(selected)-len(active),
  'targets':receipt['targets'],'contexts':dict(contexts),'leaf_top':counters(leaf,40),'context_leaf_top':{k:counters(v,20) for k,v in context_leaves.items()},'inclusive_stack_families':dict(families),'family_context':{k:dict(v) for k,v in family_context.items()},'softirq_context':dict(softirq_context),
  'client_tids_observed':dict(client_tids),'client_fork_records':[f for f in forks if f['tgid']==receipt['targets']['client']['pid']],
  'client_tids_all_have_recorded_tgid':all(tasks.get(t)==receipt['targets']['client']['pid'] for t in client_tids),
  'owned_bpf_samples':dict(bpfcalls),'bpf_leaf_samples':[{'program':p,'symbol':name,'samples':n} for (p,name),n in bpf_leaf.most_common()],
  'bpf_leaf_offsets':[{'program':p,'function_index':i,'offset':off,'samples':n} for (p,i,off),n in bpf_offsets.most_common()], 'bpf_examples':examples,
  'stats':stats,'note':'99Hz kernel-mode sampling includes idle; nonidle count is leaf-filtered. Stack families overlap; pid0/context and softirq are not exclusive process ownership. BPF elapsed counters are not additive with process CPU.'}
 results.append(report)
 print(directory.name,'window',len(selected),'nonidle',len(active),'contexts',dict(contexts),'families',dict(families))
 print('leaf top',leaf.most_common(12));print('BPF leaf',bpf_leaf.most_common(10));print('clientTGID',report['client_tids_all_have_recorded_tgid'],'tids',dict(client_tids))
(ROOT/'sample-analysis.json').write_text(json.dumps({'diagnostic_only':True,'arms':results},indent=2)+'\n')
