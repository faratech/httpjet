import importlib.machinery, os, socket, struct, subprocess, time
probe = importlib.machinery.SourceFileLoader("lsapi_probe", os.environ.get("LSAPI_PROBE", "/web/scripts/lsapi_probe.py")).load_module()
D = os.path.dirname(os.path.abspath(__file__))

def frame(script, qs, body_len=0, cnt_env=None):
    f = bytearray(probe.build_begin_request(script.encode(), script.encode(), qs=qs.encode()))
    struct.pack_into("<i", f, 12, body_len)
    if cnt_env is not None:
        struct.pack_into("<i", f, 36, cnt_env)
    return bytes(f)

def case(variant, name, run):
    sock, log, err = f"{D}/c.sock", f"{D}/c.log", f"{D}/asan-{variant}-{name}.txt"
    for p in (sock, log):
        if os.path.exists(p): os.unlink(p)
    env = dict(os.environ, ASAN_OPTIONS="exitcode=99")
    proc = subprocess.Popen([f"{D}/harness-{variant}", sock, log], stderr=open(err, "w"), env=env)
    for _ in range(60):
        if os.path.exists(sock): break
        time.sleep(0.05)
    s = socket.socket(socket.AF_UNIX); s.settimeout(2); s.connect(sock)
    out = run(s)
    time.sleep(0.3); s.close(); time.sleep(0.3)
    if proc.poll() is None: proc.terminate(); proc.wait(5)
    ran = open(log).read().split() if os.path.exists(log) else []
    asan = "ERROR: AddressSanitizer" in open(err).read()
    return out, ran, proc.returncode, asan

def t1(s):
    forged = frame("/evil", "0")
    s.sendall(frame("/legit", "8192", 8192 + len(forged)) + b"A" * 8192 + forged)
    for _ in range(2):
        try: probe.read_response(s)
        except Exception: break

def t2(s):
    # A negative env count with records that fit the packet: parseEnv walks past the list.
    f = bytearray(frame("/neg", "0", 0, cnt_env=-1))
    s.sendall(bytes(f))
    try: s.recv(1)
    except Exception: pass

def t3(s):
    f = frame("/split", "0")
    s.sendall(f[:4]); time.sleep(0.2); s.sendall(f[4:])
    try: return probe.read_response(s)[2]
    except Exception as e: return repr(e)

for v in ("orig", "patched"):
    _, ran, rc, asan = case(v, "t1", t1)
    print(f"{v:8} T1 forged tail executed={'/evil' in ran} ran={ran}")
    _, ran, rc, asan = case(v, "t2", t2)
    print(f"{v:8} T2 negative count: asan_error={asan} exit={rc}")
    out, ran, rc, asan = case(v, "t3", t3)
    print(f"{v:8} T3 header split across writes: served={out == b'/split'} out={out!r}")
