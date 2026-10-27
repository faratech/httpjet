#!/usr/bin/env python3
"""Root-owned generic installer/controller; Python 3 standard library only."""
from __future__ import annotations
import argparse
import errno
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request

RELEASE_ID = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+-[0-9]+")
ARCHES = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
MAX_ARCHIVE = 128 * 1024 * 1024
TRUSTED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
INSPECT_PROCESS = r'''
import json,sys
from pathlib import Path
pid=int(sys.argv[1]); proc=Path('/proc')/str(pid)
status=proc.joinpath('status').read_text().splitlines()
uids=list(map(int,next(x for x in status if x.startswith('Uid:')).split()[1:]))
gids=list(map(int,next(x for x in status if x.startswith('Gid:')).split()[1:]))
text=proc.joinpath('stat').read_text(); started=int(text[text.rfind(')')+2:].split()[19])
with proc.joinpath('cmdline').open('rb') as stream: arguments=stream.read(8193)
if len(arguments)>8192: raise SystemExit('process argument bound exceeded')
print(json.dumps({'pid':pid,'uids':uids,'gids':gids,'started':started,
 'executable':str(proc.joinpath('exe').resolve(strict=True)),
 'arguments':[x.decode('utf-8','surrogateescape') for x in arguments.split(b'\0')]}))
'''

class InstallError(RuntimeError):
    pass

def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()

def version_tuple(value):
    if not isinstance(value, str) or not RELEASE_ID.fullmatch(value):
        raise InstallError("release id must be X.Y.Z-N")
    return tuple(map(int, value.replace("-", ".").split(".")))

def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".httpjet-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

def checked_url(base, relative):
    parsed = urllib.parse.urlsplit(base)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise InstallError("release base must be HTTPS without credentials/query/fragment")
    return base.rstrip("/") + "/" + relative

def download(url, destination, limit):
    class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, message, headers, newurl):
            if urllib.parse.urlsplit(newurl).scheme != "https":
                raise InstallError("refusing an HTTPS downgrade redirect")
            return super().redirect_request(request, fp, code, message, headers, newurl)
    request = urllib.request.Request(url, headers={"User-Agent": "httpjet-installer/2"})
    deadline = time.monotonic() + 180
    with urllib.request.build_opener(HTTPSRedirect()).open(request, timeout=30) as response, Path(destination).open("xb") as output:
        if urllib.parse.urlsplit(response.url).scheme != "https":
            raise InstallError("refusing an HTTPS downgrade redirect")
        length = 0
        while True:
            if time.monotonic() >= deadline:
                raise InstallError("release download exceeded its total deadline")
            block = response.read(min(1024 * 1024, limit + 1 - length))
            if not block:
                break
            length += len(block)
            if length > limit:
                raise InstallError("release download exceeds its size bound")
            output.write(block)

def run(command, *, check=True, timeout=60, **kwargs):
    return subprocess.run([str(x) for x in command], check=check, timeout=timeout,
                          stdin=subprocess.DEVNULL, env={"PATH": TRUSTED_PATH}, **kwargs)

def verify_signature(document, signature_file, public_key, expected, home):
    if not re.fullmatch(r"[A-F0-9]{40}|[A-F0-9]{64}", expected):
        raise InstallError("invalid approved archive fingerprint")
    gpg = shutil.which("gpg2", path=TRUSTED_PATH) or shutil.which("gpg", path=TRUSTED_PATH)
    if not gpg:
        raise InstallError("full GnuPG (gpg2 or gpg) is required")
    home.mkdir(mode=0o700, exist_ok=True)
    # Select once; never retry another implementation after verification fails.
    command = [gpg, "--batch", "--homedir", home, "--no-auto-key-retrieve"]
    run(command + ["--import", public_key], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    result = run(command + ["--with-colons", "--list-keys"], capture_output=True, text=True)
    primary, pending = [], False
    for line in result.stdout.splitlines():
        fields = line.split(":")
        if fields[0] == "pub":
            if fields[1] in ("r", "e", "d"):
                raise InstallError("archive key is expired, revoked or disabled")
            pending = True
        elif pending and fields[0] == "fpr":
            primary.append(fields[9]); pending = False
    if primary != [expected]:
        raise InstallError("public key differs from approved primary fingerprint")
    run(command + ["--verify", signature_file, document], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def safe_extract(archive, destination, release_id):
    """Validate every member before creating any extracted file; never tar.extract."""
    version_tuple(release_id)
    prefix = "httpjet-" + release_id
    destination.mkdir(mode=0o700)
    seen, total = set(), 0
    with tarfile.open(archive, "r:gz") as source:
        members = []
        for member in source:
            if len(members) >= 4096:
                raise InstallError("too many archive members")
            members.append(member)
            name = member.name.rstrip("/")
            parts = name.split("/")
            if not re.fullmatch(r"[A-Za-z0-9_./+\-]+", name) or any(p in ("", ".", "..") for p in parts) or parts[0] != prefix:
                raise InstallError("unsafe archive member path")
            if name in seen or not (member.isdir() or member.isfile()) or member.issparse():
                raise InstallError("duplicate, link, device or unsupported archive member")
            seen.add(name)
            total += member.size
            if member.size > 64 * 1024 * 1024 or total > 512 * 1024 * 1024:
                raise InstallError("archive expanded size exceeds bound")
        for member in members:
            target = destination.joinpath(*member.name.rstrip("/").split("/"))
            directory = target if member.isdir() else target.parent
            missing = []
            while not directory.exists():
                missing.append(directory)
                directory = directory.parent
            for directory in reversed(missing):
                directory.mkdir(mode=0o755)
                directory.chmod(0o755)
            if member.isdir():
                continue
            else:
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as output, source.extractfile(member) as stream:
                    shutil.copyfileobj(stream, output)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
    payload = destination / prefix
    for required in ("bin/httpjet", "share/httpjet/conf/httpd_config.xml", "share/httpjet/conf/vhosts/default.xml",
                     "share/httpjet/welcome/index.html", "share/httpjet/services/manage.py", "share/httpjet/services/launch"):
        if not (payload / required).is_file():
            raise InstallError("archive is missing required payload: " + required)
    return payload

def fetch_release(base, requested, architecture, key, fingerprint, work, current=None):
    if architecture not in ("amd64", "arm64"):
        raise InstallError("native amd64 or arm64 is required")
    manifest_hash = manifest_size = None
    if requested:
        version_tuple(requested)
        selected = requested
    else:
        pointer, signature_file = work / "stable.json", work / "stable.json.asc"
        download(checked_url(base, "stable.json"), pointer, 1024 * 1024)
        download(checked_url(base, "stable.json.asc"), signature_file, 64 * 1024)
        verify_signature(pointer, signature_file, key, fingerprint, work / "gpg")
        metadata = json.loads(pointer.read_text())
        if metadata.get("schema") != 2:
            raise InstallError("unsupported stable selector schema")
        now = datetime.now(timezone.utc)
        issued = datetime.fromisoformat(metadata["issued_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(metadata["expires_at"].replace("Z", "+00:00"))
        if issued.tzinfo is None or expires.tzinfo is None or issued > now + timedelta(hours=1) or expires <= now or expires <= issued or expires-issued > timedelta(days=30, minutes=1):
            raise InstallError("stable selector is expired or has invalid timestamps")
        selected = metadata["release_id"]
        if current and version_tuple(selected) < version_tuple(current):
            raise InstallError("stable would downgrade installation; select --version explicitly")
        version_tuple(selected)
        manifest_hash, manifest_size = metadata["manifest_sha256"], metadata["manifest_size"]
    document, signature_file = work / "manifest.json", work / "manifest.json.asc"
    download(checked_url(base, selected + "/manifest.json"), document, 1024 * 1024)
    download(checked_url(base, selected + "/manifest.json.asc"), signature_file, 64 * 1024)
    verify_signature(document, signature_file, key, fingerprint, work / "gpg")
    if manifest_hash and (digest(document) != manifest_hash or document.stat().st_size != manifest_size):
        raise InstallError("manifest differs from signed stable selector")
    metadata = json.loads(document.read_text())
    if metadata.get("schema") != 2 or metadata.get("release_id") != selected or metadata.get("archive_fingerprint") != fingerprint:
        raise InstallError("manifest release/key identity mismatch")
    binary = metadata["binaries"][architecture]
    name = "httpjet-" + selected + "-linux-" + architecture + "-static.tar.gz"
    artifact = metadata["artifacts"].get(name, {})
    if binary["artifact"] != name or binary.get("libc") != "musl" or artifact.get("architecture") != architecture or artifact.get("libc") != "musl":
        raise InstallError("manifest does not select a static musl payload for this architecture")
    size, expected_hash = artifact.get("size"), artifact.get("sha256", "")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_hash) or not isinstance(size, int) or not 0 < size <= MAX_ARCHIVE:
        raise InstallError("invalid artifact hash or size")
    archive = work / name
    download(checked_url(base, selected + "/" + name), archive, size)
    if archive.stat().st_size != size or digest(archive) != expected_hash:
        raise InstallError("static payload hash/size mismatch")
    payload = safe_extract(archive, work / "extracted", selected)
    if digest(payload / "bin/httpjet") != binary["binary_sha256"]:
        raise InstallError("ELF hash differs from signed manifest")
    return payload, selected, metadata

class Manager:
    def __init__(self, root=Path("/")):
        self.root = Path(root)
        self.prefix = self.path("/opt/httpjet")
        self.state_dir = self.path("/var/lib/httpjet-installer")
        self.state_file = self.state_dir / "state.json"
        self.ready = self.path("/run/httpjet/ready")
        self.link = self.path("/usr/local/bin/httpjet")

    def path(self, value):
        return self.root / value.lstrip("/")

    def guard(self, path):
        for component in [Path(path), *Path(path).parents]:
            if component == self.root.parent and self.root != Path("/"):
                break
            if component.is_symlink():
                raise InstallError("managed path has a symlink component: " + str(component))
            if component.exists():
                info = component.stat()
                if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                    raise InstallError("managed path is not root-owned/protected: " + str(component))

    def load(self):
        self.guard(self.state_dir)
        if not self.state_file.exists():
            return None
        info = self.state_file.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o077:
            raise InstallError("ownership state must be a private, regular file")
        state = json.loads(self.state_file.read_text())
        if state.get("schema") != 2 or state.get("method") != "binary":
            raise InstallError("unrecognized installation ownership state")
        return state

    def lock(self):
        self.guard(self.state_dir)
        self.state_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        fd = os.open(self.state_dir / "lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd

    def save(self, state):
        atomic_json(self.state_file, state)

    def no_takeover(self, state):
        for command in (["dpkg-query", "-W", "-f=${Status}", "httpjet"], ["rpm", "-q", "httpjet"]):
            if shutil.which(command[0]):
                result = run(command, check=False, capture_output=True, text=True)
                if result.returncode == 0 and (command[0] == "rpm" or result.stdout.strip() == "install ok installed"):
                    raise InstallError("native package owns httpjet; use its package manager")
        if state:
            expected = self.prefix / "releases" / state["current"] / "bin/httpjet" if state.get("current") else None
            if self.link.is_symlink() and expected and self.link.resolve() != expected:
                raise InstallError("installer-owned command link was replaced")
            if self.link.exists() and not self.link.is_symlink():
                raise InstallError("httpjet command is no longer installer-owned")
            for relative, expected_hash in state.get("owned", {}).items():
                if relative.startswith("opt/httpjet/libexec/") or relative == "usr/local/sbin/httpjetctl":
                    owned = self.root / relative
                    if owned.is_symlink() or (owned.exists() and (not owned.is_file() or digest(owned) != expected_hash)):
                        raise InstallError("administrator modified a privileged helper: " + str(owned))
            return
        for name in ("/opt/httpjet", "/usr/bin/httpjet", "/usr/local/bin/httpjet", "/usr/local/sbin/httpjetctl",
                     "/etc/httpjet", "/var/www/httpjet", "/etc/systemd/system/httpjet.service", "/usr/local/lib/systemd/system/httpjet.service", "/etc/init.d/httpjet", "/etc/rc.d/rc.httpjet", "/etc/sv/httpjet"):
            candidate = self.path(name)
            if candidate.exists() or candidate.is_symlink():
                raise InstallError("unmanaged installation exists at " + name)

    def account(self, state):
        def lookup(database):
            if shutil.which("getent"):
                result = run(["getent", database, "httpjet"], check=False, capture_output=True, text=True)
                return result.stdout.strip().split(":") if result.returncode == 0 else None
            source = self.path("/etc/" + ("passwd" if database == "passwd" else "group"))
            return next((line.split(":") for line in source.read_text().splitlines() if line.split(":", 1)[0] == "httpjet"), None)
        account, group = lookup("passwd"), lookup("group")
        if state:
            if not account or not group or int(account[2]) != state["uid"] or int(group[2]) != state["gid"] or int(account[3]) != state["gid"] or account[5] != "/var/lib/httpjet" or account[6] not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false"):
                raise InstallError("recorded service account identity changed")
            return state["uid"], state["gid"]
        if account or group:
            raise InstallError("pre-existing httpjet account/group is not installer-owned")
        shell = next((name for name in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false") if self.path(name).exists()), None)
        if not shell:
            raise InstallError("nologin or /bin/false is required")
        if shutil.which("useradd") and shutil.which("groupadd"):
            run(["groupadd", "--system", "httpjet"])
            run(["useradd", "--system", "--gid", "httpjet", "--home-dir", "/var/lib/httpjet", "--no-create-home", "--shell", shell, "httpjet"])
        elif shutil.which("adduser") and shutil.which("addgroup"):
            help_text = run(["adduser", "--help"], check=False, capture_output=True, text=True)
            if "BusyBox" not in help_text.stdout + help_text.stderr:
                raise InstallError("install shadow useradd/groupadd or supported BusyBox account tools")
            run(["addgroup", "-S", "httpjet"])
            run(["adduser", "-S", "-D", "-H", "-h", "/var/lib/httpjet", "-s", shell, "-G", "httpjet", "httpjet"])
        else:
            raise InstallError("account tools unavailable (shadow or BusyBox required)")
        account, group = lookup("passwd"), lookup("group")
        if not account or not group or int(account[2]) == 0 or int(account[3]) != int(group[2]):
            raise InstallError("service-account creation did not produce a dedicated non-root identity")
        return int(account[2]), int(group[2])

    def process(self, pid, state):
        try:
            proc = self.path("/proc/" + str(pid))
            status = (proc / "status").read_text().splitlines()
            uids = list(map(int, next(line for line in status if line.startswith("Uid:")).split()[1:]))
            gids = list(map(int, next(line for line in status if line.startswith("Gid:")).split()[1:]))
            if not state.get("current") or state["uid"] <= 0 or state["gid"] <= 0 or any(uid != state["uid"] for uid in uids) or any(gid != state["gid"] for gid in gids):
                return None
            def inspect():
                text = (proc / "stat").read_text()
                started = int(text[text.rfind(")") + 2:].split()[19])
                return started, (proc / "exe").resolve(strict=True), (proc / "cmdline").read_bytes().split(b"\0")
            try:
                started, executable, arguments = inspect()
            except PermissionError:
                # Container root need not have CAP_SYS_PTRACE. A clean child
                # uses exactly the launch identity and minimal existing cap;
                # the privileged controller never changes its own credentials.
                tool = shutil.which("setpriv")
                if not tool:
                    raise InstallError("cannot inspect service process: setpriv is unavailable")
                result = run([tool, "--reuid", state["uid"], "--regid", state["gid"], "--init-groups",
                              "--no-new-privs", "--inh-caps=+net_bind_service", "--ambient-caps=+net_bind_service",
                              "--bounding-set=-all,+net_bind_service", "--", "python3", "-I", "-c", INSPECT_PROCESS, pid],
                             check=False, capture_output=True, text=True, timeout=5)
                if result.returncode or len(result.stdout) > 65536:
                    if not proc.exists():
                        return None
                    raise InstallError("cannot inspect the owned service under its final identity")
                try:
                    checked = json.loads(result.stdout)
                except ValueError as error:
                    raise InstallError("service inspector returned invalid metadata; refusing continuation") from error
                if checked["pid"] != pid or checked["uids"] != uids or checked["gids"] != gids:
                    return None
                started, executable = checked["started"], Path(checked["executable"])
                arguments = [os.fsencode(value) for value in checked["arguments"]]
            expected = self.prefix / "releases" / state["current"] / "bin/httpjet"
            if executable != expected:
                try:
                    relative = executable.relative_to(self.prefix / "releases")
                except ValueError:
                    return None
                if len(relative.parts) == 3 and relative.parts[1:] == ("bin", "httpjet"):
                    raise InstallError("live owned PID belongs to a different release; reconcile it before switching binaries")
                return None
            if not uids or not gids:
                return None
            if b"--ready-file" not in arguments or str(self.ready).encode() not in arguments:
                return None
            return {"pid": pid, "started": started, "executable": str(executable)}
        except (OSError, ValueError, StopIteration, IndexError):
            return None

    def ready_identity(self, state, after=0):
        try:
            descriptor = os.open(self.ready, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(descriptor, "rb") as stream:
                info, body = os.fstat(stream.fileno()), stream.read(64)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != state["uid"] or info.st_nlink != 1 or info.st_mode & 0o077 or not re.fullmatch(rb"[1-9][0-9]*\n", body):
                return None
            identity = self.process(int(body), state)
            if not identity or identity["started"] < after:
                return None
            return identity
        except OSError:
            return None

    def running(self, state):
        if self.ready_identity(state):
            return True
        recorded = state.get("process")
        return bool(recorded and self.process(recorded["pid"], state) == recorded)

    def prepare(self, state, launch_tick=None):
        for name in ("/run/httpjet", "/var/lib/httpjet", "/var/log/httpjet"):
            directory = self.path(name)
            if directory.is_symlink():
                raise InstallError("service directory must not be a symlink")
            directory.mkdir(mode=0o750, parents=True, exist_ok=True)
            info = directory.stat()
            if info.st_uid not in (0, state["uid"]) or info.st_mode & 0o022:
                raise InstallError("unsafe service directory: " + str(directory))
            os.chown(directory, state["uid"], state["gid"])
            directory.chmod(0o750)
        if self.ready.exists() or self.ready.is_symlink():
            info = self.ready.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != state["uid"] or info.st_nlink != 1:
                raise InstallError("refusing an unowned readiness marker")
            body = self.ready.read_bytes()
            if not re.fullmatch(rb"[1-9][0-9]*\n", body) or self.path("/proc/" + body.decode().strip()).exists():
                raise InstallError("readiness marker is live or malformed; stop the recorded service first")
            self.ready.unlink()
        now_tick = int(float(self.path("/proc/uptime").read_text().split()[0]) * os.sysconf("SC_CLK_TCK"))
        state["launch_tick"] = now_tick if launch_tick is None else min(now_tick, launch_tick)
        self.save(state)

    def wait_ready(self, state, seconds=30):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            identity = self.ready_identity(state, max(0, state.get("launch_tick", 0) - 1))
            if identity:
                state["process"] = identity
                state["activated"] = True
                self.save(state)
                return
            time.sleep(0.2)
        raise InstallError("service did not publish a fresh exact-PID readiness marker; io_uring and final-account startup must work")

    def stop_exact(self, state):
        identity = self.ready_identity(state) or state.get("process")
        if not identity or self.process(identity["pid"], state) != identity:
            return
        descriptor = None
        if hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"):
            try:
                descriptor = os.pidfd_open(identity["pid"], 0)
            except ProcessLookupError:
                return
            except OSError as error:
                if error.errno not in (errno.ENOSYS, errno.EINVAL):
                    raise InstallError("pidfd process control denied; service was not signalled") from error
        def send(signum):
            if self.process(identity["pid"], state) != identity:
                return False
            try:
                if descriptor is not None:
                    signal.pidfd_send_signal(descriptor, signum)
                else:
                    os.kill(identity["pid"], signum)
            except ProcessLookupError:
                return False
            return True
        try:
            if not send(signal.SIGTERM):
                return
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if self.process(identity["pid"], state) != identity:
                    return
                time.sleep(0.2)
            if send(signal.SIGKILL):
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if self.process(identity["pid"], state) != identity:
                        return
                    time.sleep(0.1)
                raise InstallError("owned process did not exit; binary switch aborted")
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def direct_start(self, state):
        if self.running(state):
            return
        self.prepare(state)
        subprocess.Popen([str(self.prefix / "libexec/launch")], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
                         env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
        self.wait_ready(state)

    def start(self, state):
        # runsv can launch as soon as its link is enabled. Its run profile
        # records that PID's birth tick; a later controller prepare would
        # incorrectly make the same process stale before it publishes ready.
        if state["init"] != "runit":
            self.prepare(state)
        self.service("start", state)

    def profile(self, state):
        paths = {"systemd":"/usr/local/lib/systemd/system/httpjet.service", "openrc":"/etc/init.d/httpjet",
                 "runit":"/etc/sv/httpjet/run", "sysv":"/etc/rc.d/rc.httpjet" if state.get("sysv_style") == "slackware" else "/etc/init.d/httpjet"}
        return self.path(paths[state["init"]]) if state["init"] in paths else None

    def check_profile(self, state):
        profile = self.profile(state)
        if profile is None:
            return
        self.guard(profile.parent)
        info = profile.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise InstallError("service profile must remain root-owned and non-writable by other users")

    def wait_runit_supervisor(self, service, timeout=15):
        # runsvdir discovers a newly enabled link asynchronously. A stale
        # supervise/ok FIFO alone does not establish that runsv is listening.
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise InstallError("runit supervisor did not become ready; service start aborted")
            try:
                result = run(["sv", "status", service], check=False, capture_output=True,
                             timeout=min(1, remaining))
                if result.returncode == 0:
                    return
            except subprocess.TimeoutExpired:
                pass
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(0.1, remaining))

    def service(self, action, state):
        manager = state["init"]
        if action == "stop" and not self.running(state):
            self.stop_exact(state)
            return
        self.check_profile(state)
        if manager == "systemd":
            run(["systemctl", action, "httpjet.service"])
        elif manager == "openrc":
            run(["rc-service", "httpjet", action])
        elif manager == "runit":
            service = self.path("/etc/sv/httpjet")
            if action == "start":
                self.wait_runit_supervisor(service)
            run(["sv", "up" if action == "start" else "down", service])
        elif manager == "sysv":
            run([self.path("/etc/rc.d/rc.httpjet" if state.get("sysv_style") == "slackware" else "/etc/init.d/httpjet"), action])
        elif manager == "none":
            self.direct_start(state) if action == "start" else self.stop_exact(state)
        else:
            raise InstallError("unsupported init adapter")
        if action == "start" and manager != "none":
            self.wait_ready(self.load())
        if action == "stop":
            self.stop_exact(state)

    def enable(self, state, enabled):
        manager = state["init"]
        if manager == "systemd":
            run(["systemctl", "enable" if enabled else "disable", "httpjet.service"])
        elif manager == "openrc":
            run(["rc-update", "add" if enabled else "del", "httpjet", "default"])
        elif manager == "runit":
            service = self.path("/etc/sv/httpjet")
            down = service / "down"
            if enabled:
                down.unlink(missing_ok=True)
                directory = next((self.path(name) for name in ("/var/service", "/service", "/run/runit/service") if self.path(name).is_dir()), None)
                if not directory:
                    raise InstallError("runit active service directory is unavailable")
                link = directory / "httpjet"
                if not link.exists() and not link.is_symlink():
                    link.symlink_to(service)
                elif not link.is_symlink() or link.resolve() != service:
                    raise InstallError("runit service link is administrator-owned")
                state["runit_link"] = str(link.relative_to(self.root))
                self.save(state)
            else:
                down.touch(mode=0o644)
        elif manager == "sysv":
            if state.get("sysv_style") == "slackware":
                self.slackware_hooks(enabled)
            elif shutil.which("update-rc.d"):
                if enabled:
                    run(["update-rc.d", "httpjet", "defaults"])
                    run(["update-rc.d", "httpjet", "enable"])
                else:
                    run(["update-rc.d", "httpjet", "disable"])
            elif shutil.which("chkconfig"):
                run(["chkconfig", "--add", "httpjet"])
                run(["chkconfig", "httpjet", "on" if enabled else "off"])
            else:
                raise InstallError("SysV profile needs update-rc.d or chkconfig; use --init none")

    def slackware_hooks(self, enabled, check_only=False):
        hooks = (("rc.local", "start"), ("rc.local_shutdown", "stop"))
        changes = []
        for filename, action in hooks:
            path = self.path("/etc/rc.d/" + filename)
            self.guard(path.parent)
            if path.is_symlink():
                raise InstallError("Slackware hook must not be a symlink: " + str(path))
            exists = path.exists()
            if exists:
                info = path.stat()
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                    raise InstallError("unsafe Slackware hook: " + str(path))
                if enabled and not info.st_mode & 0o111:
                    raise InstallError("Slackware hook is intentionally non-executable; review it or use --init none: " + str(path))
                body, mode = path.read_bytes(), stat.S_IMODE(info.st_mode)
            else:
                body, mode = b"#!/bin/sh\n", 0o755
            begin = ("# BEGIN HTTPJET MANAGED " + action.upper()).encode()
            end = ("# END HTTPJET MANAGED " + action.upper()).encode()
            block = b"\n" + begin + b"\nif [ -x /etc/rc.d/rc.httpjet ]; then\n    /etc/rc.d/rc.httpjet " + action.encode() + b"\nfi\n" + end + b"\n"
            if body.count(begin) != body.count(end) or body.count(begin) > 1:
                raise InstallError("Slackware managed block was modified; review it explicitly")
            if begin in body and block not in body:
                raise InstallError("Slackware managed block was modified; preserved")
            updated = body.replace(block, b"")
            if enabled:
                updated += block
            if exists or enabled:
                changes.append((path, updated, mode))
        if not check_only:
            for path, body, mode in changes:
                self.replace_file(path, body, mode)

    def public_dir(self, path):
        if path.exists():
            self.guard(path)
            return
        self.public_dir(path.parent)
        path.mkdir(mode=0o755)
        path.chmod(0o755)

    def replace_file(self, target, data, mode):
        self.public_dir(target.parent)
        if target.is_symlink():
            raise InstallError("refusing managed-file symlink: " + str(target))
        descriptor, name = tempfile.mkstemp(prefix=".httpjet-", dir=target.parent)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                os.fchmod(stream.fileno(), mode)
                stream.flush(); os.fsync(stream.fileno())
            os.replace(name, target)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def pointer(self, version):
        self.public_dir(self.link.parent)
        temporary = self.link.parent / (".httpjet-link-" + str(os.getpid()))
        try:
            temporary.symlink_to(self.prefix / "releases" / version / "bin/httpjet")
            os.replace(temporary, self.link)
        finally:
            temporary.unlink(missing_ok=True)

    def deploy_helpers(self, payload, state, backups):
        source = payload / "share/httpjet/services"
        owned = state.setdefault("owned", {})
        paths = {"manage.py": (self.prefix / "libexec/manage.py", 0o755),
                 "launch": (self.prefix / "libexec/launch", 0o755),
                 "control": (self.prefix / "libexec/control", 0o755),
                 "httpjetctl": (self.path("/usr/local/sbin/httpjetctl"), 0o755)}
        adapter = {"systemd": ("systemd/httpjet.service", "/usr/local/lib/systemd/system/httpjet.service", 0o644),
                   "openrc": ("openrc/httpjet", "/etc/init.d/httpjet", 0o755),
                   "runit": ("runit/run", "/etc/sv/httpjet/run", 0o755),
                   "sysv": ("sysv/httpjet", "/etc/init.d/httpjet", 0o755)}.get(state["init"])
        if state["init"] == "sysv" and state.get("sysv_style") == "slackware":
            adapter = ("sysv/httpjet", "/etc/rc.d/rc.httpjet", 0o755)
        if adapter:
            paths[adapter[0]] = (self.path(adapter[1]), adapter[2])
        for relative, (target, mode) in paths.items():
            key = str(target.relative_to(self.root))
            if target.exists() or target.is_symlink():
                info = target.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                    raise InstallError("unsafe owned helper/profile permissions: " + str(target))
            if target.exists() and key in owned and digest(target) != owned[key]:
                if "libexec" in target.parts or target.name == "httpjetctl":
                    raise InstallError("administrator modified a privileged helper: " + str(target))
                continue  # preserve edited unit/profile files
            if target.exists() and key not in owned:
                raise InstallError("refusing an unowned service/helper file: " + str(target))
            backups[target] = target.read_bytes() if target.exists() else None
            self.replace_file(target, (source / relative).read_bytes(), mode)
            owned[key] = digest(target)
        identity = self.prefix / "libexec/identity.json"
        self.replace_file(identity, (json.dumps({"uid": state["uid"], "gid": state["gid"]}) + "\n").encode(), 0o644)
        state["owned"][str(identity.relative_to(self.root))] = digest(identity)
        if state["init"] == "systemd":
            run(["systemctl", "daemon-reload"])
        return backups

    def validate(self, binary, state):
        def demote():
            os.initgroups("httpjet", state["gid"])
            os.setgid(state["gid"])
            os.setuid(state["uid"])
        run([binary, "--root", self.path("/etc/httpjet"), "check", "--strict"], preexec_fn=demote, timeout=30)

    def initialize_defaults(self, payload, state):
        """Resume only initial seeding; existing administrator bytes always win."""
        configuration = self.path("/etc/httpjet/conf")
        self.public_dir(configuration)
        source = payload / "share/httpjet/conf"
        for item in sorted(source.rglob("*")):
            target = configuration / item.relative_to(source)
            if item.is_dir():
                self.public_dir(target)
            elif not target.exists() and not target.is_symlink():
                self.replace_file(target, item.read_bytes(), 0o644)
        content = self.path("/var/www/httpjet")
        self.public_dir(content)
        page = content / "index.html"
        if not page.exists() and not page.is_symlink():
            self.replace_file(page, (payload / "share/httpjet/welcome/index.html").read_bytes(), 0o644)
        run([payload / "share/httpjet/services/setup-tls", str(self.root).rstrip("/"), str(state["gid"])])
        state["initialized"] = True
        self.save(state)

    def install(self, payload, release_id, architecture, init, base, key, fingerprint):
        version_tuple(release_id)
        previous = self.load()
        self.no_takeover(previous)
        if previous and previous["init"] != init:
            raise InstallError("init method is owned by existing installation; migrate it explicitly")
        first_setup = previous is None or not previous.get("initialized", bool(previous.get("current")))
        sysv_style = previous.get("sysv_style") if previous else None
        if init == "sysv" and not sysv_style:
            sysv_style = "slackware" if self.path("/etc/rc.d/rc.M").is_file() else "lsb"
        if first_setup and sysv_style == "slackware":
            self.slackware_hooks(True, check_only=True)
        uid, gid = self.account(previous)
        if previous and previous.get("current") == release_id and (init == "none" or previous.get("activated", True)):
            existing = self.prefix / "releases" / release_id
            recorded = previous["versions"].get(release_id)
            actual = {str(p.relative_to(existing)): digest(p) for p in existing.rglob("*") if p.is_file() and not p.is_symlink()}
            incoming = {str(p.relative_to(payload)): digest(p) for p in payload.rglob("*") if p.is_file() and not p.is_symlink()}
            if not recorded or actual != recorded or incoming != recorded or any(p.is_symlink() for p in existing.rglob("*")):
                raise InstallError("immutable release id has different or modified bytes; use a new packaging revision")
            if all((self.root / name).exists() for name in previous.get("owned", {}) if name.startswith("opt/httpjet/libexec/") or name == "usr/local/sbin/httpjetctl"):
                print("httpjet: installed release and service state retained")
                return
        was_running = bool(previous and self.running(previous))
        state = json.loads(json.dumps(previous)) if previous else {"schema": 2, "method": "binary", "current": None, "previous": None, "versions": {}, "owned": {}}
        state.setdefault("initialized", not first_setup)
        state.setdefault("activated", bool(previous and previous.get("current")))
        first_activation = not state["activated"] and init != "none"
        state.update(uid=uid, gid=gid, init=init, architecture=architecture, base=base, fingerprint=fingerprint)
        if sysv_style:
            state["sysv_style"] = sysv_style
        self.save(state)  # ownership of the newly created dedicated account
        self.public_dir(self.prefix / "releases")
        destination = self.prefix / "releases" / release_id
        if destination.exists():
            record = state["versions"].get(release_id)
            if not record or any(not (destination / name).is_file() or digest(destination / name) != value for name, value in record.items()):
                raise InstallError("existing version directory is not installer-owned and intact")
        else:
            staging = Path(tempfile.mkdtemp(prefix=".incoming-", dir=destination.parent))
            try:
                shutil.copytree(payload, staging / "payload")
                os.replace(staging / "payload", destination)
            finally:
                shutil.rmtree(staging)
            state["versions"][release_id] = {str(path.relative_to(destination)): digest(path) for path in destination.rglob("*") if path.is_file()}
        self.save(state)
        if not state["initialized"]:
            self.initialize_defaults(destination, state)
        self.validate(destination / "bin/httpjet", state)
        if was_running:
            self.service("stop", previous)
        backups = {}
        try:
            self.deploy_helpers(destination, state, backups)
            self.pointer(release_id)
            state.update(previous=previous.get("current") if previous else None, current=release_id)
            if key.resolve() != (self.state_dir / "archive.asc").resolve():
                shutil.copyfile(key, self.state_dir / "archive.asc")
            (self.state_dir / "archive.asc").chmod(0o600)
            self.save(state)
            if first_activation:
                self.enable(state, True)
            if was_running or first_activation:
                self.start(state)
                if first_activation:
                    import http.client
                    connection = http.client.HTTPConnection("127.0.0.1", 80, timeout=3)
                    try:
                        connection.request("GET", "/")
                        response = connection.getresponse()
                        if response.status != 200 or response.read() != (destination / "share/httpjet/welcome/index.html").read_bytes():
                            raise InstallError("fresh service did not return the exact welcome page")
                    finally:
                        connection.close()
                    if self.path("/etc/httpjet/listeners.env").exists():
                        import ssl
                        connection = http.client.HTTPSConnection("127.0.0.1", 443, timeout=3,
                                                                context=ssl._create_unverified_context())
                        try:
                            connection.request("GET", "/")
                            response = connection.getresponse()
                            if response.status != 200 or response.read() != (destination / "share/httpjet/welcome/index.html").read_bytes():
                                raise InstallError("fresh HTTPS service did not return the exact welcome page")
                        finally:
                            connection.close()
                        print("httpjet: http://SERVER-IP/ and https://SERVER-IP/ are ready. HTTPS uses a self-signed certificate; configure a trusted certificate to remove browser warnings.")
        except Exception:
            try:
                self.service("stop", state)
            except Exception:
                pass
            if first_activation:
                try:
                    self.enable(state, False)
                except Exception:
                    pass
            for target, body in backups.items():
                if body is None:
                    target.unlink(missing_ok=True)
                else:
                    self.replace_file(target, body, 0o644 if target.suffix == ".service" else 0o755)
            if previous and previous.get("current"):
                self.pointer(previous["current"])
                previous["versions"] = state["versions"]
                self.save(previous)
                if was_running:
                    self.start(previous)
            else:
                self.link.unlink(missing_ok=True)
                state["current"] = None
                state["activated"] = False
                self.save(state)
            raise
        print("httpjet: installed " + release_id + " using " + init)
        if init == "none":
            print("httpjet: start in the foreground with sudo httpjetctl run")

    def uninstall(self, state):
        self.no_takeover(state)
        self.service("stop", state)
        self.enable(state, False)
        if state["init"] == "runit" and state.get("runit_link"):
            link = self.root / state["runit_link"]
            if link.is_symlink() and link.resolve() == self.path("/etc/sv/httpjet"):
                link.unlink()
        if self.link.is_symlink() and state.get("current") and self.link.resolve() == self.prefix / "releases" / state["current"] / "bin/httpjet":
            self.link.unlink()
        for name, expected in state.get("owned", {}).items():
            target = self.root / name
            if target.is_file() and not target.is_symlink() and digest(target) == expected:
                target.unlink()
            elif target.exists():
                print("httpjet: preserved modified program/profile " + str(target))
        for release_id, record in state.get("versions", {}).items():
            directory = self.prefix / "releases" / release_id
            actual = {str(p.relative_to(directory)): digest(p) for p in directory.rglob("*") if p.is_file() and not p.is_symlink()}
            if actual == record and not any(p.is_symlink() for p in directory.rglob("*")):
                shutil.rmtree(directory)
            elif directory.exists():
                print("httpjet: preserved modified release " + str(directory))
        state["current"] = None
        self.save(state)
        print("httpjet: programs removed; configuration, website, logs, account and ownership record retained")

def launch():
    """Only the brief launcher is privileged; exec the web daemon after UID drop."""
    identity_file = Path("/opt/httpjet/libexec/identity.json")
    info = identity_file.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1:
        raise InstallError("unsafe public service identity file")
    identity = json.loads(identity_file.read_text())
    uid, gid = identity["uid"], identity["gid"]
    if not isinstance(uid, int) or uid <= 0 or not isinstance(gid, int) or gid <= 0:
        raise InstallError("service identity must be non-root")
    ready = Path("/run/httpjet/ready")
    if ready.exists() or ready.is_symlink():
        old = ready.lstat()
        if not stat.S_ISREG(old.st_mode) or old.st_uid != uid or old.st_nlink != 1:
            raise InstallError("unowned readiness marker")
        body = ready.read_bytes()
        if not re.fullmatch(rb"[1-9][0-9]*\n", body) or Path("/proc/" + body.decode().strip()).exists():
            raise InstallError("readiness marker is live or malformed")
        ready.unlink()
    https = ""
    settings = Path("/etc/httpjet/listeners.env")
    if settings.exists():
        for line in settings.read_text().splitlines():
            if line.startswith("HTTPJET_HTTPS_ADDR="):
                https = line.partition("=")[2].strip()
    arguments = ["/usr/local/bin/httpjet", "--root", "/etc/httpjet", "serve", "--http-addr", "0.0.0.0:80",
                 "--https-addr=" + https, "--metrics-addr=", "--no-php", "--no-multishot-accept", "--ready-file", str(ready)]
    # This redirection is evaluated only after the identity/capability drop.
    arguments = ["/bin/sh", "-c", 'exec "$@" >> /var/log/httpjet/service.log 2>&1', "httpjet-log", *arguments]
    environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HTTPJET_LOG_DIR": "/var/log/httpjet", "RUST_LOG": "httpjet=info"}
    if os.environ.get("NOTIFY_SOCKET"):
        environment["NOTIFY_SOCKET"] = os.environ["NOTIFY_SOCKET"]
    os.umask(0o027)
    if os.geteuid() == 0:
        tool = shutil.which("setpriv", path=environment["PATH"])
        if not tool:
            raise InstallError("util-linux setpriv with ambient capability support is required")
        arguments = [tool, "--reuid", str(uid), "--regid", str(gid), "--init-groups", "--no-new-privs",
                     "--inh-caps=+net_bind_service", "--ambient-caps=+net_bind_service", "--bounding-set=-all,+net_bind_service", "--", *arguments]
    elif os.geteuid() != uid or os.getegid() != gid:
        raise InstallError("launcher must run as root or the recorded service account")
    os.execve(arguments[0], arguments, environment)

def require_cap_launcher():
    tool = shutil.which("setpriv")
    if not tool:
        raise InstallError("install util-linux setpriv with ambient capabilities; BusyBox-only setpriv is insufficient")
    result = run([tool, "--help"], check=False, capture_output=True, text=True)
    for capability in ("--ambient-caps", "--inh-caps", "--bounding-set", "--reuid", "--init-groups"):
        if capability not in result.stdout + result.stderr:
            raise InstallError("setpriv lacks required " + capability + "; install util-linux setpriv")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    bootstrap = commands.add_parser("bootstrap")
    bootstrap.add_argument("--base", required=True)
    bootstrap.add_argument("--key", required=True, type=Path)
    bootstrap.add_argument("--fingerprint", required=True)
    bootstrap.add_argument("--version")
    bootstrap.add_argument("--init", required=True, choices=("systemd", "openrc", "runit", "sysv", "none"))
    for name in ("update", "rollback"):
        command = commands.add_parser(name)
        command.add_argument("--version")
    for name in ("start", "stop", "restart", "status", "enable", "disable", "uninstall", "run", "prepare", "prepare-runit", "wait", "direct-start", "direct-stop", "launch"):
        commands.add_parser(name)
    args = parser.parse_args()
    if args.command == "launch":
        launch()
        return
    if os.geteuid() != 0:
        raise InstallError("installation/service control requires root")
    manager = Manager()
    lock = manager.lock() if args.command in ("bootstrap", "update", "rollback", "uninstall") else None
    try:
        state = manager.load()
        if args.command in ("bootstrap", "update"):
            require_cap_launcher()
            manager.no_takeover(state)
            base = args.base if args.command == "bootstrap" else state["base"]
            key = args.key if args.command == "bootstrap" else manager.state_dir / "archive.asc"
            fingerprint = args.fingerprint if args.command == "bootstrap" else state["fingerprint"]
            architecture = ARCHES.get(os.uname().machine)
            selected_init = args.init if args.command == "bootstrap" else state["init"]
            with tempfile.TemporaryDirectory(prefix="httpjet-download-") as temporary:
                payload, release_id, _ = fetch_release(base, args.version, architecture, key, fingerprint,
                                                       Path(temporary), state.get("current") if state else None)
                manager.install(payload, release_id, architecture, selected_init, base, key, fingerprint)
        elif not state:
            raise InstallError("no generic installation is recorded")
        elif args.command == "rollback":
            selected = args.version or state.get("previous")
            if not selected or selected not in state["versions"]:
                raise InstallError("requested rollback release is not retained locally")
            manager.install(manager.prefix / "releases" / selected, selected, state["architecture"], state["init"],
                            state["base"], manager.state_dir / "archive.asc", state["fingerprint"])
        elif args.command == "uninstall":
            manager.uninstall(state)
        elif args.command == "prepare":
            manager.prepare(state)
        elif args.command == "prepare-runit":
            text = Path("/proc/" + str(os.getppid()) + "/stat").read_text()
            manager.prepare(state, int(text[text.rfind(")") + 2:].split()[19]))
        elif args.command == "wait":
            manager.wait_ready(state)
        elif args.command == "status":
            print("httpjet: " + ("running" if manager.running(state) else "stopped"))
            return 0 if manager.running(state) else 3
        elif args.command in ("enable", "disable"):
            manager.enable(state, args.command == "enable")
        elif args.command in ("direct-stop", "stop"):
            manager.stop_exact(state) if args.command == "direct-stop" else manager.service("stop", state)
        elif args.command == "direct-start":
            manager.direct_start(state)
        elif args.command == "run":
            if manager.running(state):
                raise InstallError("service is already running")
            manager.prepare(state)
            launch()
        else:
            if args.command == "restart":
                manager.service("stop", state)
            manager.start(state)
        return 0
    finally:
        if lock is not None:
            os.close(lock)

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (InstallError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        raise SystemExit("httpjet: " + str(error))
