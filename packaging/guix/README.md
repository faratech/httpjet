# Guix System integration

Use the native package and Shepherd service; the imperative FHS bootstrap refuses
Guix System before writing installation state. io_uring remains mandatory, with
single-shot accept by default and no global kernel-policy changes.

`channels.scm` pins the authenticated Guix channel and introduction. Add
`packaging/guix` to the Guile module load path so `(httpjet packages)` and
`(httpjet services)` resolve. The supported package systems are x86_64-linux and
aarch64-linux. Full Guix System lifecycle qualification remains required.

## Generate a lock from an authenticated manifest

First verify a specific published schema-2 manifest and `.asc` signature using
the approved archive public key and independently checked full fingerprint.
Save it as `manifest.json`. The following creates `httpjet-release.scm` directly
from those authenticated hashes; it does not choose latest or trust an unsigned
network response. Set the system explicitly to the target architecture:

```sh
HTTPJET_GUIX_TARGET=x86_64-linux python3 - <<'LOCK' > httpjet-release.scm
import json, os
m = json.load(open('manifest.json'))
system = os.environ['HTTPJET_GUIX_TARGET']
arch = {'x86_64-linux': 'amd64', 'aarch64-linux': 'arm64'}[system]
binary = m['binaries'][arch]
artifact = m['artifacts'][binary['artifact']]
assert m['schema'] == 2 and binary['libc'] == artifact['libc'] == 'musl'
assert artifact['architecture'] == arch
values = {'release-id': m['release_id'],
          'uri': 'https://httpjet-packages.pages.dev/releases/' + m['release_id'] + '/' + binary['artifact'],
          'sha256': artifact['sha256'], 'binary-sha256': binary['binary_sha256'],
          'system': system}
print('(use-modules (httpjet packages))')
print('(httpjet-binary-package')
for name, value in values.items():
    print('  #:' + name + ' ' + json.dumps(value))
print(')')
LOCK

guix time-machine -C packaging/guix/channels.scm --   build -L packaging/guix -f httpjet-release.scm
```

The package has a fixed origin hash and copies the static ELF without rebuilding
or changing its bytes. The binary hash is retained in the lock for qualification;
the archive hash authenticates the fetched payload as a whole.

Place the authenticated lock at the path used below (from the repository root):

```sh
sudo install -D -m0644 httpjet-release.scm /etc/guix/httpjet-release.scm
```

## Add to your operating-system declaration

Import the modules and load that lock from your configuration. Add the service
to your existing services list, retaining your actual machine's bootloader,
filesystems, accounts and other services:

```scheme
(use-modules (gnu) (httpjet packages) (httpjet services))
(define httpjet-release (load "/etc/guix/httpjet-release.scm"))

;; One entry in the existing operating-system's services list:
(service httpjet-service-type
         (httpjet-configuration
          (package httpjet-release)))
```

```sh
sudo guix time-machine -C packaging/guix/channels.scm --   system reconfigure -L packaging/guix /etc/config.scm
sudo herd status httpjet
curl --fail http://127.0.0.1/
```

The service declares the dedicated account, XML configuration, writable
state/log/runtime directories, launch-specific readiness file and narrow
CAP_NET_BIND_SERVICE privileged program. The daemon runs as the service account.
The default serves HTTP port 80, with TLS, PHP, page cache and management listeners
disabled. Existing website content is preserved; the default welcome page is
seeded only once when no document root exists.

Configuration fields are `package`, `config-root`, `http-address`,
`https-address`, `extra-arguments`, `extra-groups`, and `no-multishot-accept?`.
Extra groups must correspond to your deliberately configured host policy. Custom
XML configuration belongs in your Guix System declaration, not an imperative edit
to a store-backed link. A custom config-root requires you to supply that tree.

## Native generations

Authenticate a new manifest and regenerate the package lock, then reconfigure.
Use Guix System generations for rollback (`guix system roll-back`); remove the
service from your declaration and reconfigure for removal. Content/logs live
outside the store. httpjetctl does not manage declarative generations.

`qualification.scm` is a disposable-image harness, not a replacement for your
host configuration. It consumes explicit release/SSH/test-CA environment inputs
and labels initial same-ELF fixtures. Guix parse definitions alone do not establish
package evaluation, boot, Shepherd capabilities, generation lifecycle or ARM64
runtime. Those must pass the required release matrix before this route is called
qualified.
