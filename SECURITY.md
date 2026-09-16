# Security

Use GitHub's private vulnerability reporting from this repository's
**Security** tab. Do not disclose suspected vulnerabilities in public issues.

Include the affected revision, reproduction, and impact. Test only systems you
own or have permission to test. Security fixes target the latest `main`; there
is no paid bounty or LTS branch.

## Production trust boundary

The production web tier and lsphp workers intentionally run as the same
`nobody:nobody` principal. PHP must retain exactly its existing access to the
LSAPI socket, site files, cache, logs, configuration, certificates, keys, and
tokens; separating those permissions would break the supported deployment
model.

Consequently, code executing as a production PHP worker is inside httpjet's
trusted origin boundary. A compromised PHP worker is treated as a full origin
compromise, including the ability to read origin credentials and to modify
cache or log data writable by that principal. Cache-container integrity tags
can detect accidental corruption or writes by a principal that lacks their
key, but are not a security boundary against code running as `nobody`.

Reports whose only prerequisite and impact are the documented access of the
shared PHP/httpjet principal should identify that assumption explicitly. We
still welcome reports that cross this boundary without first obtaining code
execution as that principal, or that materially increase access beyond it.
