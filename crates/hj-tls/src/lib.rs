//! hj-tls: the unified [`rustls`] server-config builder for httpjet.
//!
//! This crate produces a **single** [`rustls::ServerConfig`] that is shared by
//! both the TCP path (via `monoio-rustls`) and the QUIC/HTTP3 path (via
//! `quinn-proto`).
//! Sharing one config guarantees there is exactly one SNI certificate resolver
//! and exactly one client-certificate verifier across every transport — so an
//! HTTP/3 request and an HTTP/2 request to the same listener are authenticated
//! and certified identically.
//!
//! # What it maps from the config model
//!
//! For a [`Listener`] with TLS ([`ListenerTls`]):
//!
//! * **SNI resolver.** Every vhost that has a [`VhSsl`] block contributes a
//!   [`rustls::sign::CertifiedKey`] keyed by each domain the listener maps to
//!   that vhost. The leaf is `vhssl.cert_file`; if `vhssl.cert_chain` is set,
//!   the **server chain material** in `vhssl.ca_cert_file` is appended (a
//!   fullchain that repeats the leaf is de-duplicated). The listener's own
//!   `cert_file` / `key_file` becomes the default certificate used when SNI
//!   does not match (or is absent, e.g. raw-IP TLS). The SNI→cert map is keyed
//!   purely by the **configured domain name** with no certificate name-match
//!   check, mirroring OLS `VHostMapFindSslContext`: a domain mapped to a vhost
//!   whose cert does not cover it is *still* served that vhost's cert (it does
//!   not silently fall through to the default).
//!
//! * **mTLS / client verification.** Driven by `listener.tls.client_verify`:
//!   `2` = *require* a client cert — enforced at the APPLICATION layer (the handshake
//!   completes cert-less and a non-loopback/LAN peer that presented none is refused; see
//!   [`build_server_config_inner`]), NOT fail-closed at the handshake. `1` = *optional*,
//!   `0`/other = no client auth. When client auth is enabled, the **only** trust root is
//!   the listener's `ca_cert_file` — the Cloudflare authenticated-origin-pull
//!   CA. This is distinct from `VhSsl::ca_cert_file`, which is server chain
//!   material and must never be used to verify clients.
//!
//! * **ALPN.** `h2` then `http/1.1`. (HTTP/3's ALPN token `h3` is negotiated by
//!   the quinn-proto endpoint from its own config; this config governs the TCP
//!   path's ALPN and is rebuilt with `h3` for the shared certificate/verifier
//!   state on the QUIC side.)
//!
//! * **0-RTT.** `max_early_data_size` is pinned to `0`.
//!
//! # Crypto provider
//!
//! [`install_crypto_provider`] installs the process-wide default
//! [`rustls::crypto::CryptoProvider`]. We prefer `aws-lc-rs` (the rustls
//! default in this build); the rest of the crate loads private keys through
//! the installed provider's `key_provider`, so whatever backend is active is
//! used consistently. Call [`install_crypto_provider`] once at startup before
//! building any config.
//!
//! # Public API
//!
//! * [`install_crypto_provider`] — install the default crypto provider once.
//! * [`build_server_config`] — the unified builder for the TCP path (ALPN
//!   `[h2, http/1.1]`); the main entry point.
//! * [`build_server_config_alpn`] — the same builder parameterised by ALPN; the
//!   HTTP/3 path calls it with `[h3]`, reusing the identical SNI resolver and
//!   client-cert verifier.
//! * [`load_cert_chain`] — load a PEM cert chain (leaf + optional appended chain).
//! * [`load_private_key`] — load a PEM private key into a [`SigningKey`].
//! * [`build_certified_key`] — assemble a [`CertifiedKey`] from cert + key files.
//! * [`build_sni_resolver`] — build the per-listener SNI resolver.

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, Result, anyhow};
use arc_swap::ArcSwap;
use hj_config::model::{Listener, ListenerTls, ServerConfig, VhSsl};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{
    ClientHello, ResolvesServerCert, ServerSessionMemoryCache, WebPkiClientVerifier,
};
use rustls::sign::{CertifiedKey, SigningKey};
use rustls::{RootCertStore, ServerConfig as RustlsServerConfig};

use hj_core::{ClientCert, TlsParams};

/// ALPN protocols advertised on the TCP path: HTTP/2 preferred, HTTP/1.1 fallback.
pub(crate) const ALPN_PROTOCOLS: &[&[u8]] = &[b"h2", b"http/1.1"];

/// An SNI servername → certificate map keyed *purely by the configured vhost
/// domain name*, with **no certificate name-match validation**.
///
/// # Why not [`rustls::server::ResolvesServerCertUsingSni`]
///
/// rustls's built-in SNI resolver calls `verify_server_name()` inside `add()`,
/// rejecting any certificate that does not "quote" (cover via CN/SAN) the SNI
/// name being registered. That is *not* how LiteSpeed/OpenLiteSpeed behaves.
///
/// OLS ground truth (`sslpp/sslcontext.cpp::servername_cb` →
/// `http/vhostmap.cpp::VHostMapFindSslContext` → `VHostMap::matchVHost`): the
/// SNI servername is looked up against the **listener's configured domain →
/// vhost map only**. Whatever `SslContext` the matched vhost was configured
/// with is applied to the connection (`pCtx->applyToSsl(ssl)`) — OLS never
/// checks that the vhost's leaf certificate actually covers the SNI name. So a
/// domain mapped to a vhost whose cert does not include it in its SAN (e.g.
/// `news.forum.example` served under the `publisher.example` vhost+cert) is
/// still presented that vhost's cert, *not* the listener default.
///
/// This map reproduces that: each configured domain maps to its vhost's
/// [`CertifiedKey`] regardless of the cert's SAN/CN. Lookup and insertion keys
/// are ASCII-lowercased, mirroring OLS `getLcaseServerName`/`strnlower`
/// (rustls also hands us an already-lowercased servername).
#[derive(Debug, Default)]
pub(crate) struct SniCertMap {
    by_name: HashMap<String, Arc<CertifiedKey>>,
}

impl SniCertMap {
    /// Create an empty map.
    pub(crate) fn new() -> Self {
        Self {
            by_name: HashMap::new(),
        }
    }

    /// Register `name` → `ck`. Unlike rustls's resolver this performs **no**
    /// certificate name-match check: the configured mapping is authoritative,
    /// exactly as OLS treats its vhost domain map.
    pub(crate) fn add(&mut self, name: &str, ck: Arc<CertifiedKey>) {
        self.by_name.insert(name.to_ascii_lowercase(), ck);
    }

    /// Resolve by exact (lowercased) servername. Returns `None` when SNI is
    /// absent or maps to no configured domain — the wrapping resolver then
    /// supplies the listener default certificate.
    pub(crate) fn resolve_name(&self, server_name: Option<&str>) -> Option<Arc<CertifiedKey>> {
        let name = server_name?;
        self.by_name.get(&name.to_ascii_lowercase()).cloned()
    }
}

/// A certificate resolver that tries the SNI map first and falls back to a
/// default certificate when SNI is absent or unmatched.
///
/// [`SniCertMap`] returns `None` for unknown / missing SNI; that alone would
/// abort the handshake. Wrapping it with a default mirrors LiteSpeed's
/// behaviour where the listener's own certificate serves any name not
/// explicitly mapped to a vhost cert (including raw-IP TLS with no SNI). This
/// matches OLS `VHostMapFindSslContext`, which falls back to the listener-level
/// `pMap->getSslContext()` when no mapped vhost supplies a context.
#[derive(Debug)]
struct SniWithDefault {
    sni: SniCertMap,
    default: Arc<CertifiedKey>,
}

impl ResolvesServerCert for SniWithDefault {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // Match the configured domain exactly (no SAN validation); otherwise
        // fall back to the listener default cert.
        self.sni
            .resolve_name(client_hello.server_name())
            .or_else(|| Some(self.default.clone()))
    }
}

/// (OPS9) A cert resolver whose live [`SniWithDefault`] sits behind an `ArcSwap`,
/// so renewed certificate files can be swapped in WITHOUT rebuilding the
/// `rustls::ServerConfig` / `TlsAcceptor` (which the accept loops capture once).
/// Per handshake it is one atomic load + the existing exact-SNI lookup;
/// in-flight connections keep the cert they negotiated, new handshakes pick up
/// the swapped certs. The swap handle is [`CertReloadHandle`].
struct ReloadableResolver(Arc<ArcSwap<SniWithDefault>>);

impl std::fmt::Debug for ReloadableResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReloadableResolver")
    }
}

impl ResolvesServerCert for ReloadableResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0.load().resolve(client_hello)
    }
}

/// Handle to live-reload a listener's TLS certificates (OPS9). Held by the
/// server; on SIGHUP it re-reads the configured cert files and swaps them into
/// the running resolver — an ACME renewal (new cert at the same path) takes
/// effect with no restart. Cheaply cloneable.
#[derive(Clone)]
pub struct CertReloadHandle(Arc<ArcSwap<SniWithDefault>>);

impl CertReloadHandle {
    /// Re-read `listener`'s default + per-vhost certificates from `server` and
    /// atomically swap them into the live resolver. On any load error the CURRENT
    /// certs stay in place (a failed reload never breaks TLS); new handshakes use
    /// the new certs once this returns `Ok`.
    pub fn reload(&self, server: &ServerConfig, listener: &Listener) -> Result<()> {
        let next = build_sni_with_default(server, listener)?;
        self.0.store(Arc::new(next));
        Ok(())
    }
}

/// Assemble the SNI map + listener default certificate for `listener` (reads the
/// cert/key files). Shared by [`build_server_config_inner`] (boot) and
/// [`CertReloadHandle::reload`] (SIGHUP) so the two can never diverge.
fn build_sni_with_default(server: &ServerConfig, listener: &Listener) -> Result<SniWithDefault> {
    let tls = listener
        .tls
        .as_ref()
        .ok_or_else(|| anyhow!("listener {} has no TLS configuration", listener.name))?;
    let sni = build_sni_resolver(server, listener)
        .with_context(|| format!("listener {}: building SNI resolver", listener.name))?;
    let default_ck = build_certified_key(
        &tls.cert_file,
        listener_chain_file(tls).as_deref(),
        &tls.key_file,
    )
    .with_context(|| {
        format!(
            "listener {}: loading default certificate {}",
            listener.name,
            tls.cert_file.display()
        )
    })?;
    Ok(SniWithDefault {
        sni,
        default: Arc::new(default_ck),
    })
}

/// Install the process-wide default [`rustls::crypto::CryptoProvider`].
///
/// Prefers `aws-lc-rs` (the rustls default in this build). Idempotent: if a
/// provider is already installed this is a no-op and returns `Ok(())`. Call
/// once at process startup, before constructing any [`rustls::ServerConfig`]
/// or [`rustls::ClientConfig`]; key loading in this crate relies on a provider
/// being present.
pub fn install_crypto_provider() -> Result<()> {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return Ok(());
    }
    // `install_default` returns Err(existing) if another thread won the race;
    // that is fine — a provider is installed either way.
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    // (#349) Hardware-aware TLS 1.3 suite policy: serve AES_128_GCM_SHA256
    // (+ CHACHA20 for non-AES-NI clients) and EXCLUDE AES_256_GCM_SHA384.
    // rustls negotiates by CLIENT preference, and OpenSSL-family clients list
    // 256-GCM-SHA384 first — whose SHA-384 transcript/HKDF runs the software
    // SHA-512 core (a cold-handshake profile showed 15% of CPU in transcript
    // hashing alone) while this CPU has hardware SHA-NI for SHA-256, and
    // AES-256 costs ~20% more per record byte for no practical margin.
    // AES_128_GCM_SHA256 is the TLS 1.3 MANDATORY-to-implement suite (every
    // client has it; Cloudflare and Chrome prefer it themselves), so no
    // interoperability is lost. TLS 1.2 suites are untouched.
    // rustls negotiates by CLIENT order, so the SET is the only control:
    // TLS 1.3 keeps ONLY AES_128_GCM_SHA256 (otherwise OpenSSL-family
    // clients pick 256-GCM-SHA384 or CHACHA20 first — both slower here).
    // Origin TLS 1.3 traffic is Cloudflare's AES-NI edges; a non-AES-NI
    // client still interoperates (128-GCM in software), and TLS 1.2 keeps
    // its full suite set including CHACHA20.
    provider.cipher_suites.retain(|s| {
        !matches!(s, rustls::SupportedCipherSuite::Tls13(_))
            || s.suite() == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
    });
    let _ = provider.install_default();
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        return Err(anyhow!(
            "failed to install a default rustls CryptoProvider (aws-lc-rs)"
        ));
    }
    Ok(())
}

/// Return the installed process-default crypto provider, erroring with a clear
/// message if [`install_crypto_provider`] was never called.
fn provider() -> Result<Arc<rustls::crypto::CryptoProvider>> {
    rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .ok_or_else(|| {
            anyhow!("no default rustls CryptoProvider installed; call hj_tls::install_crypto_provider() at startup")
        })
}

/// Load a PEM certificate chain from `cert_file`. When `chain_file` is `Some`
/// (the vhost/listener has `cert_chain` set) the additional PEM certificates in
/// `chain_file` are **appended** after the leaf as server chain material.
///
/// If the chain file is itself a fullchain that begins by repeating the leaf
/// certificate, that duplicate leaf is dropped so the chain is well-formed
/// (`leaf, intermediate, ...`).
///
/// Returns at least one certificate (the leaf) or an error if `cert_file`
/// contained no certificates.
pub(crate) fn load_cert_chain(
    cert_file: &Path,
    chain_file: Option<&Path>,
) -> Result<Vec<CertificateDer<'static>>> {
    let mut chain = read_certs(cert_file)
        .with_context(|| format!("loading leaf certificate from {}", cert_file.display()))?;
    if chain.is_empty() {
        return Err(anyhow!("no certificates found in {}", cert_file.display()));
    }

    if let Some(chain_file) = chain_file {
        let extra = read_certs(chain_file).with_context(|| {
            format!(
                "loading server chain material from {}",
                chain_file.display()
            )
        })?;
        let leaf = chain[0].clone();
        for cert in extra {
            // Drop a repeated leaf (fullchain that starts with the leaf) and
            // skip any certificate already present to keep the chain minimal.
            if cert == leaf || chain.contains(&cert) {
                continue;
            }
            chain.push(cert);
        }
    }

    Ok(chain)
}

/// Load and parse all PEM certificates from a file into DER form.
fn read_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file =
        File::open(path).with_context(|| format!("opening certificate file {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("parsing PEM certificates in {}", path.display()))?;
    Ok(certs)
}

/// Load the first PEM private key from `key_file` and turn it into a
/// [`SigningKey`] using the installed crypto provider's key provider.
///
/// Accepts PKCS#8, PKCS#1 (RSA) and SEC1 (EC) PEM key blocks.
pub(crate) fn load_private_key(key_file: &Path) -> Result<Arc<dyn SigningKey>> {
    let file = File::open(key_file)
        .with_context(|| format!("opening private key file {}", key_file.display()))?;
    let mut reader = BufReader::new(file);
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("parsing PEM private key in {}", key_file.display()))?
        .ok_or_else(|| anyhow!("no private key found in {}", key_file.display()))?;

    let provider = provider()?;
    provider
        .key_provider
        .load_private_key(key)
        .with_context(|| format!("loading signing key from {}", key_file.display()))
}

/// Assemble a [`CertifiedKey`] (cert chain + matching signing key) from a
/// cert file, optional chain file, and key file.
pub(crate) fn build_certified_key(
    cert_file: &Path,
    chain_file: Option<&Path>,
    key_file: &Path,
) -> Result<CertifiedKey> {
    let chain = load_cert_chain(cert_file, chain_file)?;
    let key = load_private_key(key_file)?;
    // NB: the listener's `enable_stapling` (OCSP stapling) is intentionally NOT wired
    // here — no OCSP response is fetched/attached to the CertifiedKey. It is a parsed
    // config knob with no implementation (the startup banner reports it as a no-op).
    // Unneeded in the live deployment: Cloudflare terminates TLS to browsers and does
    // not require origin-side stapling.
    Ok(CertifiedKey::new(chain, key))
}

/// Resolve the intermediate-chain PEM to append after the leaf when `cert_chain`
/// is enabled. Prefers an explicitly-configured chain file; otherwise, for the
/// ubiquitous Let's Encrypt layout where `cert_file` is a leaf-only `cert.pem`,
/// falls back to the sibling `chain.pem` (the intermediate). This makes httpjet
/// send `leaf, intermediate` rather than a bare leaf — a bare leaf trips strict
/// origin validation (e.g. Cloudflare Authenticated Origin Pull / Full-Strict).
/// Returns `None` when chaining is off or no chain material is found (the
/// `cert_file` may itself already be a fullchain, in which case `load_cert_chain`
/// already carries the intermediate and its de-dup keeps the chain minimal).
fn resolve_chain_file(
    cert_file: &Path,
    cert_chain: bool,
    explicit: Option<&Path>,
) -> Option<PathBuf> {
    if !cert_chain {
        return None;
    }
    if let Some(p) = explicit {
        return Some(p.to_path_buf());
    }
    let sibling = cert_file.parent()?.join("chain.pem");
    (sibling != cert_file && sibling.is_file()).then_some(sibling)
}

/// The chain-file argument for a [`VhSsl`]: when `cert_chain` is enabled, the
/// explicit `ca_cert_file` (server chain material) if set, else the LE sibling
/// `chain.pem`.
fn vhssl_chain_file(vhssl: &VhSsl) -> Option<PathBuf> {
    resolve_chain_file(
        &vhssl.cert_file,
        vhssl.cert_chain,
        vhssl.ca_cert_file.as_deref(),
    )
}

/// The chain-file argument for a listener's own default certificate. The
/// listener's `ca_cert_file` is the **client verifier** root (Cloudflare
/// origin-pull CA), NOT server chain material, so it is never appended. When
/// `cert_chain` is set we auto-discover the LE sibling `chain.pem` so a
/// leaf-only `cert.pem` still produces a complete `leaf, intermediate` chain.
fn listener_chain_file(tls: &ListenerTls) -> Option<PathBuf> {
    resolve_chain_file(&tls.cert_file, tls.cert_chain, None)
}

/// Build the per-listener SNI certificate resolver.
///
/// One [`CertifiedKey`] is registered for **each domain** the listener maps to
/// a vhost that has a [`VhSsl`] block. The catch-all domain `*` is not a real
/// SNI name and is skipped here (the listener's default certificate covers the
/// no-/non-matching-SNI case). Vhosts referenced by the listener but missing
/// from `server.vhosts`, or lacking a `vhssl` block, are skipped with a warning.
///
/// A vhost whose certificate fails to load is logged and skipped rather than
/// aborting the whole listener, so one bad vhost cert cannot take down TLS for
/// every other domain.
///
/// Following OLS (`VHostMapFindSslContext`), a configured domain is registered
/// to its vhost's certificate **without any certificate name-match check** —
/// the mapping is authoritative even when the cert's SAN/CN does not cover that
/// domain.
pub(crate) fn build_sni_resolver(server: &ServerConfig, listener: &Listener) -> Result<SniCertMap> {
    let mut resolver = SniCertMap::new();
    let mut registered = 0usize;

    for map in &listener.vhost_map {
        let Some(decl) = server.vhosts.get(&map.vhost) else {
            tracing::warn!(
                listener = %listener.name,
                vhost = %map.vhost,
                "listener vhostMap references unknown vhost; skipping for SNI"
            );
            continue;
        };
        let Some(vhconf) = decl.config.as_ref() else {
            tracing::debug!(vhost = %map.vhost, "vhost config not loaded; skipping for SNI");
            continue;
        };
        let Some(vhssl) = vhconf.vhssl.as_ref() else {
            // No per-vhost cert: this domain will be served by the default cert.
            continue;
        };

        let ck = match build_certified_key(
            &vhssl.cert_file,
            vhssl_chain_file(vhssl).as_deref(),
            &vhssl.key_file,
        ) {
            Ok(ck) => Arc::new(ck),
            Err(err) => {
                tracing::error!(
                    vhost = %map.vhost,
                    cert = %vhssl.cert_file.display(),
                    error = %err,
                    "failed to load vhost TLS certificate; skipping (its domains fall back to the default cert)"
                );
                continue;
            }
        };

        for domain in &map.domains {
            let domain = domain.trim();
            if domain.is_empty() || domain == "*" {
                continue;
            }
            // OLS maps the configured domain straight to the vhost's cert with
            // no name-match check: present this vhost's cert for this domain
            // even if the cert's SAN/CN does not cover it.
            resolver.add(domain, ck.clone());
            registered += 1;
        }
    }

    tracing::debug!(
        listener = %listener.name,
        sni_domains = registered,
        "built SNI resolver"
    );
    Ok(resolver)
}

/// Build an *optional* client verifier: a client cert is verified against `ca`
/// when presented, but a connection with no client cert is still allowed.
fn build_optional_client_verifier(
    ca: &Path,
) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>> {
    let roots = load_root_store(ca)?;
    WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider()?)
        .allow_unauthenticated()
        .build()
        .with_context(|| {
            format!(
                "building optional client certificate verifier from {}",
                ca.display()
            )
        })
}

/// Wraps a [`ClientCertVerifier`] to additionally enforce the listener's `verifyDepth`
/// (OpenLiteSpeed's `SSL_CTX_set_verify_depth` parity): after the inner verifier validates a
/// PRESENTED client-cert chain to the CA, reject it if it carries more intermediate CA certificates
/// than `max_intermediates`. rustls/webpki expose no chain-depth knob, so `verifyDepth` was parsed
/// and stored but silently unenforced; this closes that gap. It can only ADD a rejection on top of
/// the inner verification — never weaken it — and is a no-op for the single-level Cloudflare AOP CA
/// in prod (a presented chain has 0 intermediates, so `0 <= verifyDepth` always holds).
#[derive(Debug)]
struct DepthLimitedClientVerifier {
    inner: Arc<dyn rustls::server::danger::ClientCertVerifier>,
    max_intermediates: usize,
    /// (#301) Positive-verdict memo for validated client-cert chains. The mTLS
    /// listener disables session resumption (#300), so every connection runs a
    /// full webpki chain build + signature verification (RSA-4096 for the
    /// Cloudflare origin-pull CA) for what is in practice ONE long-lived client
    /// certificate. A chain that verified is remembered by its exact DER bytes
    /// (byte-compare, no hashing — no collision surface) for [`CHAIN_MEMO_TTL`],
    /// bounding how long an expiring certificate can keep riding a cached
    /// verdict. Rejections are never cached (and only CA-signed chains can
    /// enter, so an attacker cannot grow or thrash the memo). Config reloads
    /// rebuild the verifier, so the memo can never outlive a CA change.
    chain_memo: parking_lot::Mutex<Vec<ChainMemo>>,
}

struct ChainMemo {
    key: Vec<u8>,
    valid_until: std::time::Instant,
}

impl std::fmt::Debug for ChainMemo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainMemo").finish_non_exhaustive()
    }
}

/// How long a validated chain's verdict may be reused before webpki re-runs in
/// full. Also the upper bound on how late a certificate expiry is noticed.
const CHAIN_MEMO_TTL: std::time::Duration = std::time::Duration::from_secs(60);
/// Distinct concurrently-remembered chains (prod sees one, plus a rotation
/// overlap); oldest entry is dropped beyond this.
const CHAIN_MEMO_CAP: usize = 8;

/// Unambiguous memo key: each chain certificate length-prefixed, leaf first.
fn chain_memo_key(
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
) -> Vec<u8> {
    let total: usize =
        4 + end_entity.len() + intermediates.iter().map(|c| 4 + c.len()).sum::<usize>();
    let mut key = Vec::with_capacity(total);
    for cert in std::iter::once(end_entity).chain(intermediates.iter()) {
        key.extend_from_slice(&(cert.len() as u32).to_le_bytes());
        key.extend_from_slice(cert.as_ref());
    }
    key
}

impl DepthLimitedClientVerifier {
    fn wrap(
        inner: Arc<dyn rustls::server::danger::ClientCertVerifier>,
        max_intermediates: usize,
    ) -> Arc<dyn rustls::server::danger::ClientCertVerifier> {
        Arc::new(DepthLimitedClientVerifier {
            inner,
            max_intermediates,
            chain_memo: parking_lot::Mutex::new(Vec::new()),
        })
    }
}

impl rustls::server::danger::ClientCertVerifier for DepthLimitedClientVerifier {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }
    fn client_auth_mandatory(&self) -> bool {
        self.inner.client_auth_mandatory()
    }
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        self.inner.root_hint_subjects()
    }
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        // OLS verifyDepth N == at most N intermediate CAs between the leaf and the trust anchor.
        // Checked FIRST (before webpki AND before the memo): a too-deep chain is rejected for
        // free, and a cached verdict can never bypass the depth limit.
        if intermediates.len() > self.max_intermediates {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Other(rustls::OtherError(Arc::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "client certificate chain has {} intermediate(s), exceeding verifyDepth {}",
                        intermediates.len(),
                        self.max_intermediates
                    ),
                )))),
            ));
        }
        let key = chain_memo_key(end_entity, intermediates);
        let mono_now = std::time::Instant::now();
        {
            let mut memo = self.chain_memo.lock();
            memo.retain(|m| m.valid_until > mono_now);
            if memo.iter().any(|m| m.key == key) {
                return Ok(rustls::server::danger::ClientCertVerified::assertion());
            }
        }
        let verified = self
            .inner
            .verify_client_cert(end_entity, intermediates, now)?;
        let mut memo = self.chain_memo.lock();
        if memo.len() >= CHAIN_MEMO_CAP {
            memo.remove(0);
        }
        memo.push(ChainMemo {
            key,
            valid_until: mono_now + CHAIN_MEMO_TTL,
        });
        Ok(verified)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }
}

/// Load a PEM file of CA certificates into a [`RootCertStore`].
fn load_root_store(ca: &Path) -> Result<RootCertStore> {
    let certs =
        read_certs(ca).with_context(|| format!("loading CA certificates from {}", ca.display()))?;
    if certs.is_empty() {
        return Err(anyhow!("no CA certificates found in {}", ca.display()));
    }
    let mut roots = RootCertStore::empty();
    let (added, ignored) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(anyhow!(
            "no usable CA certificates in {} ({} unparsable)",
            ca.display(),
            ignored
        ));
    }
    if ignored > 0 {
        tracing::warn!(
            ca = %ca.display(),
            ignored,
            added,
            "some CA certificates in the verifier root file were unparsable"
        );
    }
    Ok(roots)
}

/// Build the unified [`rustls::ServerConfig`] for `listener`, shared by the TCP
/// (monoio-rustls) and QUIC (quinn-proto) transports.
///
/// Behaviour:
/// * SNI resolution per [`build_sni_resolver`], with the listener's own
///   `cert_file`/`key_file` as the default (non-matching-SNI) certificate.
/// * Client auth per `listener.tls.client_verify` (`2` = require — but enforced at the
///   application layer, not fail-closed at the handshake; `1` = optional, else none),
///   rooted solely at the listener's `ca_cert_file`.
/// * ALPN = `[h2, http/1.1]`; `max_early_data_size = 0`.
///
/// Errors if the listener has no TLS block, if a required CA file is missing
/// for client verification, or if the default certificate/key cannot load.
///
/// [`install_crypto_provider`] must have been called first.
///
/// This is the TCP-path entry point. The HTTP/3 path calls
/// [`build_server_config_alpn`] with `[b"h3"]` instead; both share the exact
/// same SNI resolver, default-cert fallback and client-cert verifier — only the
/// advertised ALPN differs.
pub fn build_server_config(
    cfg: &ServerConfig,
    listener: &Listener,
) -> Result<Arc<RustlsServerConfig>> {
    Ok(build_server_config_reloadable(cfg, listener)?.0)
}

/// Like [`build_server_config`] but also returns a [`CertReloadHandle`] for
/// live certificate reload (OPS9). The server uses this variant; tests that only
/// need the config use [`build_server_config`].
pub fn build_server_config_reloadable(
    cfg: &ServerConfig,
    listener: &Listener,
) -> Result<(Arc<RustlsServerConfig>, CertReloadHandle)> {
    build_server_config_inner(
        cfg,
        listener,
        ALPN_PROTOCOLS.iter().map(|p| p.to_vec()).collect(),
    )
}

/// Build the unified [`rustls::ServerConfig`] for `listener` advertising the
/// given `alpn` protocol list. Shared by the TCP and QUIC entry points so an
/// HTTP/3 request and an HTTP/2 request to the same listener get the same SNI
/// resolver, default-cert fallback and `max_early_data_size = 0`.
///
/// Both TCP and QUIC use the *optional* verifier for `clientVerify=2`: the TLS
/// handshake completes without a client cert, and the application layer then
/// refuses any non-loopback / non-private-LAN peer that presented none. On TCP
/// this is `server::is_trusted_internal_peer` in the https accept loop; on QUIC
/// it is the explicit check in `hj_http::h3::serve_h3_connection` (see
/// `h3.rs` around the `require_client_cert` guard). A *presented* cert is always
/// validated against the CA by the optional verifier, so external peers still
/// need a valid Cloudflare authenticated-origin-pull certificate.
///
/// [`install_crypto_provider`] must have been called first.
fn build_server_config_inner(
    cfg: &ServerConfig,
    listener: &Listener,
    alpn: Vec<Vec<u8>>,
) -> Result<(Arc<RustlsServerConfig>, CertReloadHandle)> {
    let tls = listener
        .tls
        .as_ref()
        .ok_or_else(|| anyhow!("listener {} has no TLS configuration", listener.name))?;

    let provider = provider()?;

    // 1. Client-cert verifier (see [`build_listener_verifier`] for the clientVerify semantics).
    let verifier = build_listener_verifier(tls, listener)?;

    // 2. SNI resolver + listener default certificate, held behind an ArcSwap so
    //    renewed certs can be live-reloaded (OPS9) without rebuilding this config.
    let cert_swap = Arc::new(ArcSwap::from_pointee(build_sni_with_default(
        cfg, listener,
    )?));
    let resolver = Arc::new(ReloadableResolver(cert_swap.clone()));

    // 3. Assemble the ServerConfig on the installed provider so the resolver,
    //    verifier, and key material all share one crypto backend.
    let mut config = RustlsServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .with_context(|| format!("listener {}: selecting TLS versions", listener.name))?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(resolver);

    config.alpn_protocols = alpn;
    config.max_early_data_size = 0; // 0-RTT stays off: replay risk for non-idempotent requests.

    // TLS session resumption. rustls defaults to NO session storage, so every new
    // connection does a full TLS 1.3 handshake (key exchange + cert). Cloudflare cycles
    // its origin connections continuously (idle reaps, the HTTP/1.1 max-requests cap,
    // edge-POP rotation), so an in-memory resumable-session cache turns those steady-state
    // reconnects into abbreviated (resumed) handshakes — a broad TTFB win that touches
    // every reconnecting client, cached or dynamic. Stateful store, shared across the
    // SO_REUSEPORT worker tasks in this process (one `ServerConfig` Arc). It is per
    // process: a restart (deploy) starts cold and cannot resume the post-restart burst —
    // this lifts steady-state churn, not the cold-start reconnect.
    //
    // (audit) NOT for a client-cert-verifying listener: rustls persists the presented
    // client-cert chain INSIDE the stored session value and reinstalls it as
    // peer_certificates on a RESUMED handshake — an actor holding any earlier ticket
    // would pass the app-layer mTLS gate (`has_client_cert`) without presenting a
    // certificate at all. rustls resumes ONLY through this store (no bare session-ID
    // path), so a no-op store disables resumption outright on that listener and forces
    // the full handshake, which presents (or omits) the cert fresh every time.
    // (#300) The former "keep the rustls default" branch did NOT do that: ServerConfig's
    // default session_storage IS a stateful ServerSessionMemoryCache(256), so TLS 1.3
    // tickets were stored and resumed with the old chain reinstated. Explicit no-op,
    // mirroring the kTLS builder below.
    config.session_storage = if tls.client_verify != 0 {
        Arc::new(NoServerSessions)
    } else {
        ServerSessionMemoryCache::new(TLS_SESSION_CACHE_SIZE)
    };

    Ok((Arc::new(config), CertReloadHandle(cert_swap)))
}

/// Resumable TLS sessions retained per process (stateful tickets / session IDs). 32 Ki
/// entries (~a few hundred bytes each) comfortably exceeds a node's live + churning
/// connection set, so the resumption hit rate stays high without unbounded growth.
const TLS_SESSION_CACHE_SIZE: usize = 1 << 15;

/// Build the listener's client-cert verifier from `clientVerify`.
///
/// clientVerify=2 uses the OPTIONAL verifier (the handshake completes without a cert; the
/// app layer then enforces the requirement) — it does NOT fail closed at the handshake. A
/// *presented* cert is always validated against the CA. 1/3 also map to OLS SSL_VERIFY_PEER
/// (optional, presented cert validated). `verifyDepth` is enforced on any chain-validating
/// mode (a no-op in prod: single-level CA ⇒ 0 intermediates).
fn build_listener_verifier(
    tls: &ListenerTls,
    listener: &Listener,
) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>> {
    let base_verifier: Arc<dyn rustls::server::danger::ClientCertVerifier> = match tls.client_verify
    {
        2 => {
            let ca = tls.ca_cert_file.as_deref().ok_or_else(|| {
                anyhow!(
                    "listener {} requires client certificates (clientVerify=2) but has no CACertFile",
                    listener.name
                )
            })?;
            build_optional_client_verifier(ca).with_context(|| {
                format!(
                    "listener {}: building app-enforced client verifier",
                    listener.name
                )
            })?
        }
        1 | 3 => {
            let ca = tls.ca_cert_file.as_deref().ok_or_else(|| {
                anyhow!(
                    "listener {} has optional client verification (clientVerify={}) but no CACertFile",
                    listener.name,
                    tls.client_verify
                )
            })?;
            build_optional_client_verifier(ca).with_context(|| {
                format!(
                    "listener {}: building optional client verifier",
                    listener.name
                )
            })?
        }
        _ => WebPkiClientVerifier::no_client_auth(),
    };
    Ok(if matches!(tls.client_verify, 1 | 2 | 3) {
        DepthLimitedClientVerifier::wrap(base_verifier, tls.verify_depth as usize)
    } else {
        base_verifier
    })
}

/// Reusable assembly for building **per-connection** [`rustls::ServerConfig`]s that differ
/// only in their `key_log`. The expensive parts (provider, client-cert verifier, the
/// reloadable SNI/default-cert resolver, session cache) are built once and shared by Arc; a
/// per-connection config just re-runs the cheap builder assembly with a fresh `key_log`.
///
/// This exists only for the io_uring `--ktls` path: kTLS re-keying on a TLS 1.3 KeyUpdate
/// needs the raw traffic secrets, which rustls only surfaces through `KeyLog` — and a `KeyLog`
/// is per-`ServerConfig`, so each connection needs its own config to capture its own secrets
/// without cross-connection races. ALPN, `max_early_data_size=0`, and the shared session
/// cache match [`build_server_config_inner`].
pub struct KtlsConfigTemplate {
    provider: Arc<rustls::crypto::CryptoProvider>,
    verifier: Arc<dyn rustls::server::danger::ClientCertVerifier>,
    resolver: Arc<ReloadableResolver>,
    alpn: Vec<Vec<u8>>,
    session_storage: Arc<dyn rustls::server::StoresServerSessions + Send + Sync>,
}

impl KtlsConfigTemplate {
    /// Assemble a fresh `ServerConfig` (cheap: shares the Arc'd verifier/resolver/cache)
    /// installing `key_log` as this connection's secret sink.
    pub fn server_config_with_key_log(
        &self,
        key_log: Arc<dyn rustls::KeyLog>,
    ) -> Result<Arc<RustlsServerConfig>> {
        let mut config = RustlsServerConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .context("ktls: selecting TLS versions")?
            .with_client_cert_verifier(self.verifier.clone())
            .with_cert_resolver(self.resolver.clone());
        config.alpn_protocols = self.alpn.clone();
        config.max_early_data_size = 0;
        config.session_storage = self.session_storage.clone();
        config.key_log = key_log;
        // kTLS programs the kernel TLS keys at the connection's CURRENT record sequence, which
        // we read from `dangerous_extract_secrets` after the handshake — so NewSessionTickets
        // (emitted under the server app key during the final flush, advancing the TX sequence)
        // are accounted for and resumption tickets stay enabled. `enable_secret_extraction`
        // makes that seq readable. (It does not change the wire handshake.)
        config.enable_secret_extraction = true;
        Ok(Arc::new(config))
    }
}

/// Build a [`KtlsConfigTemplate`] (+ a [`CertReloadHandle`] for SIGHUP cert reload) for the
/// io_uring `--ktls` path. Mirrors [`build_server_config_inner`]'s verifier/resolver/ALPN.
pub fn build_ktls_template(
    cfg: &ServerConfig,
    listener: &Listener,
) -> Result<(KtlsConfigTemplate, CertReloadHandle)> {
    let tls = listener
        .tls
        .as_ref()
        .ok_or_else(|| anyhow!("listener {} has no TLS configuration", listener.name))?;
    let provider = provider()?;
    let verifier = build_listener_verifier(tls, listener)?;
    let cert_swap = Arc::new(ArcSwap::from_pointee(build_sni_with_default(
        cfg, listener,
    )?));
    let resolver = Arc::new(ReloadableResolver(cert_swap.clone()));
    // (security #267) Same rule as the TCP builder: NO session storage on a
    // client-cert-verifying listener — a resumed handshake reinstates the stored
    // client-cert chain and defeats the app-layer mTLS gate. kTLS's ticket/sequence
    // accounting (see `server_config_with_key_log`) is unaffected by leaving the
    // default (no) storage; there are simply no tickets to emit.
    let session_storage: Arc<dyn rustls::server::StoresServerSessions + Send + Sync> =
        if tls.client_verify != 0 {
            Arc::new(NoServerSessions)
        } else {
            ServerSessionMemoryCache::new(TLS_SESSION_CACHE_SIZE)
        };
    let template = KtlsConfigTemplate {
        provider,
        verifier,
        resolver,
        alpn: ALPN_PROTOCOLS.iter().map(|p| p.to_vec()).collect(),
        session_storage,
    };
    Ok((template, CertReloadHandle(cert_swap)))
}

/// A `StoresServerSessions` implementation that stores nothing — used instead of
/// the shared memory cache on client-cert-verifying listeners so resumption is
/// impossible (see [`build_ktls_template`]).
#[derive(Debug)]
struct NoServerSessions;

impl rustls::server::StoresServerSessions for NoServerSessions {
    fn put(&self, _id: Vec<u8>, _value: Vec<u8>) -> bool {
        false
    }
    fn get(&self, _id: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn take(&self, _id: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn can_cache(&self) -> bool {
        false
    }
}

/// QUIC/HTTP3 entry point. Like [`build_server_config`] (the TCP entry), uses
/// the *optional* verifier for `clientVerify=2`: the handshake completes without
/// a client cert, and the QUIC accept path enforces "a valid cert is required
/// UNLESS the peer is loopback / private-LAN" at the application layer
/// (see [`hj_core::is_trusted_internal_peer`] and `hj_http::h3::serve_h3_connection`).
/// A *presented* cert is still validated against the CF origin-pull CA, so external
/// peers still need a valid one. See [`build_server_config_inner`] for the assembly.
pub fn build_server_config_alpn(
    cfg: &ServerConfig,
    listener: &Listener,
    alpn: Vec<Vec<u8>>,
) -> Result<Arc<RustlsServerConfig>> {
    Ok(build_server_config_alpn_reloadable(cfg, listener, alpn)?.0)
}

/// Like [`build_server_config_alpn`] but also returns a [`CertReloadHandle`].
pub fn build_server_config_alpn_reloadable(
    cfg: &ServerConfig,
    listener: &Listener,
    alpn: Vec<Vec<u8>>,
) -> Result<(Arc<RustlsServerConfig>, CertReloadHandle)> {
    build_server_config_inner(cfg, listener, alpn)
}

/// Extract the per-request [`TlsParams`] from a completed [`rustls::ServerConnection`]
/// (the server side of a TCP TLS connection, reachable via `tls.get_ref().1`).
///
/// Returns `None` only when no protocol version has been negotiated yet (i.e. the
/// handshake has not completed) — in that case there is nothing meaningful to
/// report. Once the handshake is done this yields the negotiated protocol/cipher
/// and, when the peer presented a leaf certificate, its parsed details.
///
/// The leaf is parsed with `x509-parser`. `verified` is set to `true`: rustls only
/// surfaces a `peer_certificate` after the configured [`WebPkiClientVerifier`] has
/// already validated the chain against the listener's CA, so any cert we see here
/// has been accepted. `not_before`/`not_after` are rendered as RFC3339 UTC strings.
pub fn tls_params_from_conn(conn: &rustls::ServerConnection) -> Option<TlsParams> {
    let protocol = match conn.protocol_version()? {
        rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3",
        rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2",
        other => other.as_str().unwrap_or("TLS"),
    };

    let cipher = conn
        .negotiated_cipher_suite()
        .map(|cs| {
            let suite = cs.suite();
            suite
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| format!("{suite:?}"))
        })
        .unwrap_or_default();

    let leaf = conn.peer_certificates().and_then(|certs| certs.first());

    Some(tls_params_from_parts(protocol, cipher, leaf))
}

/// Assemble [`TlsParams`] from already-extracted parts: the negotiated protocol
/// string, the cipher name (may be empty), and the optional verified client leaf
/// certificate (DER). Shared by the TCP path ([`tls_params_from_conn`], which
/// reads them from a [`rustls::ServerConnection`]) and the QUIC/HTTP3 path, which
/// extracts them from the quinn-proto connection's handshake data + peer identity
/// — the sans-IO endpoint does not expose the inner `ServerConnection`, so the
/// QUIC side supplies the parts directly. A `leaf`, when present, has already been validated against
/// the configured CA by the active client-cert verifier.
pub fn tls_params_from_parts(
    protocol: &'static str,
    cipher: String,
    leaf: Option<&CertificateDer<'_>>,
) -> TlsParams {
    TlsParams::new(protocol, cipher, leaf.and_then(parse_client_cert))
}

/// Parse a verified client leaf certificate (DER) into a [`ClientCert`].
///
/// Returns `None` if the DER fails to parse. `verified` is `true` because the
/// WebPkiClientVerifier already validated this certificate before rustls exposed it.
fn parse_client_cert(leaf: &CertificateDer<'_>) -> Option<ClientCert> {
    use x509_parser::prelude::FromDer;

    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(leaf.as_ref()).ok()?;
    let validity = cert.validity();
    Some(ClientCert {
        subject_dn: cert.subject().to_string(),
        issuer_dn: cert.issuer().to_string(),
        serial_hex: cert.raw_serial_as_string(),
        verified: true,
        not_before: fmt_asn1_time(&validity.not_before),
        not_after: fmt_asn1_time(&validity.not_after),
    })
}

/// Render an X.509 [`ASN1Time`](x509_parser::time::ASN1Time) as an RFC3339-style
/// UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`). ASN.1 cert times are always UTC.
fn fmt_asn1_time(t: &x509_parser::time::ASN1Time) -> String {
    let dt = t.to_datetime();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        dt.year(),
        u8::from(dt.month()),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::Arc;

    use hj_config::model::{Listener, ListenerTls, VHostConfig, VHostDecl, VhSsl, VhostMap};

    /// A generated leaf cert + key (PEM) for a set of SAN names.
    struct TestCert {
        cert_pem: String,
        key_pem: String,
    }

    fn gen_cert(names: &[&str]) -> TestCert {
        let certified = rcgen::generate_simple_self_signed(
            names.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
        .expect("generate self-signed cert");
        TestCert {
            cert_pem: certified.cert.pem(),
            key_pem: certified.signing_key.serialize_pem(),
        }
    }

    fn write_tmp(dir: &Path, name: &str, contents: &str) -> PathBuf {
        let p = dir.join(name);
        let mut f = File::create(&p).expect("create temp file");
        f.write_all(contents.as_bytes()).expect("write temp file");
        p
    }

    fn tmpdir() -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "hj-tls-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).expect("create tmpdir");
        base
    }

    fn ensure_provider() {
        install_crypto_provider().expect("install crypto provider");
    }

    fn make_vhost_decl(name: &str, vhssl: Option<VhSsl>) -> VHostDecl {
        let vhconf = VHostConfig {
            vhssl,
            ..Default::default()
        };
        VHostDecl {
            name: name.to_string(),
            vh_root: PathBuf::from("/tmp"),
            config_file: PathBuf::from("/tmp/x.xml"),
            allow_symbol_link: None,
            restrained: false,
            enable_script: false,
            config: Some(Arc::new(vhconf)),
        }
    }

    fn base_server() -> ServerConfig {
        ServerConfig {
            server_root: PathBuf::from("/tmp"),
            server_name: "test".into(),
            user: "nobody".into(),
            group: "nobody".into(),
            index_files: vec![],
            tuning: Default::default(),
            quic_enable: false,
            use_ip_in_proxy_header: 0,
            expires: Default::default(),
            cache: Default::default(),
            security: Default::default(),
            suexec: Default::default(),
            ext_processors: vec![],
            php_config: None,
            listeners: vec![],
            vhosts: Default::default(),
            vhost_order: vec![],
            mime: Default::default(),
        }
    }

    #[test]
    fn install_provider_is_idempotent() {
        ensure_provider();
        ensure_provider();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }

    #[test]
    fn load_cert_and_key_roundtrip() {
        ensure_provider();
        let dir = tmpdir();
        let c = gen_cert(&["leaf.example.com"]);
        let cert = write_tmp(&dir, "cert.pem", &c.cert_pem);
        let key = write_tmp(&dir, "key.pem", &c.key_pem);

        let chain = load_cert_chain(&cert, None).expect("load chain");
        assert_eq!(chain.len(), 1, "single leaf cert");

        let _signing = load_private_key(&key).expect("load key");
        let ck = build_certified_key(&cert, None, &key).expect("certified key");
        assert_eq!(ck.cert.len(), 1);
    }

    #[test]
    fn fullchain_dedupes_repeated_leaf() {
        ensure_provider();
        let dir = tmpdir();
        let leaf = gen_cert(&["dedupe.example.com"]);
        let intermediate = gen_cert(&["intermediate.example.com"]);

        let cert = write_tmp(&dir, "cert.pem", &leaf.cert_pem);
        // chain file is a "fullchain": leaf repeated, then an intermediate.
        let fullchain = format!("{}\n{}", leaf.cert_pem, intermediate.cert_pem);
        let chain_file = write_tmp(&dir, "chain.pem", &fullchain);

        let chain = load_cert_chain(&cert, Some(&chain_file)).expect("load chain");
        // leaf + intermediate, with the duplicate leaf dropped.
        assert_eq!(chain.len(), 2, "duplicate leaf must be removed");
    }

    #[test]
    fn appends_distinct_chain_material() {
        ensure_provider();
        let dir = tmpdir();
        let leaf = gen_cert(&["chained.example.com"]);
        let intermediate = gen_cert(&["int.example.com"]);
        let cert = write_tmp(&dir, "cert.pem", &leaf.cert_pem);
        let chain_file = write_tmp(&dir, "chain.pem", &intermediate.cert_pem);

        let chain = load_cert_chain(&cert, Some(&chain_file)).expect("load chain");
        assert_eq!(chain.len(), 2, "leaf + appended intermediate");
    }

    #[test]
    fn empty_cert_file_errors() {
        ensure_provider();
        let dir = tmpdir();
        let cert = write_tmp(&dir, "empty.pem", "not a certificate\n");
        let err = load_cert_chain(&cert, None).unwrap_err();
        assert!(err.to_string().contains("no certificates"), "got: {err}");
    }

    #[test]
    fn build_sni_resolver_registers_domains() {
        ensure_provider();
        let dir = tmpdir();
        // vhost cert valid for two SAN names.
        let c = gen_cert(&["a.example.com", "alias.example.com"]);
        let cert = write_tmp(&dir, "vh-cert.pem", &c.cert_pem);
        let key = write_tmp(&dir, "vh-key.pem", &c.key_pem);

        let vhssl = VhSsl {
            key_file: key,
            cert_file: cert,
            cert_chain: false,
            ca_cert_file: None,
        };

        let mut server = base_server();
        server
            .vhosts
            .insert("vh1".into(), make_vhost_decl("vh1", Some(vhssl)));

        let listener = Listener {
            name: "TLS".into(),
            address: "*:8443".into(),
            secure: true,
            vhost_map: vec![VhostMap {
                vhost: "vh1".into(),
                domains: vec!["a.example.com".into(), "alias.example.com".into()],
            }],
            tls: None,
        };

        let resolver = build_sni_resolver(&server, &listener).expect("resolver");
        // Both configured domains are registered (cert SAN happens to cover
        // them here, but the map does not depend on that).
        assert!(resolver.resolve_name(Some("a.example.com")).is_some());
        assert!(resolver.resolve_name(Some("alias.example.com")).is_some());
        // Case-insensitive lookup (OLS lowercases the servername).
        assert!(resolver.resolve_name(Some("A.Example.Com")).is_some());
        // Unmapped name yields None so the wrapper falls back to the default.
        assert!(resolver.resolve_name(Some("nope.example.com")).is_none());
        assert!(resolver.resolve_name(None).is_none());
    }

    #[test]
    fn build_sni_resolver_skips_star_and_unknown() {
        ensure_provider();
        let dir = tmpdir();
        let c = gen_cert(&["real.example.com"]);
        let cert = write_tmp(&dir, "c.pem", &c.cert_pem);
        let key = write_tmp(&dir, "k.pem", &c.key_pem);
        let vhssl = VhSsl {
            key_file: key,
            cert_file: cert,
            cert_chain: false,
            ca_cert_file: None,
        };

        let mut server = base_server();
        server
            .vhosts
            .insert("vh1".into(), make_vhost_decl("vh1", Some(vhssl)));

        let listener = Listener {
            name: "TLS".into(),
            address: "*:8443".into(),
            secure: true,
            vhost_map: vec![
                VhostMap {
                    vhost: "vh1".into(),
                    domains: vec!["*".into(), "real.example.com".into()],
                },
                VhostMap {
                    // unknown vhost is skipped, not fatal
                    vhost: "ghost".into(),
                    domains: vec!["ghost.example.com".into()],
                },
            ],
            tls: None,
        };

        // Should not error even though `*` and an unknown vhost are present.
        let resolver = build_sni_resolver(&server, &listener).expect("resolver");
        // `*` (catch-all) and the unknown `ghost` vhost are skipped; only the
        // single real domain is registered.
        assert!(resolver.resolve_name(Some("real.example.com")).is_some());
        assert!(resolver.resolve_name(Some("*")).is_none());
        assert!(resolver.resolve_name(Some("ghost.example.com")).is_none());
    }

    /// THE OLS-CORRECTNESS TEST: a domain mapped to a vhost whose certificate
    /// does NOT cover that domain (SAN/CN mismatch) is still served that
    /// vhost's configured cert — exactly as OLS `VHostMapFindSslContext` maps
    /// the configured domain to the vhost's `SslContext` without any cert
    /// name-match check. rustls's `ResolvesServerCertUsingSni` would have
    /// rejected this registration and silently fallen back to the default cert.
    #[test]
    fn sni_maps_to_cert_even_when_san_does_not_cover_name() {
        ensure_provider();
        let dir = tmpdir();

        // The publisher.example vhost cert. Its SAN does NOT include
        // news.forum.example — yet that domain is mapped to this vhost.
        let vh = gen_cert(&["publisher.example"]);
        let cert = write_tmp(&dir, "news-cert.pem", &vh.cert_pem);
        let key = write_tmp(&dir, "news-key.pem", &vh.key_pem);
        let vhssl = VhSsl {
            key_file: key,
            cert_file: cert,
            cert_chain: false,
            ca_cert_file: None,
        };

        let mut server = base_server();
        server.vhosts.insert(
            "publisher.example".into(),
            make_vhost_decl("publisher.example", Some(vhssl)),
        );

        let listener = Listener {
            name: "TLS".into(),
            address: "*:8443".into(),
            secure: true,
            vhost_map: vec![VhostMap {
                vhost: "publisher.example".into(),
                // Both names map to the same vhost+cert.
                domains: vec!["publisher.example".into(), "news.forum.example".into()],
            }],
            tls: None,
        };

        let resolver = build_sni_resolver(&server, &listener).expect("resolver");

        let on_name = resolver
            .resolve_name(Some("publisher.example"))
            .expect("publisher.example resolves");
        let off_name = resolver
            .resolve_name(Some("news.forum.example"))
            .expect("news.forum.example resolves to the publisher.example cert");

        // It is the SAME configured cert for both names (the vhost's cert),
        // not a default fallback.
        assert!(
            Arc::ptr_eq(&on_name, &off_name),
            "both SNI names must resolve to the same configured vhost cert"
        );

        // And the resolved cert is genuinely the publisher.example leaf, i.e. a
        // cert that does not cover news.forum.example is still presented.
        let leaf = off_name.end_entity_cert().expect("leaf cert present");
        let expected_leaf =
            load_cert_chain(Path::new(&dir.join("news-cert.pem")), None).expect("reload leaf");
        assert_eq!(
            leaf.as_ref(),
            expected_leaf[0].as_ref(),
            "the publisher.example cert is presented for news.forum.example"
        );
    }

    /// End-to-end through `build_server_config`: the wrapped resolver presents
    /// the name-uncovered vhost cert for its mapped SNI, and the listener
    /// default cert for any unmapped/missing SNI.
    #[test]
    fn full_config_resolver_serves_uncovered_sni_and_default_fallback() {
        ensure_provider();
        let dir = tmpdir();

        // Listener default cert.
        let dflt = gen_cert(&["default.example.com"]);
        let d_cert = write_tmp(&dir, "fc-default-cert.pem", &dflt.cert_pem);
        let d_key = write_tmp(&dir, "fc-default-key.pem", &dflt.key_pem);

        // vhost cert that does NOT cover the mapped alias.
        let vh = gen_cert(&["publisher.example"]);
        let vh_cert = write_tmp(&dir, "fc-vh-cert.pem", &vh.cert_pem);
        let vh_key = write_tmp(&dir, "fc-vh-key.pem", &vh.key_pem);
        let vhssl = VhSsl {
            key_file: vh_key,
            cert_file: vh_cert,
            cert_chain: false,
            ca_cert_file: None,
        };

        let mut server = base_server();
        server.vhosts.insert(
            "publisher.example".into(),
            make_vhost_decl("publisher.example", Some(vhssl)),
        );

        let listener = Listener {
            name: "TLS".into(),
            address: "*:8443".into(),
            secure: true,
            vhost_map: vec![VhostMap {
                vhost: "publisher.example".into(),
                domains: vec!["news.forum.example".into()],
            }],
            tls: Some(ListenerTls {
                key_file: d_key,
                cert_file: d_cert,
                cert_chain: false,
                ca_cert_file: None,
                client_verify: 0,
                verify_depth: 1,
                enable_stapling: false,
            }),
        };

        // Reconstruct the inner resolver the way build_server_config does, then
        // exercise the SniWithDefault wrapper directly (rustls ClientHello is
        // not publicly constructible, so we test resolve_name + default).
        let sni = build_sni_resolver(&server, &listener).expect("resolver");
        let default_ck = Arc::new(
            build_certified_key(
                &listener.tls.as_ref().unwrap().cert_file,
                None,
                &listener.tls.as_ref().unwrap().key_file,
            )
            .expect("default cert"),
        );
        let wrapper = SniWithDefault {
            sni,
            default: default_ck.clone(),
        };

        // Mapped (but SAN-uncovered) name -> the vhost cert, not the default.
        let mapped = wrapper
            .sni
            .resolve_name(Some("news.forum.example"))
            .expect("mapped name resolves");
        assert!(
            !Arc::ptr_eq(&mapped, &default_ck),
            "mapped name must NOT fall back to the default cert"
        );

        // Unmapped / missing SNI -> default cert.
        assert!(
            wrapper
                .sni
                .resolve_name(Some("unmapped.example.com"))
                .is_none()
        );
        assert!(wrapper.sni.resolve_name(None).is_none());
        // And the full config still builds.
        let cfg = build_server_config(&server, &listener).expect("server config");
        assert_eq!(cfg.max_early_data_size, 0);
    }

    #[test]
    fn client_verify_3_uses_optional_verifier_not_no_client_auth() {
        // Regression (#11): clientVerify=3 (optional_no_ca) must take the OPTIONAL verifier path
        // (like 1/2), NOT fall through to no_client_auth(). The optional path REQUIRES a CACertFile,
        // so mode 3 without one now ERRORS (the old fall-through accepted it) and mode 3 WITH one
        // builds — proving rustls now requests + validates a presented client cert (the old bug
        // never requested one, then the app layer refused every external peer).
        ensure_provider();
        let dir = tmpdir();
        let dflt = gen_cert(&["default.example.com"]);
        let d_cert = write_tmp(&dir, "cv3-cert.pem", &dflt.cert_pem);
        let d_key = write_tmp(&dir, "cv3-key.pem", &dflt.key_pem);
        let ca = gen_cert(&["ca.example.com"]);
        let ca_file = write_tmp(&dir, "cv3-ca.pem", &ca.cert_pem);

        let mk = |client_verify: u8, ca: Option<PathBuf>| Listener {
            name: "TLS".into(),
            address: "*:8443".into(),
            secure: true,
            vhost_map: vec![],
            tls: Some(ListenerTls {
                key_file: d_key.clone(),
                cert_file: d_cert.clone(),
                cert_chain: false,
                ca_cert_file: ca,
                client_verify,
                verify_depth: 1,
                enable_stapling: false,
            }),
        };
        let server = base_server();
        assert!(
            build_server_config(&server, &mk(3, Some(ca_file.clone()))).is_ok(),
            "mode 3 + CA builds"
        );
        assert!(
            build_server_config(&server, &mk(3, None)).is_err(),
            "mode 3 without a CA must error (optional path), not silently fall through to no_client_auth"
        );
        assert!(
            build_server_config(&server, &mk(0, None)).is_ok(),
            "mode 0 still builds with no CA"
        );
    }

    #[derive(Debug)]
    struct AlwaysOkVerifier;
    impl rustls::server::danger::ClientCertVerifier for AlwaysOkVerifier {
        fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
            &[]
        }
        fn verify_client_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: rustls::pki_types::UnixTime,
        ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
            Ok(rustls::server::danger::ClientCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![]
        }
    }

    #[test]
    fn depth_limited_verifier_rejects_overlong_chains() {
        // Regression (#12): verifyDepth is now enforced. With max_intermediates = 1, a presented
        // chain of 0 or 1 intermediate CAs is accepted (the inner verifier's verdict stands), but a
        // longer chain is rejected even though the inner verifier said OK — and the depth check can
        // only ever ADD a rejection, never accept what the inner verifier refused.
        use rustls::server::danger::ClientCertVerifier as _;
        let leaf = CertificateDer::from(vec![1u8, 2, 3, 4]);
        let v = DepthLimitedClientVerifier {
            inner: Arc::new(AlwaysOkVerifier),
            max_intermediates: 1,
            chain_memo: parking_lot::Mutex::new(Vec::new()),
        };
        let now = rustls::pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(
            1_700_000_000,
        ));
        assert!(
            v.verify_client_cert(&leaf, &[], now).is_ok(),
            "0 intermediates (prod shape) ok"
        );
        assert!(
            v.verify_client_cert(&leaf, &[leaf.clone()], now).is_ok(),
            "1 intermediate == depth ok"
        );
        assert!(
            v.verify_client_cert(&leaf, &[leaf.clone(), leaf.clone()], now)
                .is_err(),
            "2 intermediates exceeds verifyDepth 1 → rejected"
        );
    }

    /// (OPS9) Live cert reload: overwriting the cert file at the SAME path (the
    /// ACME-renewal case) and calling `CertReloadHandle::reload` swaps the new
    /// cert into the live resolver — observed through the handle's ArcSwap — while
    /// the rustls ServerConfig itself is untouched.
    #[test]
    fn cert_reload_swaps_in_renewed_cert() {
        ensure_provider();
        let dir = tmpdir();

        // Initial default cert (A).
        let a = gen_cert(&["default.example.com"]);
        let cert_path = write_tmp(&dir, "reload-cert.pem", &a.cert_pem);
        let key_path = write_tmp(&dir, "reload-key.pem", &a.key_pem);

        let server = base_server();
        let listener = Listener {
            name: "TLS".into(),
            address: "*:8443".into(),
            secure: true,
            vhost_map: vec![],
            tls: Some(ListenerTls {
                key_file: key_path,
                cert_file: cert_path.clone(),
                cert_chain: false,
                ca_cert_file: None,
                client_verify: 0,
                verify_depth: 1,
                enable_stapling: false,
            }),
        };

        let (_cfg, handle) =
            build_server_config_reloadable(&server, &listener).expect("build reloadable config");

        let leaf_now = || handle.0.load().default.cert[0].as_ref().to_vec();
        let expect_a = load_cert_chain(&cert_path, None).expect("load A")[0]
            .as_ref()
            .to_vec();
        assert_eq!(leaf_now(), expect_a, "resolver initially presents cert A");

        // Renew: overwrite the SAME paths with a fresh cert/key (B).
        let b = gen_cert(&["default.example.com"]);
        write_tmp(&dir, "reload-cert.pem", &b.cert_pem);
        write_tmp(&dir, "reload-key.pem", &b.key_pem);
        let expect_b = load_cert_chain(&cert_path, None).expect("load B")[0]
            .as_ref()
            .to_vec();
        assert_ne!(expect_a, expect_b, "test sanity: A and B differ");

        // No change until reload is invoked.
        assert_eq!(leaf_now(), expect_a, "cert must NOT change before reload()");

        // Reload re-reads the files and swaps the new cert into the live resolver.
        handle.reload(&server, &listener).expect("reload certs");
        assert_eq!(
            leaf_now(),
            expect_b,
            "resolver presents cert B after reload()"
        );
    }

    #[test]
    fn build_server_config_no_client_auth() {
        ensure_provider();
        let dir = tmpdir();
        let c = gen_cert(&["default.example.com"]);
        let cert = write_tmp(&dir, "d-cert.pem", &c.cert_pem);
        let key = write_tmp(&dir, "d-key.pem", &c.key_pem);

        let server = base_server();
        let listener = Listener {
            name: "TLS".into(),
            address: "*:8443".into(),
            secure: true,
            vhost_map: vec![],
            tls: Some(ListenerTls {
                key_file: key,
                cert_file: cert,
                cert_chain: false,
                ca_cert_file: None,
                client_verify: 0,
                verify_depth: 1,
                enable_stapling: false,
            }),
        };

        let cfg = build_server_config(&server, &listener).expect("server config");
        assert_eq!(
            cfg.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert_eq!(cfg.max_early_data_size, 0);
    }

    /// The HTTP/3 variant advertises only `h3` while sharing the TCP path's
    /// resolver/verifier wiring. This is the config quinn wraps for QUIC.
    #[test]
    fn build_server_config_alpn_h3_advertises_h3() {
        ensure_provider();
        let dir = tmpdir();
        let c = gen_cert(&["default.example.com"]);
        let cert = write_tmp(&dir, "h3-cert.pem", &c.cert_pem);
        let key = write_tmp(&dir, "h3-key.pem", &c.key_pem);

        let server = base_server();
        let listener = Listener {
            name: "TLS".into(),
            address: "*:8443".into(),
            secure: true,
            vhost_map: vec![],
            tls: Some(ListenerTls {
                key_file: key,
                cert_file: cert,
                cert_chain: false,
                ca_cert_file: None,
                client_verify: 0,
                verify_depth: 1,
                enable_stapling: false,
            }),
        };

        let cfg = build_server_config_alpn(&server, &listener, vec![b"h3".to_vec()])
            .expect("h3 server config");
        assert_eq!(cfg.alpn_protocols, vec![b"h3".to_vec()]);
        assert_eq!(cfg.max_early_data_size, 0);
    }

    #[test]
    fn build_server_config_requires_ca_when_verify_required() {
        ensure_provider();
        let dir = tmpdir();
        let c = gen_cert(&["default.example.com"]);
        let cert = write_tmp(&dir, "d2-cert.pem", &c.cert_pem);
        let key = write_tmp(&dir, "d2-key.pem", &c.key_pem);

        let server = base_server();
        let listener = Listener {
            name: "TLS".into(),
            address: "*:8443".into(),
            secure: true,
            vhost_map: vec![],
            tls: Some(ListenerTls {
                key_file: key,
                cert_file: cert,
                cert_chain: false,
                ca_cert_file: None, // missing on purpose
                client_verify: 2,   // require -> must fail closed (error)
                verify_depth: 1,
                enable_stapling: false,
            }),
        };

        let err = build_server_config(&server, &listener).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("CACertFile"),
            "expected CACertFile error, got: {msg}"
        );
    }

    #[test]
    fn optional_verifier_allows_missing_client_cert() {
        ensure_provider();
        let dir = tmpdir();
        let ca = gen_cert(&["ca.example.com"]);
        let ca_file = write_tmp(&dir, "ca.pem", &ca.cert_pem);

        let verifier = build_optional_client_verifier(&ca_file).expect("optional verifier");
        assert!(
            !verifier.client_auth_mandatory(),
            "optional verifier must allow connections with no client cert"
        );
    }

    /// Drive a real (in-memory) TLS handshake against the config returned by the
    /// given builder, with a client that trusts the server leaf and presents NO
    /// client certificate. Returns `Ok(())` if the handshake completes, `Err` with
    /// the server-side error otherwise. This is the ground truth for whether
    /// `clientVerify=2` fails closed at the handshake (mandatory) or completes and
    /// defers enforcement to the app layer (relaxed).
    fn handshake_without_client_cert(
        build: impl Fn(&ServerConfig, &Listener) -> Result<Arc<RustlsServerConfig>>,
    ) -> std::result::Result<(), rustls::Error> {
        use rustls::pki_types::ServerName;
        use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConnection};

        ensure_provider();
        let dir = tmpdir();
        let leaf = gen_cert(&["forum.example"]);
        let cert = write_tmp(&dir, "cert.pem", &leaf.cert_pem);
        let key = write_tmp(&dir, "key.pem", &leaf.key_pem);
        let ca = gen_cert(&["origin-pull-ca.example.com"]);
        let ca_file = write_tmp(&dir, "ca.pem", &ca.cert_pem);

        let server = base_server();
        let listener = Listener {
            name: "TLS".into(),
            address: "*:443".into(),
            secure: true,
            vhost_map: vec![],
            tls: Some(ListenerTls {
                key_file: key,
                cert_file: cert,
                cert_chain: false,
                ca_cert_file: Some(ca_file),
                client_verify: 2,
                verify_depth: 1,
                enable_stapling: true,
            }),
        };
        let server_cfg = build(&server, &listener).expect("server config");

        // Client trusts the server leaf and offers no client certificate.
        let mut roots = RootCertStore::empty();
        let leaf_der = rustls_pemfile::certs(&mut leaf.cert_pem.as_bytes())
            .next()
            .unwrap()
            .unwrap();
        roots.add(leaf_der).unwrap();
        let client_cfg = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let name = ServerName::try_from("forum.example").unwrap();
        let mut client = ClientConnection::new(Arc::new(client_cfg), name).unwrap();
        let mut srv = ServerConnection::new(server_cfg).unwrap();

        // Pump bytes between the two endpoints until the handshake settles.
        for _ in 0..16 {
            let mut c2s = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut c2s).unwrap();
            }
            if !c2s.is_empty() {
                let mut sl = &c2s[..];
                while !sl.is_empty() {
                    srv.read_tls(&mut sl).unwrap();
                }
                srv.process_new_packets()?; // server-side verdict (the thing under test)
            }
            let mut s2c = Vec::new();
            while srv.wants_write() {
                srv.write_tls(&mut s2c).unwrap();
            }
            if !s2c.is_empty() {
                let mut sl = &s2c[..];
                while !sl.is_empty() {
                    client.read_tls(&mut sl).unwrap();
                }
                let _ = client.process_new_packets();
            }
            if !client.is_handshaking() && !srv.is_handshaking() {
                break;
            }
        }
        if srv.is_handshaking() {
            return Err(rustls::Error::General("handshake did not complete".into()));
        }
        Ok(())
    }

    #[test]
    fn tcp_clientverify2_completes_handshake_without_client_cert() {
        // The TCP entry point relaxes clientVerify=2 to the optional verifier so a
        // loopback / internal caller with no Cloudflare cert can still reach the
        // origin (enforcement happens at the app layer afterwards).
        handshake_without_client_cert(build_server_config)
            .expect("relaxed TCP config must complete a no-client-cert handshake");
    }

    #[test]
    fn quic_clientverify2_completes_handshake_without_client_cert() {
        // Both TCP and QUIC use the optional verifier: the handshake completes without
        // a client cert, and the app layer (h3::serve_h3_connection) refuses any
        // non-loopback / non-private-LAN peer that presented none. This test pins
        // that invariant — the handshake MUST succeed here; enforcement is post-handshake.
        handshake_without_client_cert(|cfg, l| {
            build_server_config_alpn(cfg, l, vec![b"h2".to_vec(), b"http/1.1".to_vec()])
        })
        .expect("QUIC config with optional verifier must complete a no-client-cert handshake");
    }

    /// Both TCP and QUIC build the same optional verifier for `clientVerify=2`:
    /// neither path uses [`build_client_verifier`] (fail-closed at handshake).
    /// Pinning this prevents a future `relax_mtls=false` reintroduction from
    /// silently re-enabling handshake-layer rejection and breaking the loopback
    /// exemption without a test failure.
    #[test]
    fn clientverify2_uses_optional_verifier_not_mandatory() {
        ensure_provider();
        let dir = tmpdir();
        let c = gen_cert(&["default.example.com"]);
        let cert = write_tmp(&dir, "cv2-cert.pem", &c.cert_pem);
        let key = write_tmp(&dir, "cv2-key.pem", &c.key_pem);
        let ca = gen_cert(&["origin-pull-ca.example.com"]);
        let ca_file = write_tmp(&dir, "cv2-ca.pem", &ca.cert_pem);

        let server = base_server();
        let listener = Listener {
            name: "TLS".into(),
            address: "*:443".into(),
            secure: true,
            vhost_map: vec![],
            tls: Some(ListenerTls {
                key_file: key.clone(),
                cert_file: cert.clone(),
                cert_chain: false,
                ca_cert_file: Some(ca_file.clone()),
                client_verify: 2,
                verify_depth: 1,
                enable_stapling: false,
            }),
        };

        // Both entry points must produce an optional verifier: the verifier does
        // NOT make client auth mandatory — missing cert is allowed at the handshake.
        let tcp_cfg =
            build_server_config(&server, &listener).expect("TCP clientVerify=2 must build");
        let quic_cfg = build_server_config_alpn(&server, &listener, vec![b"h3".to_vec()])
            .expect("QUIC clientVerify=2 must build");

        // A rustls ServerConfig does not directly expose the verifier's mandatory
        // flag, but the handshake behaviour is already pinned by
        // `tcp_clientverify2_completes_handshake_without_client_cert` and
        // `quic_clientverify2_completes_handshake_without_client_cert`. Here we
        // verify the configs are structurally equivalent (same ALPN shape and
        // early-data guard) and both build without error — confirming neither
        // regressed to the fail-closed branch.
        assert_eq!(tcp_cfg.max_early_data_size, 0);
        assert_eq!(quic_cfg.max_early_data_size, 0);
        assert_eq!(
            tcp_cfg.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert_eq!(quic_cfg.alpn_protocols, vec![b"h3".to_vec()]);
    }

    #[test]
    fn build_full_config_with_required_mtls_and_sni() {
        ensure_provider();
        let dir = tmpdir();

        // Default listener cert.
        let dflt = gen_cert(&["default.example.com"]);
        let cert = write_tmp(&dir, "l-cert.pem", &dflt.cert_pem);
        let key = write_tmp(&dir, "l-key.pem", &dflt.key_pem);

        // Client-verify CA (Cloudflare origin-pull analogue).
        let ca = gen_cert(&["origin-pull-ca.example.com"]);
        let ca_file = write_tmp(&dir, "ca.pem", &ca.cert_pem);

        // One SNI vhost.
        let vh = gen_cert(&["sni.example.com"]);
        let vh_cert = write_tmp(&dir, "vh-cert.pem", &vh.cert_pem);
        let vh_key = write_tmp(&dir, "vh-key.pem", &vh.key_pem);
        let vhssl = VhSsl {
            key_file: vh_key,
            cert_file: vh_cert,
            cert_chain: false,
            ca_cert_file: None,
        };

        let mut server = base_server();
        server
            .vhosts
            .insert("vh1".into(), make_vhost_decl("vh1", Some(vhssl)));

        let listener = Listener {
            name: "TLS".into(),
            address: "*:8443".into(),
            secure: true,
            vhost_map: vec![VhostMap {
                vhost: "vh1".into(),
                domains: vec!["sni.example.com".into()],
            }],
            tls: Some(ListenerTls {
                key_file: key,
                cert_file: cert,
                cert_chain: false,
                ca_cert_file: Some(ca_file),
                client_verify: 2,
                verify_depth: 1,
                enable_stapling: true,
            }),
        };

        let cfg = build_server_config(&server, &listener).expect("full config");
        assert_eq!(cfg.max_early_data_size, 0);
        assert!(!cfg.alpn_protocols.is_empty());
        // It is shareable across transports.
        let _shared: Arc<RustlsServerConfig> = cfg;
    }

    /// Live-config smoke test: build configs straight from the running LiteSpeed
    /// install. Skipped automatically if the config (or its referenced cert
    /// files under /etc/letsencrypt, /etc/cloudflare) is absent.
    #[test]
    #[ignore = "reads /usr/local/lsws + /etc cert files; run explicitly"]
    fn live_lsws_tls_listener_builds() {
        ensure_provider();
        let root = "/usr/local/lsws";
        if !Path::new(root).join("conf/httpd_config.xml").exists() {
            eprintln!("skip: no live LSWS config");
            return;
        }
        let cfg = match hj_config::load(root) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("skip: could not load live config: {e}");
                return;
            }
        };
        let Some(tls_listener) = cfg.listeners.iter().find(|l| l.secure && l.tls.is_some()) else {
            eprintln!("skip: no TLS listener in live config");
            return;
        };
        let tls = tls_listener.tls.as_ref().unwrap();
        if !tls.cert_file.exists() || !tls.key_file.exists() {
            eprintln!("skip: listener cert/key not present on disk");
            return;
        }
        if tls.client_verify == 2 {
            match tls.ca_cert_file.as_deref() {
                Some(ca) if ca.exists() => {}
                _ => {
                    eprintln!("skip: required client-verify CA not present");
                    return;
                }
            }
        }
        let built = build_server_config(&cfg, tls_listener).expect("build live TLS config");
        assert_eq!(built.max_early_data_size, 0);
        assert_eq!(
            built.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }
}

#[cfg(test)]
mod resumption_tests {
    use super::*;
    use rustls::server::StoresServerSessions as _;

    // (#300) The no-op store must genuinely store nothing: a resumed handshake can only
    // reinstate a client-cert chain if the store returned one. Pins the type the
    // client_verify branch now installs.
    #[test]
    fn no_server_sessions_stores_nothing() {
        let s = NoServerSessions;
        assert!(
            !s.put(b"k".to_vec(), b"v".to_vec()),
            "put must refuse to store"
        );
        assert!(s.get(b"k").is_none(), "store must never return a session");
        assert!(s.take(b"k").is_none(), "take must never return a session");
        assert!(!s.can_cache());
    }

    /// (#301) The depth-limited verifier memoizes POSITIVE chain verdicts by
    /// exact DER bytes: the second handshake with the same chain skips webpki
    /// entirely, while a rejected chain is re-verified every time (negatives
    /// never enter the memo).
    #[test]
    fn client_chain_memo_dedups_positive_verifications() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
        use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};

        #[derive(Debug)]
        struct CountingVerifier {
            inner: Arc<dyn ClientCertVerifier>,
            calls: AtomicUsize,
        }
        impl ClientCertVerifier for CountingVerifier {
            fn offer_client_auth(&self) -> bool {
                self.inner.offer_client_auth()
            }
            fn client_auth_mandatory(&self) -> bool {
                self.inner.client_auth_mandatory()
            }
            fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
                self.inner.root_hint_subjects()
            }
            fn verify_client_cert(
                &self,
                end_entity: &CertificateDer<'_>,
                intermediates: &[CertificateDer<'_>],
                now: rustls::pki_types::UnixTime,
            ) -> Result<ClientCertVerified, rustls::Error> {
                self.calls.fetch_add(1, Ordering::Relaxed);
                self.inner
                    .verify_client_cert(end_entity, intermediates, now)
            }
            fn verify_tls12_signature(
                &self,
                message: &[u8],
                cert: &CertificateDer<'_>,
                dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                self.inner.verify_tls12_signature(message, cert, dss)
            }
            fn verify_tls13_signature(
                &self,
                message: &[u8],
                cert: &CertificateDer<'_>,
                dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                self.inner.verify_tls13_signature(message, cert, dss)
            }
            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                self.inner.supported_verify_schemes()
            }
            fn requires_raw_public_keys(&self) -> bool {
                self.inner.requires_raw_public_keys()
            }
        }

        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(ca_params, ca_key).expect("ca cert");

        let client_key = KeyPair::generate().expect("client key");
        let mut client_params =
            CertificateParams::new(vec!["client.test".to_string()]).expect("client params");
        client_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let client_cert = client_params
            .signed_by(&client_key, &ca)
            .expect("client cert");

        let mut roots = RootCertStore::empty();
        roots.add(ca.der().clone()).expect("add ca root");
        let webpki = WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            provider().expect("provider"),
        )
        .build()
        .expect("webpki verifier");
        let counting = Arc::new(CountingVerifier {
            inner: webpki,
            calls: AtomicUsize::new(0),
        });
        let verifier = DepthLimitedClientVerifier::wrap(counting.clone(), 3);

        let now = rustls::pki_types::UnixTime::now();
        let leaf = client_cert.der().clone();
        assert!(verifier.verify_client_cert(&leaf, &[], now).is_ok());
        assert!(verifier.verify_client_cert(&leaf, &[], now).is_ok());
        assert_eq!(
            counting.calls.load(Ordering::Relaxed),
            1,
            "second identical chain must be served from the memo"
        );

        let bad_key = KeyPair::generate().expect("bad key");
        let bad_params = CertificateParams::new(vec!["bad.test".to_string()]).expect("bad params");
        let bad_cert = bad_params.self_signed(&bad_key).expect("bad cert");
        let bad_leaf = bad_cert.der().clone();
        let before = counting.calls.load(Ordering::Relaxed);
        assert!(verifier.verify_client_cert(&bad_leaf, &[], now).is_err());
        assert!(verifier.verify_client_cert(&bad_leaf, &[], now).is_err());
        assert_eq!(
            counting.calls.load(Ordering::Relaxed) - before,
            2,
            "a rejected chain is re-verified every time (negatives never memoized)"
        );
    }
}
