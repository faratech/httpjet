//! Provider-neutral DNS-01, with an explicitly scoped webhook adapter.
use crate::{Directory, Domain};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt, time::Duration};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsError;
impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DNS challenge provider operation failed")
    }
}
impl std::error::Error for DnsError {}

#[derive(Clone)]
pub struct DnsScope {
    zones: BTreeSet<Domain>,
}
impl DnsScope {
    pub fn new(zones: &[&str]) -> Result<Self, DnsError> {
        if zones.is_empty() || zones.len() > 16 {
            return Err(DnsError);
        }
        let zones = zones
            .iter()
            .map(|s| Domain::parse(s).map_err(|_| DnsError))
            .collect::<Result<BTreeSet<_>, _>>()?;
        Ok(Self { zones })
    }
    pub fn permits(&self, domain: &Domain) -> bool {
        let base = domain.dns_base();
        self.zones.iter().any(|zone| {
            base == zone.as_str()
                || base
                    .strip_suffix(zone.as_str())
                    .is_some_and(|prefix| prefix.ends_with('.'))
        })
    }
    pub fn identity(&self) -> String {
        self.zones
            .iter()
            .map(Domain::as_str)
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Exact TXT value ownership: cleanup MUST NOT delete another value in the RRset.
/// This contains public challenge material only, never provider credentials.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DnsRecord {
    name: String,
    value: String,
}
impl DnsRecord {
    pub(crate) fn new(domain: &Domain, value: String) -> Result<Self, DnsError> {
        if domain.dns_base().len() + "_acme-challenge.".len() > 253
            || value.len() != 43
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(DnsError);
        }
        Ok(Self {
            name: format!("_acme-challenge.{}", domain.dns_base()),
            value,
        })
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn value(&self) -> &str {
        &self.value
    }
    pub(crate) fn domain(&self) -> Result<Domain, DnsError> {
        Domain::parse(self.name.strip_prefix("_acme-challenge.").ok_or(DnsError)?)
            .map_err(|_| DnsError)
    }
    pub(crate) fn valid_for(&self, scope: &DnsScope) -> bool {
        self.domain()
            .is_ok_and(|d| scope.permits(&d) && Self::new(&d, self.value.clone()).is_ok())
    }
}

/// Credentials remain encapsulated by the provider, never in ACME snapshots.
/// Operations must be idempotent, propagate errors, and preserve unrelated TXT
/// values. The manager adds deadlines, durable cleanup intent and scope checks.
#[async_trait::async_trait]
pub trait DnsProvider: Send + Sync {
    fn scope(&self) -> &DnsScope;
    /// Stable non-secret adapter identity; changing it invalidates stored cleanup.
    fn identity(&self) -> String;
    async fn present(&self, record: &DnsRecord) -> Result<(), DnsError>;
    async fn ready(&self, record: &DnsRecord) -> Result<bool, DnsError>;
    async fn cleanup(&self, record: &DnsRecord) -> Result<(), DnsError>;
}

/// POSTs a small JSON protocol to an operator-managed DNS controller. The bearer
/// credential is scoped to this endpoint (no redirects or environment proxies).
/// Adapter operators are responsible for minimum DNS-provider zone privileges.
pub struct WebhookDnsProvider {
    endpoint: Directory,
    scope: DnsScope,
    bearer: Option<String>,
    client: reqwest::Client,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    ok: bool,
    #[serde(default)]
    ready: bool,
}
impl WebhookDnsProvider {
    /// HTTPS and a bearer token are mandatory unless the endpoint is explicitly
    /// test-mode literal-loopback HTTP. Optional test roots never disable TLS.
    pub fn new(
        endpoint: Directory,
        scope: DnsScope,
        bearer: Option<String>,
        test_root: Option<&[u8]>,
    ) -> Result<Self, DnsError> {
        if bearer.as_ref().is_some_and(|b| {
            b.len() < 16 || b.len() > 4096 || !b.bytes().all(|c| c.is_ascii_graphic())
        }) || (endpoint.uri().scheme_str() == Some("https") && bearer.is_none())
        {
            return Err(DnsError);
        }
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(5))
            .pool_max_idle_per_host(1);
        if let Some(root) = test_root {
            if root.len() > 65536 {
                return Err(DnsError);
            }
            builder = builder
                .tls_certs_only([reqwest::Certificate::from_pem(root).map_err(|_| DnsError)?]);
        }
        Ok(Self {
            endpoint,
            scope,
            bearer,
            client: builder.build().map_err(|_| DnsError)?,
        })
    }
    async fn call(&self, operation: &str, record: &DnsRecord) -> Result<Reply, DnsError> {
        if !record.valid_for(&self.scope) {
            return Err(DnsError);
        }
        let body = serde_json::to_vec(&serde_json::json!({"version": 1, "operation": operation, "name": record.name, "value": record.value})).map_err(|_| DnsError)?;
        let mut request = self
            .client
            .post(self.endpoint.uri().to_string())
            .header("content-type", "application/json")
            .body(body);
        if let Some(bearer) = &self.bearer {
            request = request.bearer_auth(bearer);
        }
        let mut response = request.send().await.map_err(|_| DnsError)?;
        if !response.status().is_success() || response.content_length().is_some_and(|n| n > 16384) {
            return Err(DnsError);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| DnsError)? {
            if chunk.len() > 16384 - bytes.len() {
                return Err(DnsError);
            }
            bytes.extend_from_slice(&chunk);
        }
        let reply: Reply = serde_json::from_slice(&bytes).map_err(|_| DnsError)?;
        if !reply.ok {
            return Err(DnsError);
        }
        Ok(reply)
    }
}
#[async_trait::async_trait]
impl DnsProvider for WebhookDnsProvider {
    fn scope(&self) -> &DnsScope {
        &self.scope
    }
    fn identity(&self) -> String {
        format!("webhook:{}:{}", self.endpoint.uri(), self.scope.identity())
    }
    async fn present(&self, record: &DnsRecord) -> Result<(), DnsError> {
        self.call("present", record).await.map(|_| ())
    }
    async fn ready(&self, record: &DnsRecord) -> Result<bool, DnsError> {
        self.call("ready", record).await.map(|r| r.ready)
    }
    async fn cleanup(&self, record: &DnsRecord) -> Result<(), DnsError> {
        self.call("cleanup", record).await.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scopes_are_dns_boundaries_and_wildcards_do_not_broaden_them() {
        let scope = DnsScope::new(&["example.test"]).unwrap();
        for good in ["example.test", "a.example.test", "*.example.test"] {
            assert!(scope.permits(&Domain::parse_dns01(good).unwrap()));
        }
        for bad in ["example.test.evil", "notexample.test", "other.test"] {
            assert!(!scope.permits(&Domain::parse_dns01(bad).unwrap()));
        }
        assert!(Domain::parse("*.example.test").is_err());
        assert!(Domain::parse_dns01("*.*.example.test").is_err());
        assert!(Domain::parse_dns01("foo*.example.test").is_err());
        let record = DnsRecord::new(
            &Domain::parse_dns01("*.example.test").unwrap(),
            "A".repeat(43),
        )
        .unwrap();
        assert_eq!(record.name(), "_acme-challenge.example.test");
        assert!(record.valid_for(&scope));
    }

    #[tokio::test]
    async fn webhook_rejects_out_of_scope_and_oversized_or_redirected_replies() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for response in [
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/leak\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 16385\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n{\"ok\":false}",
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = Directory::parse(
                &format!("http://{}/dns", listener.local_addr().unwrap()),
                true,
            )
            .unwrap();
            let provider = WebhookDnsProvider::new(
                endpoint,
                DnsScope::new(&["example.test"]).unwrap(),
                Some("fixture-credential-only".into()),
                None,
            )
            .unwrap();
            let bad =
                DnsRecord::new(&Domain::parse("other.test").unwrap(), "A".repeat(43)).unwrap();
            assert_eq!(provider.present(&bad).await, Err(DnsError));
            assert!(
                tokio::time::timeout(Duration::from_millis(10), listener.accept())
                    .await
                    .is_err()
            );
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                let n = socket.read(&mut request).await.unwrap();
                assert!(n > 0);
                socket.write_all(response.as_bytes()).await.unwrap();
            });
            let record =
                DnsRecord::new(&Domain::parse("example.test").unwrap(), "A".repeat(43)).unwrap();
            assert_eq!(provider.present(&record).await, Err(DnsError));
            server.await.unwrap();
        }
    }
}
