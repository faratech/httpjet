use super::*;

fn valid_authority(value: &str) -> bool {
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let Some((host, tail)) = rest.split_once(']') else {
            return false;
        };
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        if tail.is_empty() {
            return true;
        }
        let Some(port) = tail.strip_prefix(':') else {
            return false;
        };
        (host, Some(port))
    } else {
        let (host, port) = value
            .split_once(':')
            .map_or((value, None), |(h, p)| (h, Some(p)));
        if host.is_empty()
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        {
            return false;
        }
        (host, port)
    };
    !host.is_empty()
        && port.is_none_or(|p| {
            !p.is_empty()
                && p.bytes().all(|b| b.is_ascii_digit())
                && p.parse::<u16>().is_ok_and(|p| p > 0)
        })
}

pub(super) fn parse(e: &RawExtProcessor, path: &Path) -> Result<LoadBalanceConfig> {
    let invalid = |directive, value: String, reason: &str| ConfigError::InvalidValue {
        path: path.to_path_buf(),
        directive,
        value,
        reason: reason.into(),
    };
    let specified =
        e.load_balance_policy.is_some() || e.address_weights.is_some() || e.health_check.is_some();
    if specified {
        let mut scheme = None;
        for address in &e.address {
            let address = address.trim();
            let unix = address.starts_with("uds://");
            let (protocol, authority) = address.split_once("://").unwrap_or(("http", address));
            let protocol = if protocol == "uds" { "http" } else { protocol };
            if !matches!(protocol, "http" | "https" | "h2" | "h2s")
                || authority.is_empty()
                || (!unix && !valid_authority(authority))
                || authority
                    .bytes()
                    .any(|b| b <= 0x20 || b == b'@' || b == b'?' || b == b'#')
                || (address.contains("://")
                    && !address.starts_with("uds://")
                    && !address.starts_with("UDS://")
                    && authority.contains('/'))
            {
                return Err(invalid(
                    "address",
                    address.into(),
                    "group addresses require an authority or Unix socket, not credentials/path/query",
                ));
            }
            if scheme.is_some_and(|s| s != protocol) {
                return Err(invalid(
                    "address",
                    address.into(),
                    "all peers in a group must use the same protocol",
                ));
            }
            scheme = Some(protocol);
        }
    }
    if specified
        && (e.kind.as_deref().is_some_and(|v| v.trim() != "proxy")
            || e.name.as_deref().is_none_or(|v| v.trim().is_empty())
            || e.address.is_empty())
    {
        return Err(invalid(
            "loadBalancePolicy",
            String::new(),
            "requires a named proxy with at least one address",
        ));
    }
    let policy = match e
        .load_balance_policy
        .as_deref()
        .map(str::trim)
        .unwrap_or("primary-first")
    {
        "primary-first" => LoadBalancePolicy::PrimaryFirst,
        "weighted-round-robin" => LoadBalancePolicy::WeightedRoundRobin,
        "weighted-least-active" => LoadBalancePolicy::WeightedLeastActive,
        other => return Err(invalid("loadBalancePolicy", other.into(), "unknown policy")),
    };
    let weights = match &e.address_weights {
        None => Vec::new(),
        Some(value) => {
            let weights: Vec<u16> = value
                .split(',')
                .map(|s| {
                    s.trim()
                        .parse::<u16>()
                        .ok()
                        .filter(|n| (1..=1000).contains(n))
                        .ok_or_else(|| {
                            invalid(
                                "addressWeights",
                                value.clone(),
                                "weights must be integers in 1..=1000",
                            )
                        })
                })
                .collect::<Result<_>>()?;
            if weights.len() != e.address.len() {
                return Err(invalid(
                    "addressWeights",
                    value.clone(),
                    "one weight is required per address",
                ));
            }
            weights
        }
    };
    let health_check = e
        .health_check
        .as_ref()
        .map(|h| {
            let number = |v: &Option<String>, default: u32, max: u32| -> Result<u32> {
                match v {
                    None => Ok(default),
                    Some(s) => s
                        .trim()
                        .parse::<u32>()
                        .ok()
                        .filter(|n| *n > 0 && *n <= max)
                        .ok_or_else(|| {
                            invalid(
                                "healthCheck",
                                s.clone(),
                                "invalid positive integer or out of range",
                            )
                        }),
                }
            };
            let mode = h.mode.as_deref().unwrap_or("connect").trim().to_owned();
            if !matches!(mode.as_str(), "connect" | "GET" | "HEAD") {
                return Err(invalid(
                    "healthCheck",
                    mode,
                    "mode must be connect, GET or HEAD",
                ));
            }
            let interval = Duration::from_secs(u64::from(number(&h.interval, 10, 3600)?));
            let timeout = Duration::from_secs(u64::from(number(&h.timeout, 2, 3600)?));
            if timeout > interval {
                return Err(invalid(
                    "healthCheck",
                    String::new(),
                    "timeout exceeds interval",
                ));
            }
            let path = h.path.clone().unwrap_or_else(|| "/".into());
            if !path.starts_with('/')
                || path.starts_with("//")
                || path.bytes().any(|b| b <= 0x20 || b >= 0x7f || b == b'#')
            {
                return Err(invalid(
                    "healthCheck",
                    path,
                    "path must be an ASCII origin-form request target",
                ));
            }
            if h.host.as_ref().is_some_and(|s| {
                !valid_authority(s)
                    || s.bytes().any(|b| {
                        b <= 0x20 || b >= 0x7f || matches!(b, b'/' | b'\\' | b'@' | b'#' | b'?')
                    })
            }) {
                return Err(invalid(
                    "healthCheck",
                    String::new(),
                    "invalid Host override",
                ));
            }
            let expected_status = number(&h.expected_status, 200, 599)? as u16;
            if expected_status < 200 {
                return Err(invalid(
                    "healthCheck",
                    expected_status.to_string(),
                    "expectedStatus must be 200..599",
                ));
            }
            Ok(HealthCheckConfig {
                mode,
                interval,
                timeout,
                rise: number(&h.rise, 2, 100)?,
                fall: number(&h.fall, 3, 100)?,
                path,
                host: h.host.clone(),
                expected_status,
            })
        })
        .transpose()?;
    Ok(LoadBalanceConfig {
        policy,
        weights,
        health_check,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse_xml(extra: &str, kind: &str) -> Result<LoadBalanceConfig> {
        let e: RawExtProcessor = quick_xml::de::from_str(&format!(
            "<extProcessor><name>backend</name><type>{kind}</type><address>127.0.0.1:1</address><address>127.0.0.1:2</address>{extra}</extProcessor>"
        )).unwrap();
        parse(&e, Path::new("test.xml"))
    }
    #[test]
    fn validates_authority_ports_and_ipv6() {
        for value in ["localhost", "api.internal:8080", "[::1]:443"] {
            assert!(valid_authority(value));
        }
        for value in [
            "",
            "localhost:",
            "localhost:0",
            "localhost:65536",
            "localhost:abc",
            "[broken]:80",
            "user@host",
            "host\\name",
        ] {
            assert!(!valid_authority(value));
        }
    }

    #[test]
    fn rejects_mixed_protocol_and_credential_group_addresses() {
        for second in [
            "https://localhost:2",
            "http://user@localhost:2",
            "http://localhost:2/path",
            "ftp://localhost:2",
        ] {
            let e: RawExtProcessor = quick_xml::de::from_str(&format!("<extProcessor><name>backend</name><type>proxy</type><address>http://localhost:1</address><address>{second}</address><loadBalancePolicy>weighted-round-robin</loadBalancePolicy></extProcessor>")).unwrap();
            assert!(parse(&e, Path::new("test.xml")).is_err());
        }
    }

    #[test]
    fn defaults_and_weighted_policies() {
        assert_eq!(
            parse_xml("", "proxy").unwrap(),
            LoadBalanceConfig::default()
        );
        for policy in [
            "primary-first",
            "weighted-round-robin",
            "weighted-least-active",
        ] {
            assert_eq!(parse_xml(&format!("<loadBalancePolicy>{policy}</loadBalancePolicy><addressWeights>2,1</addressWeights>"), "proxy").unwrap().weights, vec![2,1]);
        }
    }
    #[test]
    fn rejects_invalid_or_non_proxy_options() {
        for extra in [
            "<loadBalancePolicy>random</loadBalancePolicy>",
            "<addressWeights>1</addressWeights>",
            "<addressWeights>0,1</addressWeights>",
            "<addressWeights>1001,1</addressWeights>",
            "<addressWeights>1,</addressWeights>",
        ] {
            assert!(parse_xml(extra, "proxy").is_err());
        }
        assert!(
            parse_xml(
                "<loadBalancePolicy>primary-first</loadBalancePolicy>",
                "lsapi"
            )
            .is_err()
        );
    }

    #[test]
    fn health_defaults_and_validation() {
        let h = parse_xml("<healthCheck/>", "proxy")
            .unwrap()
            .health_check
            .unwrap();
        assert_eq!(
            (
                h.interval.as_secs(),
                h.timeout.as_secs(),
                h.rise,
                h.fall,
                h.expected_status
            ),
            (10, 2, 2, 3, 200)
        );
        for field in [
            "<mode>POST</mode>",
            "<timeout>11</timeout>",
            "<rise>0</rise>",
            "<path>https://evil.test/</path>",
            "<path>//evil.test/</path>",
            "<host>bad host</host>",
            "<expectedStatus>101</expectedStatus>",
        ] {
            assert!(
                parse_xml(&format!("<healthCheck>{field}</healthCheck>"), "proxy").is_err(),
                "{field}"
            );
        }
        assert!(parse_xml("<healthCheck/>", "lsapi").is_err());
    }
}
