use crate::{LogLevel, json_escape};
use std::{
    fmt::Write as _,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::field::{Field, Visit};

fn sensitive(name: &str) -> bool {
    let n = name.to_ascii_lowercase().replace(['_', '-'], "");
    [
        "authorization",
        "cookie",
        "password",
        "passwd",
        "secret",
        "token",
        "apikey",
        "privatekey",
        "clientkey",
        "signingkey",
        "accesskey",
        "credential",
    ]
    .iter()
    .any(|s| n.contains(s))
        || n == "key"
}

fn redact(name: &str, value: &str, cap: usize) -> String {
    if value.len() > 32768 {
        return "[OVERSIZED]".into();
    }
    // Free-form diagnostics cannot reliably separate a secret from its surrounding
    // text. Suppress the entire value when common credential syntax is present.
    let lower = value.to_ascii_lowercase();
    if sensitive(name)
        || lower
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(sensitive)
        || [
            "authorization:",
            "bearer ",
            "basic ",
            "password=",
            "password:",
            "token=",
            "secret=",
            "api_key=",
            "apikey=",
            "cookie:",
            "-----begin private key",
        ]
        .iter()
        .any(|s| lower.contains(s))
        || value.contains("://") && (value.contains('@') || value.contains('?'))
    {
        return "[REDACTED]".into();
    }
    value.chars().take(cap).collect()
}

pub(crate) fn render(
    level: LogLevel,
    ts: SystemTime,
    target: Option<&str>,
    message: &str,
    fields: &[(String, String)],
) -> String {
    let q = |s: &str| format!("\"{}\"", json_escape(s));
    let values = fields
        .iter()
        .take(32)
        .map(|(k, v)| {
            format!(
                "{}:{}",
                q(&k.chars().take(128).collect::<String>()),
                q(&redact(k, v, 1024))
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"schema_version\":1,\"timestamp_unix_ms\":{},\"level\":{},\"target\":{},\"message\":{},\"fields\":{{{}}}}}",
        ts.duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
        q(level.as_str()),
        target
            .map(|s| q(&redact("target", s, 256)))
            .unwrap_or_else(|| "null".into()),
        q(&redact("message", message, 8192)),
        values
    )
}

#[derive(Default)]
pub(crate) struct Collector {
    pub message: String,
    pub fields: Vec<(String, String)>,
}
impl Collector {
    fn add(&mut self, name: &str, value: &str) {
        if name == "message" {
            self.message = redact(name, value, 8192);
        } else if self.fields.len() < 32 {
            self.fields.push((name.into(), redact(name, value, 1024)));
        }
    }
}
impl Visit for Collector {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if sensitive(field.name()) {
            self.add(field.name(), "[REDACTED]");
            return;
        }
        // Bound formatting itself, not only the serialized result.
        struct Buffer(String);
        impl std::fmt::Write for Buffer {
            fn write_str(&mut self, s: &str) -> std::fmt::Result {
                if self.0.len() + s.len() > 32768 {
                    return Err(std::fmt::Error);
                }
                self.0.push_str(s);
                Ok(())
            }
        }
        let mut b = Buffer(String::new());
        if write!(&mut b, "{value:?}").is_err() {
            self.add(field.name(), "[OVERSIZED]");
        } else {
            self.add(field.name(), &b.0);
        }
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.add(field.name(), value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn escapes_and_redacts_without_changing_field_boundaries() {
        let fields = vec![
            ("authorization".into(), "Bearer hidden".into()),
            ("detail".into(), "https://user:pass@host/".into()),
            ("code".into(), "502".into()),
        ];
        let line = render(
            LogLevel::Error,
            UNIX_EPOCH,
            Some("proxy"),
            "bad\n\"value\"",
            &fields,
        );
        assert!(line.contains("\"timestamp_unix_ms\":0"));
        assert!(line.contains("bad\\n\\\"value\\\""));
        assert!(line.contains("\"code\":\"502\""));
        assert!(!line.contains("hidden") && !line.contains("user:pass"));
        assert!(!line.contains('\n'));
        for value in [
            "Authorization: Basic abc",
            "password=hunter2",
            "https://host/?secret=abc",
            "Cookie: sid=abc",
            "{\"password\":\"hidden\"}",
            "token = hidden",
        ] {
            assert_eq!(redact("message", value, 8192), "[REDACTED]");
        }
    }
    #[tokio::test]
    async fn writer_json_mode_preserves_one_event_per_line() {
        let path = std::env::temp_dir().join(format!("hj-json-errors-{}.log", std::process::id()));
        let logger =
            crate::ErrorLogger::spawn_with_format(&path, 0, 0, false, crate::ErrorLogFormat::Json);
        logger.log_at(LogLevel::Error, UNIX_EPOCH, "line\none");
        logger.log_at(LogLevel::Warn, UNIX_EPOCH, "token=hidden");
        logger.shutdown().await;
        let content = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(content.lines().count(), 2);
        assert!(content.contains("line\\none"));
        assert!(!content.contains("hidden"));
    }
}
