//! `$VAR` substitution for LiteSpeed config values.
//!
//! Supported variables: `$SERVER_ROOT`, `$VH_NAME`, `$VH_ROOT`, `$HOSTNAME`.
//! Both `$VAR` and `${VAR}` forms are accepted.

#[derive(Debug, Clone, Default)]
pub(crate) struct SubstCtx {
    pub(crate) server_root: String,
    pub(crate) vh_name: String,
    pub(crate) vh_root: String,
    pub(crate) hostname: String,
}

impl SubstCtx {
    pub(crate) fn expand(&self, input: &str) -> String {
        // Order longest-first so `$SERVER_ROOT` isn't partially matched.
        let vars: [(&str, &str); 4] = [
            ("SERVER_ROOT", &self.server_root),
            ("HOSTNAME", &self.hostname),
            ("VH_ROOT", &self.vh_root),
            ("VH_NAME", &self.vh_name),
        ];
        let mut out = String::with_capacity(input.len());
        let bytes = input.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'$' {
                let rest = &input[i + 1..];
                let (name_span, after) = if rest.starts_with('{') {
                    match rest.find('}') {
                        Some(end) => (&rest[1..end], i + 1 + end + 1),
                        None => (rest, input.len()),
                    }
                } else {
                    let end = rest
                        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                        .unwrap_or(rest.len());
                    (&rest[..end], i + 1 + end)
                };
                if let Some((_, val)) = vars.iter().find(|(n, _)| *n == name_span) {
                    out.push_str(val);
                    i = after;
                    continue;
                }
            }
            // copy this char
            let ch_len = utf8_len(bytes[i]);
            out.push_str(&input[i..i + ch_len]);
            i += ch_len;
        }
        out
    }
}

fn utf8_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b >> 5 == 0b110 {
        2
    } else if b >> 4 == 0b1110 {
        3
    } else {
        4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_known_vars() {
        let ctx = SubstCtx {
            server_root: "/usr/local/lsws".into(),
            vh_name: "tenant.example".into(),
            vh_root: "/srv/www/tenant".into(),
            hostname: "host1".into(),
        };
        assert_eq!(
            ctx.expand("$SERVER_ROOT/conf/vhosts/$VH_NAME.xml"),
            "/usr/local/lsws/conf/vhosts/tenant.example.xml"
        );
        assert_eq!(ctx.expand("${VH_ROOT}/html"), "/srv/www/tenant/html");
        assert_eq!(ctx.expand("no vars here"), "no vars here");
        assert_eq!(ctx.expand("$UNKNOWN/x"), "$UNKNOWN/x");
    }
}
