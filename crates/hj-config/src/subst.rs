//! `$VAR` substitution for LiteSpeed config values.
//!
//! Supported variables: `$SERVER_ROOT`, `$VH_NAME`, `$VH_ROOT`, `$HOSTNAME`,
//! plus `$DOC_ROOT` / `$VH_DOMAIN` once the vhost has resolved them. Both
//! `$VAR` and `${VAR}` forms are accepted; names match case-insensitively
//! (OLS `ConfigCtx::expandVariable` uses `strncasecmp`).

#[derive(Debug, Clone, Default)]
pub(crate) struct SubstCtx {
    pub(crate) server_root: String,
    pub(crate) vh_name: String,
    pub(crate) vh_root: String,
    pub(crate) hostname: String,
    /// Empty until the vhost's `<docRoot>` is parsed; an unset value leaves
    /// `$DOC_ROOT` literal.
    pub(crate) doc_root: String,
    /// `<vhDomain>` (default: the vhost name); empty leaves `$VH_DOMAIN` literal.
    pub(crate) vh_domain: String,
}

impl SubstCtx {
    pub(crate) fn expand(&self, input: &str) -> String {
        if !input.contains('$') {
            return input.to_string();
        }
        let mut vars: Vec<(&str, &str)> = vec![
            ("SERVER_ROOT", &self.server_root),
            ("HOSTNAME", &self.hostname),
            ("VH_ROOT", &self.vh_root),
            ("VH_NAME", &self.vh_name),
        ];
        if !self.doc_root.is_empty() {
            vars.push(("DOC_ROOT", &self.doc_root));
        }
        if !self.vh_domain.is_empty() {
            vars.push(("VH_DOMAIN", &self.vh_domain));
        }
        let mut out = String::with_capacity(input.len());
        let bytes = input.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'$' {
                let rest = &input[i + 1..];
                let hit = if rest.starts_with('{') {
                    rest.find('}').and_then(|end| {
                        let name = &rest[1..end];
                        vars.iter()
                            .find(|(n, _)| n.eq_ignore_ascii_case(name))
                            .map(|(_, v)| (*v, i + 1 + end + 1))
                    })
                } else {
                    // OLS matches the bare form as a case-insensitive PREFIX
                    // (configctx.cpp strncasecmp): `$VH_NAME_lsphp` is `<name>_lsphp`
                    // (#937).
                    vars.iter()
                        .find(|(n, _)| {
                            rest.get(..n.len())
                                .is_some_and(|head| head.eq_ignore_ascii_case(n))
                        })
                        .map(|(n, v)| (*v, i + 1 + n.len()))
                };
                if let Some((val, after)) = hit {
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
            ..Default::default()
        };
        assert_eq!(
            ctx.expand("$SERVER_ROOT/conf/vhosts/$VH_NAME.xml"),
            "/usr/local/lsws/conf/vhosts/tenant.example.xml"
        );
        assert_eq!(ctx.expand("${VH_ROOT}/html"), "/srv/www/tenant/html");
        assert_eq!(ctx.expand("no vars here"), "no vars here");
        assert_eq!(ctx.expand("$UNKNOWN/x"), "$UNKNOWN/x");
        // #937: the bare form is a prefix match, as in OLS.
        assert_eq!(
            ctx.expand("uds://tmp/lshttpd/$VH_NAME_lsphp.sock"),
            "uds://tmp/lshttpd/tenant.example_lsphp.sock"
        );
        assert_eq!(ctx.expand("$http_upgrade"), "$http_upgrade");
    }

    /// #920: variable names are case-insensitive; DOC_ROOT/VH_DOMAIN expand once set.
    #[test]
    fn expands_case_insensitively_and_doc_root_once_known() {
        let mut ctx = SubstCtx {
            vh_root: "/srv/t".into(),
            ..Default::default()
        };
        assert_eq!(ctx.expand("$vh_root/a"), "/srv/t/a");
        assert_eq!(ctx.expand("${Vh_Root}/a"), "/srv/t/a");
        assert_eq!(ctx.expand("$DOC_ROOT/a"), "$DOC_ROOT/a");
        ctx.doc_root = "/srv/t/html".into();
        ctx.vh_domain = "t.example".into();
        assert_eq!(ctx.expand("$doc_root/a"), "/srv/t/html/a");
        assert_eq!(ctx.expand("$VH_DOMAIN.log"), "t.example.log");
    }
}
