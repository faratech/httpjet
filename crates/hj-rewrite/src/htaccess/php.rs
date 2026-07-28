//! Resolve the `.htaccess` PHP-ini directive chain into the effective set that
//! is passed to lsphp via the LSAPI *special-env* section.
//!
//! Apache/LiteSpeed precedence: walking the chain from the document root to the
//! deepest directory, a `php_admin_value`/`php_admin_flag` **locks** its setting
//! name — a later `php_value`/`php_flag` cannot override it — while a plain
//! `php_value`/`php_flag` in a deeper directory overrides a shallower one.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::Htaccess;

/// One resolved PHP-ini setting. `admin` selects the lsphp permission level:
/// `true` ⇒ `PHP_INI_SYSTEM` (`php_admin_*`), `false` ⇒ `PHP_INI_PERDIR`
/// (`php_value`/`php_flag`, which PHP refuses to use for stronger settings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPhp {
    pub admin: bool,
    pub name: String,
    pub value: String,
}

/// Fold a `.htaccess` chain (document root → deepest dir) into the effective
/// PHP-ini settings, honoring the admin-locks precedence above. Empty when no
/// `php_value`-family directive appears anywhere in the chain (the common case,
/// so the LSAPI special-env table stays empty and the request is byte-identical
/// to today).
///
/// `rel_path` is the request path and `basename` the resolved script's filename
/// (e.g. `index.php` for a DirectoryIndex hit) — used to honor each directive's
/// enclosing `<Files*>`/`<DirectoryMatch>`/`<If>` scope, so a `php_value` inside
/// `<Files "crontab.html">` does not leak onto sibling scripts.
pub fn php_directives(chain: &[Arc<Htaccess>], rel_path: &str, basename: &str) -> Vec<ResolvedPhp> {
    // name -> (admin, value, locked-by-admin). BTreeMap for deterministic order.
    let mut map: BTreeMap<String, (bool, String, bool)> = BTreeMap::new();
    for h in chain {
        for pd in &h.php_directives {
            if !crate::directives::scopes_match(&pd.scopes, rel_path, basename) {
                continue;
            }
            let admin = pd.kind.is_admin();
            // An admin-locked name can only be changed by another admin directive.
            if let Some((_, _, true)) = map.get(&pd.name) {
                if !admin {
                    continue;
                }
            }
            map.insert(pd.name.clone(), (admin, pd.value.clone(), admin));
        }
    }
    map.into_iter()
        .map(|(name, (admin, value, _))| ResolvedPhp { admin, name, value })
        .collect()
}

/// Decide whether the file the request maps to is FORCED through PHP by a
/// `.htaccess` handler-override directive (`SetHandler`/`AddHandler`/`AddType`),
/// independent of its extension. Folds the chain (document root → deepest dir),
/// honoring each directive's enclosing `<Files*>`/`<DirectoryMatch>`/`<If>` scope
/// via [`scopes_match`](crate::directives::scopes_match) — exactly as
/// [`php_directives`] does — so a `<Files "crontab.html">` override applies only to
/// that file.
///
/// This is **additive only**: the caller ORs it with the extension-based PHP check,
/// so it can turn a non-PHP file *into* a PHP route but can NEVER strip PHP routing
/// from a `.php` file (which would be a source-disclosure regression).
///
/// `SetHandler` is authoritative when any in-scope one is present (last wins), so a
/// deeper `SetHandler none` cancels a shallower `SetHandler application/x-httpd-php`
/// or `AddHandler` force; otherwise an in-scope `AddHandler`/`AddType` whose
/// extension list contains the file's extension forces PHP.
///
/// `rel_path` is the request/script URL path and `basename` the file's name (used
/// for `<Files*>` scoping and to derive the extension for the `AddHandler`/`AddType`
/// match). Callers gate this on [`Htaccess::has_handler_override`](super::Htaccess)
/// so it is never reached on the common no-override path.
pub fn php_handler_forced(chain: &[Arc<Htaccess>], rel_path: &str, basename: &str) -> bool {
    let ext = basename
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase());
    let mut set: Option<bool> = None;
    let mut added = false;
    for h in chain {
        for d in &h.set_handlers {
            if crate::directives::scopes_match(&d.scopes, rel_path, basename) {
                set = Some(d.php);
            }
        }
        if let Some(ext) = &ext {
            for a in &h.add_php_exts {
                if a.exts.iter().any(|e| e == ext)
                    && crate::directives::scopes_match(&a.scopes, rel_path, basename)
                {
                    added = true;
                }
            }
        }
    }
    set.unwrap_or(added)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::htaccess::{PhpDirective, PhpDirectiveKind};

    fn ht(dirs: Vec<PhpDirective>) -> Arc<Htaccess> {
        Arc::new(Htaccess {
            php_directives: dirs,
            ..Default::default()
        })
    }
    fn pd(kind: PhpDirectiveKind, name: &str, value: &str) -> PhpDirective {
        PhpDirective {
            kind,
            name: name.into(),
            value: value.into(),
            scopes: vec![],
        }
    }
    // A directory-wide request path/basename: every `None`-scoped directive applies.
    const ANY: (&str, &str) = ("/x.php", "x.php");

    #[test]
    fn deeper_php_value_overrides_shallower() {
        let chain = vec![
            ht(vec![pd(
                PhpDirectiveKind::Value,
                "auto_prepend_file",
                "/root.php",
            )]),
            ht(vec![pd(
                PhpDirectiveKind::Value,
                "auto_prepend_file",
                "/deep.php",
            )]),
        ];
        let r = php_directives(&chain, ANY.0, ANY.1);
        assert_eq!(
            r,
            vec![ResolvedPhp {
                admin: false,
                name: "auto_prepend_file".into(),
                value: "/deep.php".into()
            }]
        );
    }

    #[test]
    fn admin_locks_against_later_value() {
        // php_admin_value in a shallow dir cannot be overridden by a deeper php_value.
        let chain = vec![
            ht(vec![pd(
                PhpDirectiveKind::AdminValue,
                "open_basedir",
                "/safe",
            )]),
            ht(vec![pd(PhpDirectiveKind::Value, "open_basedir", "/")]),
        ];
        let r = php_directives(&chain, ANY.0, ANY.1);
        assert_eq!(
            r,
            vec![ResolvedPhp {
                admin: true,
                name: "open_basedir".into(),
                value: "/safe".into()
            }]
        );
    }

    #[test]
    fn admin_overrides_admin_and_value() {
        let chain = vec![
            ht(vec![pd(PhpDirectiveKind::Value, "memory_limit", "64M")]),
            ht(vec![pd(
                PhpDirectiveKind::AdminValue,
                "memory_limit",
                "128M",
            )]),
            ht(vec![pd(
                PhpDirectiveKind::AdminValue,
                "memory_limit",
                "256M",
            )]),
        ];
        let r = php_directives(&chain, ANY.0, ANY.1);
        assert_eq!(
            r,
            vec![ResolvedPhp {
                admin: true,
                name: "memory_limit".into(),
                value: "256M".into()
            }]
        );
    }

    #[test]
    fn empty_chain_is_empty() {
        assert!(php_directives(&[], ANY.0, ANY.1).is_empty());
        assert!(php_directives(&[ht(vec![])], ANY.0, ANY.1).is_empty());
    }

    #[test]
    fn files_scoped_php_value_does_not_leak_to_siblings() {
        // The exact prod shape that 500'd `/admin/compression/`: a global
        // `auto_prepend_file` (the pagecache fast-path), plus a `<Files>`-scoped
        // override meant only for `crontab.html`. The override must NOT leak onto
        // sibling scripts (else they `require 'none'` and lsphp fatals).
        let root = Arc::new(
            Htaccess::parse("php_value auto_prepend_file \"/web/pagecache.php\"").unwrap(),
        );
        let admin = Arc::new(
            Htaccess::parse(
                "<Files \"crontab.html\">\n  php_value auto_prepend_file \"none\"\n</Files>",
            )
            .unwrap(),
        );
        let chain = [root, admin];

        // index.php (a DirectoryIndex hit) is not crontab.html -> inherits the
        // global prepend, NOT "none".
        let idx = php_directives(&chain, "/admin/compression/", "index.php");
        assert_eq!(
            idx,
            vec![ResolvedPhp {
                admin: false,
                name: "auto_prepend_file".into(),
                value: "/web/pagecache.php".into()
            }]
        );

        // crontab.html IS the scoped target -> the override applies to it.
        let cron = php_directives(&chain, "/admin/crontab.html", "crontab.html");
        assert_eq!(
            cron,
            vec![ResolvedPhp {
                admin: false,
                name: "auto_prepend_file".into(),
                value: "none".into()
            }]
        );
    }

    #[test]
    fn nested_if_files_scope_honors_the_outer_if() {
        // `<If %{REQUEST_URI} ~ ^/admin> <Files "x.php"> php_value ... </Files> </If>`
        // The override must apply ONLY when BOTH the outer `<If>` (URI under /admin)
        // AND the inner `<Files>` (basename x.php) match — the old innermost-only
        // scope silently dropped the `<If>` and leaked the override to /public/x.php.
        let root = Arc::new(
            Htaccess::parse("php_value auto_prepend_file \"/web/pagecache.php\"").unwrap(),
        );
        let scoped = Arc::new(
            Htaccess::parse(
                "<If \"%{REQUEST_URI} =~ m#^/admin#\">\n  \
                 <Files \"x.php\">\n    php_value auto_prepend_file \"none\"\n  \
                 </Files>\n</If>",
            )
            .unwrap(),
        );
        let chain = [root, scoped];

        // Under /admin AND basename x.php -> both scopes match -> override applies.
        let admin = php_directives(&chain, "/admin/x.php", "x.php");
        assert_eq!(
            admin,
            vec![ResolvedPhp {
                admin: false,
                name: "auto_prepend_file".into(),
                value: "none".into(),
            }]
        );

        // Same basename x.php but NOT under /admin -> the outer `<If>` fails the
        // conjunction -> the override must NOT apply (inherits the global prepend).
        let public = php_directives(&chain, "/public/x.php", "x.php");
        assert_eq!(
            public,
            vec![ResolvedPhp {
                admin: false,
                name: "auto_prepend_file".into(),
                value: "/web/pagecache.php".into(),
            }]
        );
    }

    #[test]
    fn nested_directorymatch_files_scope_requires_both() {
        // `<DirectoryMatch ^/admin> <Files "x.php"> ... </Files> </DirectoryMatch>`
        // requires BOTH the path (DirectoryMatch vs rel_path) and the basename
        // (Files) to match.
        let h = Arc::new(
            Htaccess::parse(
                "<DirectoryMatch \"^/admin\">\n  \
                 <Files \"x.php\">\n    php_value memory_limit \"256M\"\n  \
                 </Files>\n</DirectoryMatch>",
            )
            .unwrap(),
        );
        let chain = [h];

        // path matches AND basename matches -> applies.
        assert_eq!(
            php_directives(&chain, "/admin/x.php", "x.php"),
            vec![ResolvedPhp {
                admin: false,
                name: "memory_limit".into(),
                value: "256M".into()
            }]
        );
        // basename matches but path does not -> does NOT apply.
        assert!(php_directives(&chain, "/public/x.php", "x.php").is_empty());
        // path matches but basename does not -> does NOT apply.
        assert!(php_directives(&chain, "/admin/y.php", "y.php").is_empty());
    }

    // -- php_handler_forced (SetHandler / AddHandler / AddType) --------------

    fn parse(text: &str) -> Arc<Htaccess> {
        Arc::new(Htaccess::parse(text).unwrap())
    }

    #[test]
    fn files_scoped_set_handler_forces_only_the_named_file() {
        // The exact bug shape: `<Files "crontab.html"> SetHandler …php …</Files>`.
        let chain = [parse(
            "<Files \"crontab.html\">\n  SetHandler application/x-httpd-php\n</Files>",
        )];
        assert!(php_handler_forced(
            &chain,
            "/admin/crontab.html",
            "crontab.html"
        ));
        // A sibling .html in the same dir is NOT in scope -> not forced.
        assert!(!php_handler_forced(
            &chain,
            "/admin/other.html",
            "other.html"
        ));
    }

    #[test]
    fn filesmatch_forces_all_matching() {
        let chain = [parse(
            "<FilesMatch \"\\.html$\">\n  SetHandler application/x-httpd-php\n</FilesMatch>",
        )];
        assert!(php_handler_forced(&chain, "/a.html", "a.html"));
        assert!(php_handler_forced(&chain, "/deep/b.html", "b.html"));
        assert!(!php_handler_forced(&chain, "/a.txt", "a.txt"));
    }

    #[test]
    fn add_handler_and_add_type_force_by_extension_directory_wide() {
        for directive in [
            "AddHandler application/x-httpd-php .html .htm",
            "AddType application/x-httpd-php .html .htm",
        ] {
            let chain = [parse(directive)];
            assert!(
                php_handler_forced(&chain, "/x.html", "x.html"),
                "{directive} should force .html"
            );
            assert!(
                php_handler_forced(&chain, "/sub/y.htm", "y.htm"),
                "{directive} should force .htm in a subdir (chain carries parent dir)"
            );
            assert!(
                !php_handler_forced(&chain, "/x.css", "x.css"),
                "{directive} must not force a non-listed extension"
            );
        }
    }

    #[test]
    fn non_php_add_type_is_ignored() {
        let chain = [parse("AddType text/html .shtml")];
        assert!(!php_handler_forced(&chain, "/x.shtml", "x.shtml"));
    }

    #[test]
    fn deeper_set_handler_none_cancels_a_shallower_force() {
        // docroot forces .html via AddHandler; a deeper dir resets the handler.
        let chain = [
            parse("AddHandler application/x-httpd-php .html"),
            parse("<Files \"safe.html\">\n  SetHandler none\n</Files>"),
        ];
        assert!(php_handler_forced(&chain, "/page.html", "page.html"));
        assert!(!php_handler_forced(&chain, "/safe.html", "safe.html"));
    }

    #[test]
    fn no_directive_never_forces() {
        let chain = [parse("php_value auto_prepend_file \"/web/pagecache.php\"")];
        assert!(!php_handler_forced(&chain, "/x.html", "x.html"));
        assert!(!php_handler_forced(&chain, "/x.php", "x.php"));
        assert!(!php_handler_forced(&[], "/x.html", "x.html"));
    }
}
