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
    // Apache merge order across the chain: directory-level, then `<Files*>`,
    // then `<If>`; chain and source order are kept within a phase.
    let mut staged: Vec<(u8, &super::PhpDirective)> = chain
        .iter()
        .flat_map(|h| &h.php_directives)
        .filter(|pd| crate::directives::scopes_match(&pd.scopes, rel_path, rel_path, basename))
        .map(|pd| (super::scope_merge_phase(&pd.scopes), pd))
        .collect();
    staged.sort_by_key(|(phase, _)| *phase);
    for (_, pd) in staged {
        let admin = pd.kind.is_admin();
        // An admin-locked name can only be changed by another admin directive.
        if let Some((_, _, true)) = map.get(&pd.name) {
            if !admin {
                continue;
            }
        }
        map.insert(pd.name.clone(), (admin, pd.value.clone(), admin));
    }
    // `.htaccess` is per-directory configuration: Apache refuses `php_admin_*`
    // there, so it keeps its locking precedence but never reaches
    // `PHP_INI_SYSTEM` (e.g. `allow_url_include`), only `PHP_INI_PERDIR`.
    map.into_iter()
        .map(|(name, (_, value, _))| ResolvedPhp {
            admin: false,
            name,
            value,
        })
        .collect()
}

/// Decide whether the file the request maps to is FORCED through PHP by a
/// `.htaccess` handler/type directive (`SetHandler`, `ForceType`, `AddHandler`,
/// `AddType`, with `RemoveHandler`/`RemoveType` undoing inherited mappings),
/// independent of its configured script suffixes. Each directive applies only
/// where its enclosing `<Files*>`/`<DirectoryMatch>`/`<If>` scope matches
/// ([`scopes_match`](crate::directives::scopes_match)).
///
/// This is **additive only**: the caller ORs it with the configured-suffix check,
/// so it can turn a non-PHP file *into* a PHP route but can NEVER strip PHP
/// routing from a `.php` file (which would be a source-disclosure regression).
///
/// Fold (Apache mod_mime + core): directives merge in chain order (document root
/// -> deepest dir), directory-level first, then `<Files*>`, then `<If>`; within a
/// phase the later directive wins. The effective handler is the last
/// `SetHandler` (unless reset by `SetHandler None`), else the extension's
/// `AddHandler` mapping, else the content type: `ForceType` over the
/// extension's `AddType` mapping. PHP iff that winner names PHP.
///
/// `rel_path` is the request/script URL path and `basename` the file's name (used
/// for `<Files*>` scoping and to derive the extension). Callers gate this on
/// [`Htaccess::has_handler_override`](super::Htaccess) so it is never reached on
/// the common no-override path.
pub fn php_handler_forced(chain: &[Arc<Htaccess>], rel_path: &str, basename: &str) -> bool {
    php_handler_forced_iter(chain.iter().map(AsRef::as_ref), rel_path, basename)
}

/// Iterator form used by callers that already retain directory metadata beside
/// each parsed file. It avoids building a second `Vec<Arc<Htaccess>>` merely to
/// ask the same handler-routing question.
pub fn php_handler_forced_iter<'a>(
    chain: impl IntoIterator<Item = &'a Htaccess>,
    rel_path: &str,
    basename: &str,
) -> bool {
    use super::HandlerOpKind as K;
    let ext = basename
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase());
    let has_ext = |exts: &[String]| ext.as_ref().is_some_and(|x| exts.iter().any(|e| e == x));
    let mut ops: Vec<(u8, &super::HandlerOp)> = Vec::new();
    for h in chain {
        for op in &h.handler_ops {
            let relevant = match &op.kind {
                K::SetHandler(_) | K::ForceType(_) => true,
                K::AddHandler { exts, .. }
                | K::AddType { exts, .. }
                | K::RemoveHandler(exts)
                | K::RemoveType(exts) => has_ext(exts),
            };
            if relevant && crate::directives::scopes_match(&op.scopes, rel_path, rel_path, basename)
            {
                ops.push((super::scope_merge_phase(&op.scopes), op));
            }
        }
    }
    // Stable: chain and source order are kept within each merge phase.
    ops.sort_by_key(|(phase, _)| *phase);
    let (mut set, mut by_ext, mut force, mut by_type) = (None, None, None, None);
    for (_, op) in ops {
        match &op.kind {
            K::SetHandler(v) => set = *v,
            K::ForceType(v) => force = v.as_ref().map(|ty| ty.php),
            K::AddHandler { php, .. } => by_ext = Some(*php),
            K::AddType { ty, .. } => by_type = Some(ty.php),
            K::RemoveHandler(_) => by_ext = None,
            K::RemoveType(_) => by_type = None,
        }
    }
    set.or(by_ext).or(force).or(by_type).unwrap_or(false)
}

/// The `Content-Type` an `.htaccess` `ForceType`/`AddType` gives the file
/// `basename` (at `rel_path`, for section scoping), folded in the same Apache
/// merge order as [`php_handler_forced_iter`]: `ForceType` over the extension's
/// `AddType` mapping, `ForceType None`/`RemoveType` undoing inherited ones.
/// `None` when no mapping applies or the winner names PHP (a routing choice,
/// never a static content type). Only the final extension is mapped, as the
/// server's own MIME table does.
pub fn content_type_override<'a>(
    chain: impl IntoIterator<Item = &'a Htaccess>,
    rel_path: &str,
    basename: &str,
) -> Option<String> {
    use super::HandlerOpKind as K;
    let ext = basename
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase());
    let has_ext = |exts: &[String]| ext.as_ref().is_some_and(|x| exts.iter().any(|e| e == x));
    let mut ops: Vec<(u8, &super::HandlerOp)> = Vec::new();
    for h in chain {
        for op in &h.handler_ops {
            let relevant = match &op.kind {
                K::ForceType(_) => true,
                K::AddType { exts, .. } | K::RemoveType(exts) => has_ext(exts),
                _ => false,
            };
            if relevant && crate::directives::scopes_match(&op.scopes, rel_path, rel_path, basename)
            {
                ops.push((super::scope_merge_phase(&op.scopes), op));
            }
        }
    }
    ops.sort_by_key(|(phase, _)| *phase);
    let (mut force, mut by_type) = (None, None);
    for (_, op) in ops {
        match &op.kind {
            K::ForceType(ty) => force = ty.as_ref(),
            K::AddType { ty, .. } => by_type = Some(ty),
            K::RemoveType(_) => by_type = None,
            _ => {}
        }
    }
    force
        .or(by_type)
        .filter(|ty| !ty.php)
        .map(|ty| ty.mime.clone())
}

/// The chain's `SetEnv`/`UnsetEnv` assignments for a request whose sections
/// are matched against `rel_path`/`basename` (`<If>` against the
/// slash-preserving `request_path`), in Apache merge order (directory
/// level, then `<Files*>`, then `<If>`; chain then source order within a phase).
/// An unset is encoded as `("!VAR", "")` like `SetEnvIf` output — decode with
/// [`EnvAssignment::classify`](crate::EnvAssignment::classify).
pub fn set_env_assignments<'a>(
    chain: impl IntoIterator<Item = &'a Htaccess>,
    rel_path: &str,
    request_path: &str,
    basename: &str,
) -> Vec<(String, String)> {
    let mut staged: Vec<(u8, &super::EnvDirective)> = chain
        .into_iter()
        .flat_map(|h| &h.set_env)
        .filter(|d| crate::directives::scopes_match(&d.scopes, rel_path, request_path, basename))
        .map(|d| (super::scope_merge_phase(&d.scopes), d))
        .collect();
    staged.sort_by_key(|(phase, _)| *phase);
    staged
        .into_iter()
        .map(|(_, d)| match &d.value {
            Some(value) => (d.name.clone(), value.clone()),
            None => (format!("!{}", d.name), String::new()),
        })
        .collect()
}

/// The effective `AddDefaultCharset` charset for `rel_path`/`basename` (`None`
/// = Off or never set), last wins in Apache merge order.
pub fn default_charset<'a>(
    chain: impl IntoIterator<Item = &'a Htaccess>,
    rel_path: &str,
    basename: &str,
) -> Option<String> {
    let mut staged: Vec<(u8, &super::CharsetDirective)> = chain
        .into_iter()
        .flat_map(|h| &h.default_charset)
        .filter(|d| crate::directives::scopes_match(&d.scopes, rel_path, rel_path, basename))
        .map(|d| (super::scope_merge_phase(&d.scopes), d))
        .collect();
    staged.sort_by_key(|(phase, _)| *phase);
    staged.last().and_then(|(_, d)| d.charset.clone())
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
    fn htaccess_php_admin_value_never_reaches_system_level() {
        let h = Arc::new(
            Htaccess::parse("php_admin_value allow_url_include 1\nphp_admin_flag engine off")
                .unwrap(),
        );
        let r = php_directives(&[h], ANY.0, ANY.1);
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|d| !d.admin), "{r:?}");
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
                admin: false,
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
                admin: false,
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
    fn deeper_set_handler_default_cancels_a_shallower_force() {
        // docroot forces .html via AddHandler; a deeper dir resets the handler.
        let chain = [
            parse("AddHandler application/x-httpd-php .html"),
            parse("<Files \"safe.html\">\n  SetHandler default-handler\n</Files>"),
        ];
        assert!(php_handler_forced(&chain, "/page.html", "page.html"));
        assert!(!php_handler_forced(&chain, "/safe.html", "safe.html"));
    }

    #[test]
    fn set_handler_none_only_clears_set_handler() {
        // Apache core: `SetHandler None` removes an earlier SetHandler; the
        // extension mapping then applies again.
        let chain = [
            parse("AddHandler application/x-httpd-php .html\nSetHandler default-handler"),
            parse("SetHandler None"),
        ];
        assert!(php_handler_forced(&chain, "/a.html", "a.html"));
        assert!(!php_handler_forced(&chain, "/a.txt", "a.txt"));
    }

    #[test]
    fn force_type_php_forces_extensionless_files() {
        // #850: `<Files api> ForceType application/x-httpd-php </Files>`.
        let chain = [parse(
            "<Files api>\n  ForceType application/x-httpd-php\n</Files>",
        )];
        assert!(php_handler_forced(&chain, "/api", "api"));
        assert!(!php_handler_forced(&chain, "/other", "other"));
        // Directory-wide ForceType forces every file; a deeper `ForceType None`
        // or non-PHP type undoes it.
        let chain = [parse("ForceType application/x-httpd-php")];
        assert!(php_handler_forced(&chain, "/x.txt", "x.txt"));
        for reset in ["ForceType None", "ForceType text/plain"] {
            let chain = [parse("ForceType application/x-httpd-php"), parse(reset)];
            assert!(!php_handler_forced(&chain, "/x.txt", "x.txt"), "{reset}");
        }
        // An AddHandler mapping outranks the content type.
        let chain = [parse(
            "ForceType text/plain\nAddHandler application/x-httpd-php .inc",
        )];
        assert!(php_handler_forced(&chain, "/x.inc", "x.inc"));
    }

    #[test]
    fn quoted_set_handler_forces_php() {
        // #851.
        let chain = [parse("SetHandler \"application/x-httpd-php\"")];
        assert!(php_handler_forced(&chain, "/x.html", "x.html"));
        let chain = [parse(
            "<FilesMatch \"\\.tpl$\">\n  SetHandler 'application/x-httpd-php'\n</FilesMatch>",
        )];
        // Single quotes are not Apache quoting: the literal value names PHP
        // anyway, and PHP is the fail-closed answer.
        assert!(php_handler_forced(&chain, "/x.tpl", "x.tpl"));
    }

    #[test]
    fn remove_handler_and_type_undo_inherited_php_mapping() {
        // #853: uploads/.htaccess under a docroot PHP mapping for .html.
        for (root, child) in [
            (
                "AddHandler application/x-httpd-php .html",
                "RemoveHandler .html",
            ),
            ("AddType application/x-httpd-php .html", "RemoveType .html"),
            (
                "AddHandler application/x-httpd-php .html",
                "AddHandler default-handler .html",
            ),
            (
                "AddType application/x-httpd-php .html",
                "AddType text/html .html",
            ),
        ] {
            let chain = [parse(root), parse(child)];
            assert!(
                !php_handler_forced(&chain, "/uploads/evil.html", "evil.html"),
                "{root} / {child}"
            );
            // The parent directory keeps its mapping.
            assert!(php_handler_forced(&chain[..1], "/a.html", "a.html"));
            // Other extensions are untouched by the removal.
            let chain = [parse(&format!("{root} .htm")), parse(child)];
            assert!(php_handler_forced(&chain, "/uploads/x.htm", "x.htm"));
        }
        // A RemoveType does not undo an AddHandler (separate mod_mime tables).
        let chain = [
            parse("AddHandler application/x-httpd-php .html"),
            parse("RemoveType .html"),
        ];
        assert!(php_handler_forced(&chain, "/u/x.html", "x.html"));
        // A deeper re-add wins again (chain order).
        let chain = [
            parse("AddHandler application/x-httpd-php .html"),
            parse("RemoveHandler .html"),
            parse("AddHandler application/x-httpd-php .html"),
        ];
        assert!(php_handler_forced(&chain, "/u/v/x.html", "x.html"));
    }

    #[test]
    fn files_section_merges_after_directory_level() {
        // Apache merges <Files*> after every directory-level directive, so a
        // parent's Files-scoped SetHandler outranks a child's top-level reset.
        let chain = [
            parse("<Files \"x.html\">\n  SetHandler application/x-httpd-php\n</Files>"),
            parse("SetHandler default-handler"),
        ];
        assert!(php_handler_forced(&chain, "/sub/x.html", "x.html"));
        assert!(!php_handler_forced(&chain, "/sub/y.html", "y.html"));
    }

    /// #909: php_value merges directory-level, then `<Files*>`, then `<If>`.
    #[test]
    fn php_value_applies_in_apache_merge_order() {
        let chain = [parse(
            "<Files x.php>\n  php_value memory_limit files\n</Files>\n\
             php_value memory_limit dir",
        )];
        assert_eq!(php_directives(&chain, "/x.php", "x.php")[0].value, "files");
        assert_eq!(php_directives(&chain, "/y.php", "y.php")[0].value, "dir");
        let chain = [
            parse("<Files x.php>\n  php_value memory_limit parent-files\n</Files>"),
            parse("php_value memory_limit child-dir"),
        ];
        assert_eq!(
            php_directives(&chain, "/sub/x.php", "x.php")[0].value,
            "parent-files"
        );
        // An admin lock still holds against a later-merged plain value.
        let chain = [parse(
            "<Files x.php>\n  php_value open_basedir /\n</Files>\n\
             php_admin_value open_basedir /safe",
        )];
        assert_eq!(php_directives(&chain, "/x.php", "x.php")[0].value, "/safe");
    }

    /// #911: AddType/ForceType MIME mappings for static files.
    #[test]
    fn content_type_override_follows_mod_mime() {
        let ct = |chain: &[Arc<Htaccess>], rel: &str, base: &str| {
            content_type_override(chain.iter().map(AsRef::as_ref), rel, base)
        };
        let root = parse("AddType application/manifest+json .webmanifest\nAddType video/webm webm");
        assert_eq!(
            ct(&[root.clone()], "/site.webmanifest", "site.webmanifest").as_deref(),
            Some("application/manifest+json")
        );
        assert_eq!(
            ct(&[root.clone()], "/a/CLIP.WEBM", "CLIP.WEBM").as_deref(),
            Some("video/webm")
        );
        assert_eq!(ct(&[root.clone()], "/x.css", "x.css"), None);
        // A deeper RemoveType / AddType re-maps; PHP types are routing, not MIME.
        let child = parse("RemoveType .webm");
        assert_eq!(ct(&[root.clone(), child], "/a/x.webm", "x.webm"), None);
        let php = parse("AddType application/x-httpd-php .webm");
        assert_eq!(ct(&[root.clone(), php], "/a/x.webm", "x.webm"), None);
        // ForceType outranks the extension mapping; `ForceType None` clears it.
        let force = parse("<Files feed>\n  ForceType application/rss+xml\n</Files>");
        assert_eq!(
            ct(&[force.clone()], "/feed", "feed").as_deref(),
            Some("application/rss+xml")
        );
        assert_eq!(ct(&[force.clone()], "/other", "other"), None);
        let all = parse("ForceType text/plain");
        assert_eq!(
            ct(&[root.clone(), all.clone()], "/x.webm", "x.webm").as_deref(),
            Some("text/plain")
        );
        assert_eq!(
            ct(&[root, all, parse("ForceType None")], "/x.webm", "x.webm").as_deref(),
            Some("video/webm")
        );
        // The MIME form never opens the PHP-forcing gate.
        assert!(!parse("ForceType text/plain").has_handler_override);
        assert!(parse("ForceType text/plain").has_type_override);
        assert!(!parse("AddType application/x-httpd-php .x").has_type_override);
    }

    /// #911: SetEnv/UnsetEnv in merge order; AddDefaultCharset On/charset/Off.
    #[test]
    fn set_env_and_default_charset_fold_across_the_chain() {
        let chain = [
            parse("SetEnv FOO bar\nSetEnv EMPTY\nSetEnv QUOTED \"a b\"\nSetEnv GONE 1"),
            parse("<Files x.txt>\n  SetEnv FOO files\n</Files>\nUnsetEnv GONE OTHER"),
        ];
        let got = set_env_assignments(
            chain.iter().map(AsRef::as_ref),
            "/s/x.txt",
            "/s/x.txt",
            "x.txt",
        );
        assert_eq!(
            got,
            vec![
                ("FOO".to_string(), "bar".to_string()),
                ("EMPTY".to_string(), String::new()),
                ("QUOTED".to_string(), "a b".to_string()),
                ("GONE".to_string(), "1".to_string()),
                ("!GONE".to_string(), String::new()),
                ("!OTHER".to_string(), String::new()),
                ("FOO".to_string(), "files".to_string()),
            ]
        );
        let cs = |chain: &[Arc<Htaccess>]| {
            default_charset(chain.iter().map(AsRef::as_ref), "/x.html", "x.html")
        };
        assert_eq!(
            cs(&[parse("AddDefaultCharset On")]).as_deref(),
            Some("ISO-8859-1")
        );
        assert_eq!(
            cs(&[parse("AddDefaultCharset UTF-8")]).as_deref(),
            Some("UTF-8")
        );
        assert_eq!(
            cs(&[
                parse("AddDefaultCharset UTF-8"),
                parse("AddDefaultCharset Off")
            ]),
            None
        );
        assert_eq!(cs(&[parse("Header set X 1")]), None);
    }

    #[test]
    fn no_directive_never_forces() {
        let chain = [parse("php_value auto_prepend_file \"/web/pagecache.php\"")];
        assert!(!php_handler_forced(&chain, "/x.html", "x.html"));
        assert!(!php_handler_forced(&chain, "/x.php", "x.php"));
        assert!(!php_handler_forced(&[], "/x.html", "x.html"));
    }
}
