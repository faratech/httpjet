//! Scoped authentication configuration. Metadata inherits independently; an
//! explicit Require group replaces the inherited group, never unions siblings.

use super::{AccessMatcher, Htaccess};
use crate::auth::AuthRealm;
use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub(crate) struct AuthGroup {
    pub scope_id: usize,
    pub matchers: Vec<AccessMatcher>,
    pub invalid_scope: bool,
    pub auth_type: Option<String>,
    pub realm: Option<String>,
    pub user_file: Option<PathBuf>,
    pub require: Option<AuthRequirement>,
}

#[derive(Debug, Clone)]
pub(crate) enum AuthRequirement {
    Granted,
    Denied,
    Users {
        valid_user: bool,
        users: Vec<String>,
    },
}

/// Parsed configuration, not a resolved directory-wide realm. Call
/// [`resolve_auth`] with the complete parent-to-child chain and resource path.
#[derive(Debug, Default)]
pub struct AuthPolicy {
    pub(crate) groups: Vec<AuthGroup>,
    pub(crate) sensitive: bool,
}

/// Missing/unsupported configuration for an active authorization requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidAuth;

#[derive(Default, Clone)]
struct EffectiveAuth {
    auth_type: Option<String>,
    realm: Option<String>,
    user_file: Option<PathBuf>,
    require: Option<AuthRequirement>,
    invalid_scope: bool,
}

impl EffectiveAuth {
    fn merge(&mut self, group: &AuthGroup) {
        if let Some(v) = &group.auth_type {
            self.auth_type = Some(v.clone());
        }
        if let Some(v) = &group.realm {
            self.realm = Some(v.clone());
        }
        if let Some(v) = &group.user_file {
            self.user_file = Some(v.clone());
        }
        if let Some(v) = &group.require {
            self.require = Some(v.clone());
        }
        self.invalid_scope |= group.invalid_scope;
    }

    fn finish(self) -> Result<Option<AuthRealm>, InvalidAuth> {
        if self.invalid_scope {
            return Err(InvalidAuth);
        }
        match self.require {
            None | Some(AuthRequirement::Granted) => Ok(None),
            Some(AuthRequirement::Denied) => Err(InvalidAuth),
            Some(AuthRequirement::Users { valid_user, users }) => {
                if !self
                    .auth_type
                    .as_deref()
                    .is_some_and(|v| v.eq_ignore_ascii_case("basic"))
                {
                    return Err(InvalidAuth);
                }
                let user_file = self
                    .user_file
                    .filter(|p| !p.as_os_str().is_empty())
                    .ok_or(InvalidAuth)?;
                let realm = self.realm.unwrap_or_else(|| "Restricted".into());
                if realm.bytes().any(|b| b < 0x20 || b == 0x7f) {
                    return Err(InvalidAuth);
                }
                Ok(Some(AuthRealm {
                    realm,
                    user_file,
                    require_valid_user: valid_user,
                    require_users: users,
                }))
            }
        }
    }
}

/// Resolve auth on a normalized docroot-relative resource path. Files patterns
/// see its basename; Directory/If see the same path as the access-control layer.
pub fn resolve_auth<'a>(
    chain: impl IntoIterator<Item = &'a Htaccess>,
    resource_path: &str,
) -> Result<Option<AuthRealm>, InvalidAuth> {
    resolve_auth_for_request(chain, resource_path, resource_path, None)
}

/// As resolve_auth, but preserves REQUEST_URI while Files/Directory match the
/// mapped resource. Required for mixed If + Files scopes on index/PATH_INFO.
/// Directory patterns also see the mapped filesystem path when supplied;
/// docroot-relative patterns remain supported for existing configurations.
pub fn resolve_auth_for_request<'a>(
    chain: impl IntoIterator<Item = &'a Htaccess>,
    resource_path: &str,
    request_path: &str,
    filesystem_path: Option<&str>,
) -> Result<Option<AuthRealm>, InvalidAuth> {
    let basename = resource_path.rsplit('/').next().unwrap_or("");
    let mut effective = EffectiveAuth::default();
    for ht in chain {
        if let Some(policy) = &ht.auth {
            for group in &policy.groups {
                // Check both polarities: a regex evaluation error must never
                // make a grant apply or silently remove a restriction.
                let matches_at = |m: &AccessMatcher, on_error| {
                    if matches!(m, AccessMatcher::Path(_)) {
                        return m.matches(resource_path, basename, on_error)
                            || filesystem_path
                                .is_some_and(|path| m.matches(path, basename, on_error));
                    }
                    let path = match m {
                        AccessMatcher::IfUri { .. } | AccessMatcher::IfUriExpr(_) => request_path,
                        _ => resource_path,
                    };
                    m.matches(path, basename, on_error)
                };
                let matches = group.matchers.iter().all(|m| matches_at(m, true));
                if !matches {
                    continue;
                }
                if group.invalid_scope {
                    return Err(InvalidAuth);
                }
                if !group.matchers.iter().all(|m| matches_at(m, false)) {
                    return Err(InvalidAuth);
                }
                // Matching sections merge in configuration order. Only an
                // explicit Require replaces requirements; metadata-only
                // siblings must not erase a previously selected restriction.
                effective.merge(group);
            }
        }
    }
    effective.finish()
}

impl Htaccess {
    /// Whether this file contains authentication directives (including
    /// incomplete/unsupported ones). Used to conservatively bypass fast paths.
    pub fn has_auth(&self) -> bool {
        self.auth.as_ref().is_some_and(|p| p.sensitive)
    }

    /// Conservative configuration-only lint. Only directory-wide metadata is
    /// guaranteed to apply to a scoped group; matching sibling metadata is not
    /// assumed when lint cannot establish a concrete request path.
    pub fn auth_warnings(&self) -> Vec<usize> {
        let Some(policy) = &self.auth else {
            return Vec::new();
        };
        if !policy.sensitive {
            return Vec::new();
        }
        let mut directory = EffectiveAuth::default();
        let mut warnings = Vec::new();
        for group in &policy.groups {
            if group.scope_id == 0 {
                directory.merge(group);
            }
            let mut effective = directory.clone();
            effective.merge(group);
            // Matching cannot be established during lint, so only flag definite
            // invalid scopes and incomplete groups with no usable Basic metadata.
            if group.invalid_scope
                || (matches!(group.require, Some(AuthRequirement::Users { .. }))
                    && (!effective
                        .auth_type
                        .as_deref()
                        .is_some_and(|v| v.eq_ignore_ascii_case("basic"))
                        || effective
                            .user_file
                            .as_ref()
                            .is_none_or(|p| p.as_os_str().is_empty())))
                || matches!(group.require, Some(AuthRequirement::Denied))
            {
                warnings.push(group.scope_id.max(1));
            }
        }
        warnings
    }
}
