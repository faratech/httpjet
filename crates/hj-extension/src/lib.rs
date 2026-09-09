//! Compile-time extension registry for httpjet.
//!
//! Extensions are ordinary Rust crates linked into the server binary. The
//! registry deliberately provides no native dynamic ABI: Rust trait-object ABI
//! stability, allocator ownership, and panic isolation cannot be promised
//! safely across independently built shared objects.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use hj_core::{HandlerError, ReqCtx, Request, Response, ResponseTransform};

/// Read-only request view passed to a pre-handler extension.
///
/// The body and mutable request parts are intentionally not exposed. A hook can
/// observe the resolved request identity and either continue or produce a
/// response, but cannot consume a streaming body, rewrite routing inputs, or
/// invalidate cache/security decisions made by the host.
#[derive(Clone, Copy)]
pub struct RequestView<'a> {
    request: &'a Request,
}

impl<'a> RequestView<'a> {
    pub fn new(request: &'a Request) -> Self {
        Self { request }
    }

    pub fn method(&self) -> &http::Method {
        self.request.method()
    }

    pub fn uri(&self) -> &http::Uri {
        self.request.uri()
    }

    pub fn headers(&self) -> &http::HeaderMap {
        self.request.headers()
    }
}

/// Result of a pre-handler extension.
pub enum PreHandlerDecision {
    /// Continue to the next extension and then the built-in dispatch pipeline.
    Continue,
    /// Stop before rewrite, cache lookup, or a terminal backend and use this
    /// response. The host still applies post-handler transforms and logging.
    Respond(Response),
}

/// Read-only hook after routing/trust/access checks and before dispatch.
#[async_trait]
pub trait PreHandler: Send + Sync {
    async fn handle(
        &self,
        ctx: &ReqCtx,
        request: RequestView<'_>,
    ) -> Result<PreHandlerDecision, HandlerError>;
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RegisterError {
    #[error(
        "invalid extension name {0:?}; use 1-64 lowercase ASCII letters, digits, '.', '-' or '_'"
    )]
    InvalidName(String),
    #[error("duplicate extension registration name {0:?}")]
    DuplicateName(String),
}

struct NamedPreHandler {
    name: &'static str,
    handler: Arc<dyn PreHandler>,
}

struct NamedResponseTransform {
    name: &'static str,
    transform: Arc<dyn ResponseTransform>,
}

/// Deterministically ordered registry assembled by the binary at compile time.
/// Registration order is execution order.
#[derive(Default)]
pub struct ExtensionRegistry {
    names: HashSet<&'static str>,
    pre_handlers: Vec<NamedPreHandler>,
    response_transforms: Vec<NamedResponseTransform>,
}

impl ExtensionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_pre_handler(
        &mut self,
        name: &'static str,
        handler: Arc<dyn PreHandler>,
    ) -> Result<(), RegisterError> {
        self.reserve_name(name)?;
        self.pre_handlers.push(NamedPreHandler { name, handler });
        Ok(())
    }

    pub fn register_response_transform(
        &mut self,
        name: &'static str,
        transform: Arc<dyn ResponseTransform>,
    ) -> Result<(), RegisterError> {
        self.reserve_name(name)?;
        self.response_transforms
            .push(NamedResponseTransform { name, transform });
        Ok(())
    }

    fn reserve_name(&mut self, name: &'static str) -> Result<(), RegisterError> {
        if !valid_name(name) {
            return Err(RegisterError::InvalidName(name.to_string()));
        }
        if !self.names.insert(name) {
            return Err(RegisterError::DuplicateName(name.to_string()));
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    pub fn has_pre_handlers(&self) -> bool {
        !self.pre_handlers.is_empty()
    }

    pub fn registrations(&self) -> impl Iterator<Item = (&'static str, &'static str)> + '_ {
        self.pre_handlers
            .iter()
            .map(|entry| (entry.name, "pre-handler"))
            .chain(
                self.response_transforms
                    .iter()
                    .map(|entry| (entry.name, "response-transform")),
            )
    }

    pub async fn run_pre_handlers(
        &self,
        ctx: &ReqCtx,
        request: &Request,
    ) -> Result<PreHandlerDecision, ExtensionError> {
        for entry in &self.pre_handlers {
            match entry.handler.handle(ctx, RequestView::new(request)).await {
                Ok(PreHandlerDecision::Continue) => {}
                Ok(PreHandlerDecision::Respond(response)) => {
                    return Ok(PreHandlerDecision::Respond(response));
                }
                Err(source) => {
                    return Err(ExtensionError {
                        name: entry.name,
                        source,
                    });
                }
            }
        }
        Ok(PreHandlerDecision::Continue)
    }

    pub async fn run_response_transforms(&self, ctx: &ReqCtx, response: &mut Response) {
        for entry in &self.response_transforms {
            entry.transform.transform(ctx, response).await;
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("extension {name:?} failed: {source}")]
pub struct ExtensionError {
    pub name: &'static str,
    #[source]
    pub source: HandlerError,
}

impl ExtensionError {
    pub fn status(&self) -> http::StatusCode {
        self.source.status()
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-_".contains(&byte)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MarkerTransform;

    #[async_trait]
    impl ResponseTransform for MarkerTransform {
        async fn transform(&self, _ctx: &ReqCtx, response: &mut Response) {
            response.headers_mut().insert(
                "x-extension-test",
                http::HeaderValue::from_static("present"),
            );
        }
    }

    #[test]
    fn registration_names_are_bounded_and_unique_across_hook_kinds() {
        let mut registry = ExtensionRegistry::new();
        registry
            .register_response_transform("example.marker", Arc::new(MarkerTransform))
            .unwrap();
        assert!(matches!(
            registry.register_response_transform("example.marker", Arc::new(MarkerTransform)),
            Err(RegisterError::DuplicateName(_))
        ));
        assert!(matches!(
            registry.register_response_transform("Bad Name", Arc::new(MarkerTransform)),
            Err(RegisterError::InvalidName(_))
        ));
    }
}
