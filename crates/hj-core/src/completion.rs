//! Optional response-lifetime notification, independent of any telemetry SDK.
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseEnd {
    Complete,
    Error,
    Cancelled,
}

type Callback = Box<dyn FnOnce(ResponseEnd) + Send + 'static>;
struct Inner(Mutex<Option<Callback>>);
impl Drop for Inner {
    fn drop(&mut self) {
        if let Some(callback) = self.0.get_mut().unwrap().take() {
            callback(ResponseEnd::Cancelled);
        }
    }
}

/// An optional response extension. Transport ownership lasts through the final
/// write/flush, not merely body collection. Clones share exactly one notification;
/// dropping the last unfinished clone reports cancellation. Callbacks must be
/// nonblocking and must not panic. No allocation occurs unless explicitly created.
#[derive(Clone)]
pub struct ResponseCompletion(Arc<Inner>);
impl ResponseCompletion {
    pub fn new(callback: impl FnOnce(ResponseEnd) + Send + 'static) -> Self {
        Self(Arc::new(Inner(Mutex::new(Some(Box::new(callback))))))
    }
    pub fn finish(self, end: ResponseEnd) {
        let callback = self.0.0.lock().unwrap().take();
        if let Some(callback) = callback {
            callback(end);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clones_notify_exactly_once_and_last_drop_cancels() {
        for explicit in [false, true] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let copy = events.clone();
            let completion = ResponseCompletion::new(move |end| copy.lock().unwrap().push(end));
            let other = completion.clone();
            if explicit {
                completion.finish(ResponseEnd::Complete);
            } else {
                drop(completion);
                assert!(events.lock().unwrap().is_empty());
            }
            drop(other);
            assert_eq!(
                *events.lock().unwrap(),
                vec![if explicit {
                    ResponseEnd::Complete
                } else {
                    ResponseEnd::Cancelled
                }]
            );
        }
    }
}
