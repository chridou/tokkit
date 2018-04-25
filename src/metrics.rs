use std::time::Instant;

/// Collects metrics for token introspection
pub trait MetricsCollector {
    /// An incoming request for token introspection
    fn incoming_introspection_request(&self);
    /// The token introspections was called regardless of the result.
    fn introspection_service_called(&self, request_started: Instant);
    /// The token introspections was called and the call was a failure.
    fn introspection_service_called_and_failed(&self, request_started: Instant);
    /// The token introspections was called and the call was a success.
    fn introspection_service_called_successfully(&self, request_started: Instant);
    /// The complete introspection workflow was finished regardless of the
    /// result.
    fn introspection_request(&self, request_started: Instant);
    /// The complete introspection workflow was finished and successful
    fn introspection_request_successful(&self, request_started: Instant);
    /// The complete introspection workflow was finished and failed
    fn introspection_request_failed(&self, request_started: Instant);
}

pub struct DevNullMetricsCollector;

impl MetricsCollector for DevNullMetricsCollector {
    fn incoming_introspection_request(&self) {}
    fn introspection_service_called(&self, _request_started: Instant) {}
    fn introspection_service_called_and_failed(&self, _request_started: Instant) {}
    fn introspection_service_called_successfully(&self, _request_started: Instant) {}
    fn introspection_request(&self, _request_started: Instant) {}
    fn introspection_request_successful(&self, _request_started: Instant) {}
    fn introspection_request_failed(&self, _request_started: Instant) {}
}
