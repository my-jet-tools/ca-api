use crate::storage::NotInitialized;

#[derive(Debug)]
pub enum FlowError {
    /// The service has no key yet: it waits for `POST /api/initialize`.
    NotInitialized,
    /// No network key is set, so nothing can be served to my-reverse-proxy.
    NoNetworkKey,
    CaAlreadyGenerated,
    CaNotFound,
    CertNotFound,
    /// The certificate with this id is revoked already.
    CertAlreadyRevoked,
    ValidationError(String),
    SomethingWentWrong(String),
}

impl From<NotInitialized> for FlowError {
    fn from(_: NotInitialized) -> Self {
        Self::NotInitialized
    }
}
