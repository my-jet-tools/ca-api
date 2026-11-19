use my_http_server::HttpFailResult;

use crate::flows::FlowError;

impl From<FlowError> for HttpFailResult {
    fn from(value: FlowError) -> Self {
        match value {
            FlowError::NotInitialized => Self::from((
                409u16,
                "the service is not initialized: it waits for its key",
            )),
            FlowError::NoNetworkKey => Self::from((
                503u16,
                "no network key is set: nothing is served to my-reverse-proxy until one is (/api/set-network-key)",
            )),
            FlowError::CaAlreadyGenerated => {
                Self::as_forbidden("CA is already generated".to_string().into())
            }
            FlowError::CaNotFound => Self::as_not_found("CA not found".to_string(), false),
            FlowError::CertNotFound => {
                Self::as_not_found("Certificate not found".to_string(), false)
            }
            FlowError::CertAlreadyRevoked => {
                Self::from((409u16, "The certificate is revoked already"))
            }
            FlowError::ArchiveNotFound => Self::as_not_found("Archive not found".to_string(), false),
            FlowError::ValidationError(err) => Self::as_forbidden(err.into()),
            FlowError::SomethingWentWrong(err) => Self::as_fatal_error(err),
        }
    }
}
