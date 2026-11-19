use std::sync::Arc;

use my_http_server::controllers::ControllersMiddleware;

use crate::app::AppContext;

pub fn build_controllers(app: &Arc<AppContext>) -> ControllersMiddleware {
    let mut result = ControllersMiddleware::new(None, None);

    // Client certificates
    result.register_post_action(Arc::new(
        crate::http::controllers::client_certs::GenerateCertificateAction::new(app.clone()),
    ));

    result.register_post_action(Arc::new(
        crate::http::controllers::client_certs::RevokeCertificateAction::new(app.clone()),
    ));

    result.register_post_action(Arc::new(
        crate::http::controllers::client_certs::DownloadCertAction::new(app.clone()),
    ));

    result.register_get_action(Arc::new(
        crate::http::controllers::client_certs::GetListOfCertificatesAction::new(app.clone()),
    ));

    result.register_get_action(Arc::new(
        crate::http::controllers::client_certs::GetListOfRevokedCertificatesAction::new(
            app.clone(),
        ),
    ));

    // Certificate Authority
    result.register_post_action(Arc::new(
        crate::http::controllers::ca::CheckCaAction::new(app.clone()),
    ));

    result.register_post_action(Arc::new(
        crate::http::controllers::ca::GenerateCaAction::new(app.clone()),
    ));

    result.register_post_action(Arc::new(
        crate::http::controllers::ca::ImportCaAction::new(app.clone()),
    ));

    result.register_get_action(Arc::new(
        crate::http::controllers::ca::DownloadCertAction::new(app.clone()),
    ));

    result.register_post_action(Arc::new(
        crate::http::controllers::ca::DownloadPrivateKeyAction::new(app.clone()),
    ));

    result.register_get_action(Arc::new(
        crate::http::controllers::ca::GetListOfCaAction::new(app.clone()),
    ));

    // Security
    result.register_post_action(Arc::new(
        crate::http::controllers::security::SetNetworkKeyAction::new(app.clone()),
    ));

    result.register_post_action(Arc::new(
        crate::http::controllers::security::GetJournalAction::new(app.clone()),
    ));

    result.register_post_action(Arc::new(
        crate::http::controllers::security::ChangeFilesKeyAction::new(app.clone()),
    ));

    result.register_post_action(Arc::new(
        crate::http::controllers::security::RollBackFilesKeyAction::new(app.clone()),
    ));

    result.register_get_action(Arc::new(
        crate::http::controllers::security::FilesKeyArchivesAction::new(app.clone()),
    ));

    result.register_post_action(Arc::new(
        crate::http::controllers::security::DeleteFilesKeyArchiveAction::new(app.clone()),
    ));

    result
}
