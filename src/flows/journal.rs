use crate::app::AppContext;
use crate::storage::journal::{JournalPage, JournalQuery};

use super::FlowError;

/// The journal records `query` asks for, newest first.
pub async fn read_journal(app: &AppContext, query: &JournalQuery) -> Result<JournalPage, FlowError> {
    let opened = app.storage.lock().await?;
    opened
        .read_journal(query)
        .map_err(FlowError::SomethingWentWrong)
}
