//! The log tells what happened, never about what: no CA name, no CN, no key, no path inside the
//! data. Those are in the encrypted journal only — the log may be read by anyone who gets into the
//! machine or the log service.

use my_logger::LogEventCtx;

const PROCESS: &str = "ca-api";

pub fn info(message: impl Into<String>) {
    my_logger::LOGGER.write_info(PROCESS, message.into(), LogEventCtx::new());
}

pub fn warn(message: impl Into<String>) {
    my_logger::LOGGER.write_warning(PROCESS, message.into(), LogEventCtx::new());
}
