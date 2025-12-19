//! Implementation of ART and auxiliary tree routines.

pub mod art;
pub mod art_node;
pub mod changes;
pub mod errors;
pub mod node_index;

mod display;
pub(crate) mod helper_tools;

#[cfg(test)]
mod test_helper_tools {
    use chrono::Local;
    use std::fmt;
    use tracing_subscriber::fmt::format::Writer;
    use tracing_subscriber::fmt::time::FormatTime;

    struct LocalTimer;

    impl FormatTime for LocalTimer {
        fn format_time(&self, w: &mut Writer<'_>) -> fmt::Result {
            let now = Local::now();
            write!(w, "[{}]", now.format("%Y-%m-%d %H:%M:%S"))
        }
    }

    /// Try to init console logger with RUST_LOG level filter
    pub(crate) fn init_tracing() {
        _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_timer(LocalTimer)
            .with_target(true)
            .try_init();
    }
}

#[cfg(test)]
pub(crate) use test_helper_tools::init_tracing;
