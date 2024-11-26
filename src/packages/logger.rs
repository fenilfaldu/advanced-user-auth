use std::env;

use super::settings::SETTINGS;

pub fn setup() {
    if env::var_os("RUST_LOG").is_none() {
        let app_name = env::var("CARGO_PKG_NAME").unwrap();
        let level = SETTINGS.read().logger.level.clone();
        let env = format!("{app_name }={level},tower_http={level}");

        env::set_var("RUST_LOG", env);
    }

    tracing_subscriber::fmt::init();
}
