// #[tokio::main]
// async fn main() -> color_eyre::Result<()> {
fn main() -> color_eyre::Result<()> {
    let config_file_path = format!("{}/config.toml", env!("CARGO_MANIFEST_DIR"));

    #[cfg(debug_assertions)]
    dbg!(&config_file_path);

    let config = lib_config::Config::load_from_path(config_file_path)?;

    #[cfg(debug_assertions)]
    dbg!(&config);

    lib_pingora_proxy::run(config)?;

    Ok(())
}
