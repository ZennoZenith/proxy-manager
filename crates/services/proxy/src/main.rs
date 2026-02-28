fn main() -> color_eyre::Result<()> {
    tracing_subscriber::fmt()
        // .without_time() // For early local development.
        .with_target(true)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "debug".into()),
        )
        .try_init()
        .ok();

    let args = std::env::args().collect::<Vec<String>>();

    // if let Some() = args.get(1);
    let config_file_path = match args.into_iter().nth(1) {
        Some(arg) => arg,
        None => format!("{}/config.toml", env!("CARGO_MANIFEST_DIR")),
    };

    #[cfg(debug_assertions)]
    dbg!(&config_file_path);

    let config = lib_config::Config::load_from_path(config_file_path)?;

    // #[cfg(debug_assertions)]
    // dbg!(&config);

    lib_pingora_proxy::run(config)?;

    Ok(())
}
