use crate::error::DynError;
use crate::io::cli::init;
use crate::ops;
use tracing::info;

pub async fn run_init_test() -> Result<String, DynError> {
    let init_state = init::load_init_state()?;
    let output = init_state.validation().with_current_timestamp()?;
    let json = serde_json::to_string_pretty(&output)?;

    println!("{json}");
    info!("init keys tested successfully");

    Ok(json)
}

pub async fn run_key_test(id: &str) -> Result<String, DynError> {
    let init_state = init::load_init_state()?;
    let output = ops::test::handle_test(&init_state, id).await?;
    let json = serde_json::to_string_pretty(&output)?;

    println!("{json}");
    info!(id, "stored ops keys tested successfully");

    Ok(json)
}
