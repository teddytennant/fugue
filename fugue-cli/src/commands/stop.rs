use anyhow::Result;
use fugue_core::ipc::{self, IpcMessage};
use fugue_core::FugueConfig;
use tokio::net::UnixStream;

pub async fn run() -> Result<()> {
    let config = if FugueConfig::default_config_path().exists() {
        FugueConfig::load(&FugueConfig::default_config_path())?
    } else {
        FugueConfig::default_config()
    };

    let socket_path = &config.core.socket_path;

    if !socket_path.exists() {
        eprintln!("Fugue is not running (no socket at {})", socket_path.display());
        std::process::exit(1);
    }

    let mut stream = UnixStream::connect(socket_path).await.map_err(|e| {
        anyhow::anyhow!("failed to connect to fugue: {} (is it running?)", e)
    })?;

    ipc::write_message(&mut stream, &IpcMessage::Shutdown).await?;
    println!("Shutdown signal sent");
    Ok(())
}
