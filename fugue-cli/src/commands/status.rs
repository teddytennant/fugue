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
        println!("Fugue is not running");
        return Ok(());
    }

    match UnixStream::connect(socket_path).await {
        Ok(mut stream) => {
            ipc::write_message(&mut stream, &IpcMessage::Ping).await?;
            match ipc::read_message(&mut stream).await {
                Ok(IpcMessage::Pong) => {
                    println!("Fugue is running");
                    println!("  Socket: {}", socket_path.display());
                }
                Ok(_) => {
                    println!("Fugue responded with unexpected message");
                }
                Err(e) => {
                    println!("Fugue is not responding: {}", e);
                }
            }
        }
        Err(_) => {
            println!("Fugue is not running (stale socket file)");
            // Clean up stale socket
            let _ = std::fs::remove_file(socket_path);
        }
    }

    Ok(())
}
