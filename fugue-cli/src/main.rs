#![deny(unsafe_code)]

use clap::{Parser, Subcommand};

mod commands;

#[derive(Parser)]
#[command(
    name = "fugue",
    about = "Security-first AI agent gateway",
    version,
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start core and enabled adapters
    Start {
        /// Path to config file
        #[arg(short, long)]
        config: Option<String>,

        /// Run in foreground (don't daemonize)
        #[arg(short, long)]
        foreground: bool,
    },

    /// Stop running instance
    Stop,

    /// Show status of core and adapters
    Status,

    /// Interactive CLI chat session
    Chat {
        /// LLM provider to use
        #[arg(short, long)]
        provider: Option<String>,

        /// System prompt
        #[arg(short, long)]
        system: Option<String>,
    },

    /// Configuration management
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Credential vault management
    Vault {
        #[command(subcommand)]
        action: VaultAction,
    },

    /// Plugin management
    Plugin {
        #[command(subcommand)]
        action: PluginAction,
    },

    /// View logs
    Log {
        #[command(subcommand)]
        action: LogAction,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Generate default config interactively
    Init {
        /// Force overwrite existing config
        #[arg(short, long)]
        force: bool,
    },
    /// Print current config
    Show,
    /// Validate current config
    Validate,
}

#[derive(Subcommand)]
enum VaultAction {
    /// Initialize the vault with a password-derived key
    Init {
        /// Derive encryption key from a password instead of storing a plaintext key file
        #[arg(short, long)]
        password: bool,
    },
    /// Set a credential
    Set {
        /// Credential name
        name: String,
        /// Credential value (omit to read from stdin)
        value: Option<String>,
        /// Use password-derived key (prompts for password)
        #[arg(short, long)]
        password: bool,
    },
    /// List stored credentials
    List {
        /// Use password-derived key (prompts for password)
        #[arg(short, long)]
        password: bool,
    },
    /// Remove a credential
    Remove {
        /// Credential name
        name: String,
        /// Use password-derived key (prompts for password)
        #[arg(short, long)]
        password: bool,
    },
}

#[derive(Subcommand)]
enum PluginAction {
    /// Install a plugin from a directory
    Install {
        /// Path to plugin directory containing manifest.toml
        path: String,
    },
    /// Remove an installed plugin
    Remove {
        /// Plugin name
        name: String,
    },
    /// List installed plugins
    List,
    /// Inspect a plugin's manifest and capabilities
    Inspect {
        /// Plugin name
        name: String,
    },
    /// Approve a plugin's requested capabilities
    Approve {
        /// Plugin name
        name: String,
    },
}

#[derive(Subcommand)]
enum LogAction {
    /// View audit log
    Audit {
        /// Number of entries to show
        #[arg(short, long, default_value = "50")]
        count: usize,

        /// Filter by severity (info, warning, critical)
        #[arg(short, long)]
        severity: Option<String>,
    },
    /// View application log
    App {
        /// Number of lines to show
        #[arg(short, long, default_value = "50")]
        count: usize,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Start { config, foreground } => {
            commands::start::run(config, foreground).await
        }
        Commands::Stop => commands::stop::run().await,
        Commands::Status => commands::status::run().await,
        Commands::Chat { provider, system } => {
            commands::chat::run(provider, system).await
        }
        Commands::Config { action } => match action {
            ConfigAction::Init { force } => commands::config::init(force).await,
            ConfigAction::Show => commands::config::show().await,
            ConfigAction::Validate => commands::config::validate().await,
        },
        Commands::Vault { action } => match action {
            VaultAction::Init { password } => {
                commands::vault::init(password).await
            }
            VaultAction::Set { name, value, password } => {
                commands::vault::set(&name, value.as_deref(), password).await
            }
            VaultAction::List { password } => commands::vault::list(password).await,
            VaultAction::Remove { name, password } => commands::vault::remove(&name, password).await,
        },
        Commands::Plugin { action } => match action {
            PluginAction::Install { path } => commands::plugin::install(&path).await,
            PluginAction::Remove { name } => commands::plugin::remove(&name).await,
            PluginAction::List => commands::plugin::list().await,
            PluginAction::Inspect { name } => commands::plugin::inspect(&name).await,
            PluginAction::Approve { name } => commands::plugin::approve(&name).await,
        },
        Commands::Log { action } => match action {
            LogAction::Audit { count, severity } => {
                commands::log::audit(count, severity.as_deref()).await
            }
            LogAction::App { count } => commands::log::app(count).await,
        },
    }
}
