# Fugue

A security-first AI agent gateway that connects LLM providers to messaging channels with WASM-sandboxed plugins and encrypted credential storage.

## Why Fugue

- **~14,500 lines of Rust** -- small enough to audit in a week
- **No network server by default** -- zero network attack surface
- **Channel adapters as separate processes** -- crash isolation
- **WASM-sandboxed plugins** -- capability-gated, hash-verified execution
- **Credentials never in config files** -- OS keyring or AES-256-GCM encrypted vault
- **Localhost-only by default** -- network exposure requires explicit opt-in

## Supported Integrations

**LLM Providers:** Ollama, Anthropic, OpenAI

**Channels:** Telegram, Discord, IRC, Matrix, Signal, Slack, WhatsApp, CLI

## Quick Start

### Install

```bash
# From source
cargo install --path fugue-cli

# Nix
nix develop
```

### Configure

```bash
fugue config init
```

This creates `~/.config/fugue/config.toml`. At minimum, configure a provider and channel:

```toml
[providers.ollama]
type = "ollama"
base_url = "http://localhost:11434"
model = "llama3.2"

[channels.cli]
type = "cli"
```

### Run

```bash
fugue start       # Start the gateway
fugue chat        # Interactive CLI session
fugue status      # Check running state
fugue stop        # Stop the gateway
```

## Credential Vault

Store secrets in the encrypted vault instead of config files:

```bash
fugue vault set anthropic-key    # Prompted for value
fugue vault list
fugue vault remove anthropic-key
```

Reference vault entries in config with `credential = "vault:anthropic-key"`.

## Plugins

Plugins run in a WASM sandbox with explicit capability grants:

```bash
fugue plugin install ./my-plugin
fugue plugin approve my-plugin       # Review and approve capabilities
fugue plugin list
fugue plugin inspect my-plugin
fugue plugin remove my-plugin
```

See `fugue-sdk` for the plugin development SDK.

## Project Structure

```
fugue-core/       Core library (config, vault, IPC, plugins, routing, providers)
fugue-cli/        Command-line interface
fugue-sdk/        Plugin development SDK
fugue-adapters/   Channel adapter implementations
docs/             mdbook documentation
wit/              WebAssembly Interface Types definitions
examples/         Example config and plugins
```

## Building

```bash
cargo build                # Debug
cargo build --release      # Release
cargo test                 # Run tests
```

Requires Rust 1.75+. A Nix flake is provided for reproducible development environments.

## Documentation

Full documentation is available in `docs/` and can be built with mdbook:

```bash
mdbook serve docs
```

## License

MIT
