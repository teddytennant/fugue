# Credential Vault

The credential vault provides secure storage for tokens, API keys, and other secrets used by Fugue and its plugins.

Secrets stored in the vault are encrypted at rest and only decrypted when needed by an authorized adapter or plugin. Use `fugue vault set <key>` to store a credential and `fugue vault get <key>` to retrieve one.

See [Plugin Security Model](plugins/security.md) for how plugins interact with the vault.
