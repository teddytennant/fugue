# Plugin Security Model

Fugue enforces a capability-based security model for all plugins.

Plugins run in a WebAssembly sandbox and have no ambient authority. Every sensitive operation requires an explicit capability grant. The host validates capability tokens on each IPC call, preventing unauthorized access.

This model ensures that a compromised or malicious plugin cannot escalate privileges beyond its declared capability set.
