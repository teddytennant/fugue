# Security Model

Fugue's security model is built on sandboxed execution and capability-based access control.

All plugins execute inside a WebAssembly sandbox with no direct access to the host filesystem or network. Communication between the host and plugins occurs exclusively through the IPC protocol, and every operation is gated by capability checks.

Credentials are stored in an encrypted vault and are never exposed to plugins without an explicit capability grant.
