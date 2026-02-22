# Capabilities

Capabilities define what resources and operations a plugin is allowed to access within Fugue.

Each capability is requested in the plugin manifest and must be approved by the user or configuration policy. Examples include network access, vault read/write, and channel message sending.

See [Plugin Security Model](security.md) for how capabilities are enforced at runtime.
