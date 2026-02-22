# Writing Plugins

This guide covers how to create a new Fugue plugin from scratch.

Plugins are compiled to WebAssembly and interact with Fugue through the WIT interface. Start by generating a plugin scaffold with `fugue plugin new <name>`, then implement the required exports.

Refer to the [WIT Interface Reference](../reference/wit.md) for the full interface definition and [Capabilities](capabilities.md) for the permissions your plugin can request.
