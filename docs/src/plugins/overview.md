# Plugin System

Fugue supports a WebAssembly-based plugin system that allows extending its functionality in a sandboxed environment.

Plugins communicate with the host through a well-defined IPC protocol and are granted capabilities explicitly. This design ensures that plugins cannot access resources beyond what they have been permitted.

See [Writing Plugins](writing.md) to get started building your own plugin.
