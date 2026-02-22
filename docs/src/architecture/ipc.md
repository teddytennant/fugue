# IPC Protocol

Fugue uses a structured IPC protocol for communication between the host runtime and plugins.

Messages are serialized and passed across the WebAssembly boundary using the Component Model. Each message carries a capability token that the host validates before processing the request.

See the [WIT Interface Reference](../reference/wit.md) for the message types and function signatures.
