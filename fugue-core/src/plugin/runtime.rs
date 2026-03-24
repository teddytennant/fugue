#![deny(unsafe_code)]

//! WASM plugin execution runtime
//!
//! Loads, sandboxes, and executes WASM plugins with capability-gated host functions.
//!
//! ## Plugin ABI
//!
//! Guest modules must export:
//! - `memory` — linear memory
//! - `fugue_alloc(size: i32) -> i32` — allocate `size` bytes, return pointer
//! - `fugue_handle(ptr: i32, len: i32) -> i64` — process input JSON, return packed `(ptr << 32) | len`
//!
//! Host provides imports in the `"fugue"` namespace:
//! - `host_log(level: i32, msg_ptr: i32, msg_len: i32)` — log a message (always available)
//! - `host_state_get(ns_ptr, ns_len, key_ptr, key_len) -> i32` — get state value length, or -1/-2/-3
//! - `host_state_get_read(buf_ptr: i32) -> i32` — copy stashed value to buf_ptr
//! - `host_state_set(ns_ptr, ns_len, key_ptr, key_len, val_ptr, val_len) -> i32` — set state
//! - `host_state_delete(ns_ptr, ns_len, key_ptr, key_len) -> i32` — delete state

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use tracing::{debug, warn};
use wasmtime::*;

use super::capabilities::Capability;
use super::registry::PluginEntry;
use crate::error::{FugueError, Result};
use crate::state::StateStore;

/// Configuration for the WASM plugin runtime
pub struct RuntimeConfig {
    /// Maximum linear memory in bytes. Default: 16 MiB
    pub max_memory_bytes: usize,
    /// Maximum fuel (instruction count) per handle() invocation. Default: 1 billion
    pub max_fuel: u64,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: 16 * 1024 * 1024,
            max_fuel: 1_000_000_000,
        }
    }
}

/// Captured log entry from a plugin invocation
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub level: LogLevel,
    pub message: String,
}

/// Log levels for plugin logging
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

impl LogLevel {
    fn from_i32(v: i32) -> Self {
        match v {
            0 => LogLevel::Error,
            1 => LogLevel::Warn,
            2 => LogLevel::Info,
            3 => LogLevel::Debug,
            _ => LogLevel::Trace,
        }
    }
}

/// Data stored inside each wasmtime Store
struct PluginCtx {
    plugin_name: String,
    capabilities: HashSet<Capability>,
    state: Option<Arc<Mutex<StateStore>>>,
    log_entries: Vec<LogEntry>,
    response_buffer: Vec<u8>,
    limits: StoreLimits,
    max_fuel: u64,
}

impl PluginCtx {
    fn has_capability(&self, cap: &Capability) -> bool {
        self.capabilities.iter().any(|granted| granted.satisfies(cap))
    }
}

/// The WASM plugin engine — compiles and instantiates plugins
pub struct PluginEngine {
    engine: Engine,
    config: RuntimeConfig,
}

/// A compiled plugin module, ready to be instantiated
pub struct CompiledPlugin {
    module: Module,
    name: String,
}

impl CompiledPlugin {
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// A live, sandboxed plugin instance
pub struct PluginInstance {
    store: Store<PluginCtx>,
    instance: Instance,
}

impl PluginEngine {
    /// Create a new plugin engine with the given configuration
    pub fn new(config: RuntimeConfig) -> Result<Self> {
        let mut engine_config = Config::new();
        engine_config.consume_fuel(true);

        let engine = Engine::new(&engine_config)
            .map_err(|e| FugueError::Plugin(format!("failed to create WASM engine: {e}")))?;

        Ok(Self { engine, config })
    }

    /// Compile raw WASM bytes (binary or WAT text) into a reusable module
    pub fn compile(&self, name: &str, wasm_bytes: &[u8]) -> Result<CompiledPlugin> {
        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(|e| FugueError::Plugin(format!("failed to compile '{name}': {e}")))?;

        Ok(CompiledPlugin {
            module,
            name: name.to_string(),
        })
    }

    /// Compile a plugin from a registry entry (loads WASM from disk)
    pub fn compile_entry(&self, entry: &PluginEntry) -> Result<CompiledPlugin> {
        let wasm_bytes = std::fs::read(&entry.wasm_path).map_err(|e| {
            FugueError::Plugin(format!("failed to read '{}': {e}", entry.wasm_path.display()))
        })?;
        self.compile(&entry.name, &wasm_bytes)
    }

    /// Instantiate a compiled plugin with capabilities and optional state store
    pub fn instantiate(
        &self,
        compiled: &CompiledPlugin,
        capabilities: HashSet<Capability>,
        state: Option<Arc<Mutex<StateStore>>>,
    ) -> Result<PluginInstance> {
        let limits = StoreLimitsBuilder::new()
            .memory_size(self.config.max_memory_bytes)
            .build();

        let ctx = PluginCtx {
            plugin_name: compiled.name.clone(),
            capabilities,
            state,
            log_entries: Vec::new(),
            response_buffer: Vec::new(),
            limits,
            max_fuel: self.config.max_fuel,
        };

        let mut store = Store::new(&self.engine, ctx);
        store.limiter(|ctx| &mut ctx.limits);
        store
            .set_fuel(self.config.max_fuel)
            .map_err(|e| FugueError::Plugin(format!("failed to set fuel: {e}")))?;

        let mut linker = Linker::new(&self.engine);
        Self::register_host_functions(&mut linker)?;

        let instance = linker
            .instantiate(&mut store, &compiled.module)
            .map_err(|e| FugueError::Plugin(format!("failed to instantiate '{}': {e}", compiled.name)))?;

        Self::validate_exports(&instance, &mut store, &compiled.name)?;

        Ok(PluginInstance { store, instance })
    }

    fn register_host_functions(linker: &mut Linker<PluginCtx>) -> Result<()> {
        // --- host_log ---
        linker
            .func_wrap(
                "fugue",
                "host_log",
                |mut caller: Caller<'_, PluginCtx>, level: i32, ptr: i32, len: i32| {
                    if let Some(msg) = read_guest_str(&mut caller, ptr, len) {
                        let log_level = LogLevel::from_i32(level);
                        let name = caller.data().plugin_name.clone();
                        match log_level {
                            LogLevel::Error | LogLevel::Warn => {
                                warn!(plugin = %name, "[plugin] {msg}")
                            }
                            _ => debug!(plugin = %name, "[plugin] {msg}"),
                        }
                        caller.data_mut().log_entries.push(LogEntry {
                            level: log_level,
                            message: msg,
                        });
                    }
                },
            )
            .map_err(wrap_linker_err("host_log"))?;

        // --- host_state_get ---
        // Returns: value length (>= 0), -1 not found, -2 no capability, -3 internal error
        // Stashes value in response_buffer
        linker
            .func_wrap(
                "fugue",
                "host_state_get",
                |mut caller: Caller<'_, PluginCtx>,
                 ns_ptr: i32,
                 ns_len: i32,
                 key_ptr: i32,
                 key_len: i32|
                 -> i32 {
                    if !caller.data().has_capability(&Capability::StateRead) {
                        return -2;
                    }

                    let (ns, key) = match read_two_strings(&mut caller, ns_ptr, ns_len, key_ptr, key_len)
                    {
                        Some(v) => v,
                        None => return -3,
                    };

                    let state = match caller.data().state.clone() {
                        Some(s) => s,
                        None => return -3,
                    };

                    let store = state.lock().expect("state lock poisoned");
                    match store.kv_get(&ns, &key) {
                        Ok(Some(value)) => {
                            let len = value.len() as i32;
                            caller.data_mut().response_buffer = value.into_bytes();
                            len
                        }
                        Ok(None) => -1,
                        Err(_) => -3,
                    }
                },
            )
            .map_err(wrap_linker_err("host_state_get"))?;

        // --- host_state_get_read ---
        // Copies stashed response_buffer into guest memory at buf_ptr
        linker
            .func_wrap(
                "fugue",
                "host_state_get_read",
                |mut caller: Caller<'_, PluginCtx>, buf_ptr: i32| -> i32 {
                    let response = std::mem::take(&mut caller.data_mut().response_buffer);
                    if response.is_empty() {
                        return 0;
                    }

                    let memory = match get_memory(&mut caller) {
                        Some(m) => m,
                        None => return -1,
                    };

                    let start = buf_ptr as usize;
                    let end = start + response.len();
                    let data = memory.data_mut(&mut caller);
                    if end > data.len() {
                        return -1;
                    }

                    data[start..end].copy_from_slice(&response);
                    response.len() as i32
                },
            )
            .map_err(wrap_linker_err("host_state_get_read"))?;

        // --- host_state_set ---
        // Returns: 0 success, -1 error, -2 no capability
        linker
            .func_wrap(
                "fugue",
                "host_state_set",
                |mut caller: Caller<'_, PluginCtx>,
                 ns_ptr: i32,
                 ns_len: i32,
                 key_ptr: i32,
                 key_len: i32,
                 val_ptr: i32,
                 val_len: i32|
                 -> i32 {
                    if !caller.data().has_capability(&Capability::StateWrite) {
                        return -2;
                    }

                    let memory = match get_memory(&mut caller) {
                        Some(m) => m,
                        None => return -1,
                    };

                    let data = memory.data(&caller);
                    let ns = match read_str(data, ns_ptr, ns_len) {
                        Some(s) => s,
                        None => return -1,
                    };
                    let key = match read_str(data, key_ptr, key_len) {
                        Some(s) => s,
                        None => return -1,
                    };
                    let val = match read_str(data, val_ptr, val_len) {
                        Some(s) => s,
                        None => return -1,
                    };

                    let state = match caller.data().state.clone() {
                        Some(s) => s,
                        None => return -1,
                    };

                    let store = state.lock().expect("state lock poisoned");
                    match store.kv_set(&ns, &key, &val) {
                        Ok(()) => 0,
                        Err(_) => -1,
                    }
                },
            )
            .map_err(wrap_linker_err("host_state_set"))?;

        // --- host_state_delete ---
        // Returns: 1 deleted, 0 not found, -1 error, -2 no capability
        linker
            .func_wrap(
                "fugue",
                "host_state_delete",
                |mut caller: Caller<'_, PluginCtx>,
                 ns_ptr: i32,
                 ns_len: i32,
                 key_ptr: i32,
                 key_len: i32|
                 -> i32 {
                    if !caller.data().has_capability(&Capability::StateWrite) {
                        return -2;
                    }

                    let (ns, key) = match read_two_strings(&mut caller, ns_ptr, ns_len, key_ptr, key_len)
                    {
                        Some(v) => v,
                        None => return -1,
                    };

                    let state = match caller.data().state.clone() {
                        Some(s) => s,
                        None => return -1,
                    };

                    let store = state.lock().expect("state lock poisoned");
                    match store.kv_delete(&ns, &key) {
                        Ok(true) => 1,
                        Ok(false) => 0,
                        Err(_) => -1,
                    }
                },
            )
            .map_err(wrap_linker_err("host_state_delete"))?;

        Ok(())
    }

    fn validate_exports(
        instance: &Instance,
        store: &mut Store<PluginCtx>,
        name: &str,
    ) -> Result<()> {
        if instance.get_memory(&mut *store, "memory").is_none() {
            return Err(FugueError::Plugin(format!(
                "plugin '{name}' missing required 'memory' export"
            )));
        }
        if instance
            .get_typed_func::<i32, i32>(&mut *store, "fugue_alloc")
            .is_err()
        {
            return Err(FugueError::Plugin(format!(
                "plugin '{name}' missing required 'fugue_alloc(i32) -> i32' export"
            )));
        }
        if instance
            .get_typed_func::<(i32, i32), i64>(&mut *store, "fugue_handle")
            .is_err()
        {
            return Err(FugueError::Plugin(format!(
                "plugin '{name}' missing required 'fugue_handle(i32, i32) -> i64' export"
            )));
        }
        Ok(())
    }
}

impl PluginInstance {
    /// Invoke the plugin's handle function with JSON input, returning JSON output.
    ///
    /// Resets fuel each invocation so the instance can be reused.
    pub fn handle(&mut self, input_json: &str) -> Result<String> {
        // Reset fuel for this invocation
        let max_fuel = self.store.data().max_fuel;
        self.store
            .set_fuel(max_fuel)
            .map_err(|e| FugueError::Plugin(format!("failed to reset fuel: {e}")))?;

        // Clear log entries from previous invocation
        self.store.data_mut().log_entries.clear();

        let input_bytes = input_json.as_bytes();

        // Allocate guest memory for input
        let alloc = self
            .instance
            .get_typed_func::<i32, i32>(&mut self.store, "fugue_alloc")
            .map_err(|e| FugueError::Plugin(format!("fugue_alloc lookup failed: {e}")))?;

        let input_ptr = alloc
            .call(&mut self.store, input_bytes.len() as i32)
            .map_err(|e| FugueError::Plugin(format!("fugue_alloc call failed: {e}")))?;

        // Write input into guest memory
        {
            let memory = self
                .instance
                .get_memory(&mut self.store, "memory")
                .ok_or_else(|| FugueError::Plugin("missing memory export".into()))?;
            let start = input_ptr as usize;
            let end = start + input_bytes.len();
            let data = memory.data_mut(&mut self.store);
            if end > data.len() {
                return Err(FugueError::Plugin("input exceeds guest memory".into()));
            }
            data[start..end].copy_from_slice(input_bytes);
        }

        // Call fugue_handle
        let handle_fn = self
            .instance
            .get_typed_func::<(i32, i32), i64>(&mut self.store, "fugue_handle")
            .map_err(|e| FugueError::Plugin(format!("fugue_handle lookup failed: {e}")))?;

        let result_packed = handle_fn
            .call(&mut self.store, (input_ptr, input_bytes.len() as i32))
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("fuel") {
                    FugueError::Plugin(format!(
                        "plugin '{}' exceeded execution limit",
                        self.store.data().plugin_name
                    ))
                } else {
                    FugueError::Plugin(format!("fugue_handle failed: {msg}"))
                }
            })?;

        // Unpack result: high 32 = ptr, low 32 = len
        let result_ptr = (result_packed >> 32) as u32;
        let result_len = (result_packed & 0xFFFF_FFFF) as u32;

        // Read result from guest memory
        let memory = self
            .instance
            .get_memory(&mut self.store, "memory")
            .ok_or_else(|| FugueError::Plugin("missing memory export".into()))?;

        let rstart = result_ptr as usize;
        let rend = rstart + result_len as usize;
        let data = memory.data(&self.store);
        if rend > data.len() {
            return Err(FugueError::Plugin("result pointer exceeds guest memory".into()));
        }

        let result_str = std::str::from_utf8(&data[rstart..rend])
            .map_err(|e| FugueError::Plugin(format!("invalid UTF-8 in result: {e}")))?;

        Ok(result_str.to_string())
    }

    /// Take captured log entries (drains the internal buffer)
    pub fn take_logs(&mut self) -> Vec<LogEntry> {
        std::mem::take(&mut self.store.data_mut().log_entries)
    }

    /// Get remaining fuel from the last invocation
    pub fn fuel_remaining(&self) -> u64 {
        self.store.get_fuel().unwrap_or(0)
    }
}

// --- Helper functions ---

fn get_memory(caller: &mut Caller<'_, PluginCtx>) -> Option<Memory> {
    match caller.get_export("memory") {
        Some(Extern::Memory(m)) => Some(m),
        _ => None,
    }
}

fn read_str(data: &[u8], ptr: i32, len: i32) -> Option<String> {
    let start = ptr as usize;
    let end = start.checked_add(len as usize)?;
    if end > data.len() {
        return None;
    }
    std::str::from_utf8(&data[start..end])
        .ok()
        .map(|s| s.to_string())
}

fn read_guest_str(caller: &mut Caller<'_, PluginCtx>, ptr: i32, len: i32) -> Option<String> {
    let memory = get_memory(caller)?;
    let data = memory.data(caller);
    read_str(data, ptr, len)
}

fn read_two_strings(
    caller: &mut Caller<'_, PluginCtx>,
    a_ptr: i32,
    a_len: i32,
    b_ptr: i32,
    b_len: i32,
) -> Option<(String, String)> {
    let memory = get_memory(caller)?;
    let data = memory.data(caller);
    let a = read_str(data, a_ptr, a_len)?;
    let b = read_str(data, b_ptr, b_len)?;
    Some((a, b))
}

fn wrap_linker_err(name: &str) -> impl FnOnce(wasmtime::Error) -> FugueError + '_ {
    move |e| FugueError::Plugin(format!("failed to register {name}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_engine() -> PluginEngine {
        PluginEngine::new(RuntimeConfig::default()).unwrap()
    }

    fn small_fuel_engine() -> PluginEngine {
        PluginEngine::new(RuntimeConfig {
            max_fuel: 10_000,
            ..RuntimeConfig::default()
        })
        .unwrap()
    }

    // --- WAT test modules ---

    /// Minimal echo: returns input as-is
    const ECHO_WAT: &str = r#"
        (module
          (memory (export "memory") 2)
          (global $bump (mut i32) (i32.const 65536))

          (func (export "fugue_alloc") (param $size i32) (result i32)
            (local $ptr i32)
            (local.set $ptr (global.get $bump))
            (global.set $bump (i32.add (global.get $bump) (local.get $size)))
            (local.get $ptr)
          )

          (func (export "fugue_handle") (param $ptr i32) (param $len i32) (result i64)
            (i64.or
              (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
              (i64.extend_i32_u (local.get $len))
            )
          )
        )
    "#;

    /// Calls host_log then echoes
    const LOGGING_WAT: &str = r#"
        (module
          (import "fugue" "host_log" (func $log (param i32 i32 i32)))
          (memory (export "memory") 2)
          (global $bump (mut i32) (i32.const 65536))
          (data (i32.const 0) "hello from wasm")

          (func (export "fugue_alloc") (param $size i32) (result i32)
            (local $ptr i32)
            (local.set $ptr (global.get $bump))
            (global.set $bump (i32.add (global.get $bump) (local.get $size)))
            (local.get $ptr)
          )

          (func (export "fugue_handle") (param $ptr i32) (param $len i32) (result i64)
            ;; Log at info level (2)
            (call $log (i32.const 2) (i32.const 0) (i32.const 15))
            ;; Echo input
            (i64.or
              (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
              (i64.extend_i32_u (local.get $len))
            )
          )
        )
    "#;

    /// Calls host_state_set then host_state_get, returns the retrieved value
    const STATE_WAT: &str = r#"
        (module
          (import "fugue" "host_state_set" (func $set (param i32 i32 i32 i32 i32 i32) (result i32)))
          (import "fugue" "host_state_get" (func $get (param i32 i32 i32 i32) (result i32)))
          (import "fugue" "host_state_get_read" (func $get_read (param i32) (result i32)))
          (memory (export "memory") 2)
          (global $bump (mut i32) (i32.const 1024))

          ;; "ns" at 0, "key" at 2, "hello" at 5
          (data (i32.const 0) "ns")
          (data (i32.const 2) "key")
          (data (i32.const 5) "hello")

          (func $alloc (export "fugue_alloc") (param $size i32) (result i32)
            (local $ptr i32)
            (local.set $ptr (global.get $bump))
            (global.set $bump (i32.add (global.get $bump) (local.get $size)))
            (local.get $ptr)
          )

          (func (export "fugue_handle") (param $ptr i32) (param $len i32) (result i64)
            (local $vlen i32)
            (local $buf i32)

            ;; state_set("ns"(0,2), "key"(2,3), "hello"(5,5))
            (drop (call $set (i32.const 0) (i32.const 2) (i32.const 2) (i32.const 3) (i32.const 5) (i32.const 5)))

            ;; state_get("ns"(0,2), "key"(2,3)) -> length
            (local.set $vlen (call $get (i32.const 0) (i32.const 2) (i32.const 2) (i32.const 3)))

            ;; allocate buffer
            (local.set $buf (call $alloc (local.get $vlen)))

            ;; read stashed value into buffer
            (drop (call $get_read (local.get $buf)))

            ;; return the value
            (i64.or
              (i64.shl (i64.extend_i32_u (local.get $buf)) (i64.const 32))
              (i64.extend_i32_u (local.get $vlen))
            )
          )
        )
    "#;

    /// Infinite loop — should hit fuel exhaustion
    const INFINITE_WAT: &str = r#"
        (module
          (memory (export "memory") 2)
          (global $bump (mut i32) (i32.const 65536))

          (func (export "fugue_alloc") (param $size i32) (result i32)
            (local $ptr i32)
            (local.set $ptr (global.get $bump))
            (global.set $bump (i32.add (global.get $bump) (local.get $size)))
            (local.get $ptr)
          )

          (func (export "fugue_handle") (param $ptr i32) (param $len i32) (result i64)
            (loop $inf (br $inf))
            (unreachable)
          )
        )
    "#;

    /// Missing memory export
    const NO_MEMORY_WAT: &str = r#"
        (module
          (memory 1)
          (func (export "fugue_alloc") (param i32) (result i32) (i32.const 0))
          (func (export "fugue_handle") (param i32 i32) (result i64) (i64.const 0))
        )
    "#;

    /// Missing fugue_handle export
    const NO_HANDLE_WAT: &str = r#"
        (module
          (memory (export "memory") 2)
          (func (export "fugue_alloc") (param i32) (result i32) (i32.const 0))
        )
    "#;

    /// Writes a fixed response string to memory and returns it
    const FIXED_RESPONSE_WAT: &str = r#"
        (module
          (memory (export "memory") 2)
          (global $bump (mut i32) (i32.const 65536))
          (data (i32.const 256) "{\"success\":true,\"output\":\"ok\",\"error\":null}")

          (func $alloc (export "fugue_alloc") (param $size i32) (result i32)
            (local $ptr i32)
            (local.set $ptr (global.get $bump))
            (global.set $bump (i32.add (global.get $bump) (local.get $size)))
            (local.get $ptr)
          )

          (func (export "fugue_handle") (param $ptr i32) (param $len i32) (result i64)
            ;; Return the fixed JSON at offset 256, length 43
            (i64.or
              (i64.shl (i64.const 256) (i64.const 32))
              (i64.const 43)
            )
          )
        )
    "#;

    /// State delete test module
    const STATE_DELETE_WAT: &str = r#"
        (module
          (import "fugue" "host_state_set" (func $set (param i32 i32 i32 i32 i32 i32) (result i32)))
          (import "fugue" "host_state_delete" (func $del (param i32 i32 i32 i32) (result i32)))
          (import "fugue" "host_state_get" (func $get (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 2)
          (global $bump (mut i32) (i32.const 1024))

          (data (i32.const 0) "ns")
          (data (i32.const 2) "key")
          (data (i32.const 5) "val")

          (func $alloc (export "fugue_alloc") (param $size i32) (result i32)
            (local $ptr i32)
            (local.set $ptr (global.get $bump))
            (global.set $bump (i32.add (global.get $bump) (local.get $size)))
            (local.get $ptr)
          )

          (func (export "fugue_handle") (param $ptr i32) (param $len i32) (result i64)
            (local $result i32)

            ;; Set a value
            (drop (call $set (i32.const 0) (i32.const 2) (i32.const 2) (i32.const 3) (i32.const 5) (i32.const 3)))

            ;; Delete it
            (local.set $result (call $del (i32.const 0) (i32.const 2) (i32.const 2) (i32.const 3)))

            ;; Try to get it — should return -1 (not found)
            (local.set $result (call $get (i32.const 0) (i32.const 2) (i32.const 2) (i32.const 3)))

            ;; Write the result code as a string digit at offset 100
            ;; -1 in two's complement i32 is what we expect; write "D" if delete worked, "F" if get returns -1
            ;; Simple: write the get result as a byte
            ;; result == -1 means success, anything else means failure
            ;; Let's write "ok" if result == -1, "no" otherwise
            (if (i32.eq (local.get $result) (i32.const -1))
              (then
                (i32.store8 (i32.const 100) (i32.const 111)) ;; 'o'
                (i32.store8 (i32.const 101) (i32.const 107)) ;; 'k'
              )
              (else
                (i32.store8 (i32.const 100) (i32.const 110)) ;; 'n'
                (i32.store8 (i32.const 101) (i32.const 111)) ;; 'o'
              )
            )

            ;; Return "ok" or "no" from offset 100, length 2
            (i64.or
              (i64.shl (i64.const 100) (i64.const 32))
              (i64.const 2)
            )
          )
        )
    "#;

    // --- Engine tests ---

    #[test]
    fn test_engine_creation() {
        let engine = default_engine();
        assert!(engine.config.max_fuel > 0);
    }

    #[test]
    fn test_compile_echo() {
        let engine = default_engine();
        let compiled = engine.compile("echo", ECHO_WAT.as_bytes()).unwrap();
        assert_eq!(compiled.name(), "echo");
    }

    #[test]
    fn test_compile_invalid_wasm() {
        let engine = default_engine();
        let result = engine.compile("bad", b"not wasm at all");
        let err = result.err().unwrap().to_string();
        assert!(err.contains("failed to compile"), "unexpected error: {err}");
    }

    // --- Instantiation tests ---

    #[test]
    fn test_instantiate_echo() {
        let engine = default_engine();
        let compiled = engine.compile("echo", ECHO_WAT.as_bytes()).unwrap();
        let _instance = engine
            .instantiate(&compiled, HashSet::new(), None)
            .unwrap();
    }

    #[test]
    fn test_instantiate_missing_memory() {
        let engine = default_engine();
        let compiled = engine.compile("no-mem", NO_MEMORY_WAT.as_bytes()).unwrap();
        let result = engine.instantiate(&compiled, HashSet::new(), None);
        assert!(result.is_err());
        let err = result.err().unwrap().to_string();
        assert!(err.contains("memory"), "unexpected error: {err}");
    }

    #[test]
    fn test_instantiate_missing_handle() {
        let engine = default_engine();
        let compiled = engine.compile("no-handle", NO_HANDLE_WAT.as_bytes()).unwrap();
        let result = engine.instantiate(&compiled, HashSet::new(), None);
        let err = result.err().unwrap().to_string();
        assert!(err.contains("fugue_handle"), "unexpected error: {err}");
    }

    // --- Execution tests ---

    #[test]
    fn test_echo_handle() {
        let engine = default_engine();
        let compiled = engine.compile("echo", ECHO_WAT.as_bytes()).unwrap();
        let mut instance = engine
            .instantiate(&compiled, HashSet::new(), None)
            .unwrap();

        let result = instance.handle(r#"{"name":"echo","arguments":{"msg":"hi"}}"#).unwrap();
        assert_eq!(result, r#"{"name":"echo","arguments":{"msg":"hi"}}"#);
    }

    #[test]
    fn test_echo_multiple_invocations() {
        let engine = default_engine();
        let compiled = engine.compile("echo", ECHO_WAT.as_bytes()).unwrap();
        let mut instance = engine
            .instantiate(&compiled, HashSet::new(), None)
            .unwrap();

        for i in 0..5 {
            let input = format!("input-{i}");
            let result = instance.handle(&input).unwrap();
            assert_eq!(result, input);
        }
    }

    #[test]
    fn test_fixed_response() {
        let engine = default_engine();
        let compiled = engine
            .compile("fixed", FIXED_RESPONSE_WAT.as_bytes())
            .unwrap();
        let mut instance = engine
            .instantiate(&compiled, HashSet::new(), None)
            .unwrap();

        let result = instance.handle("anything").unwrap();
        assert_eq!(
            result,
            r#"{"success":true,"output":"ok","error":null}"#
        );
    }

    // --- Logging tests ---

    #[test]
    fn test_host_logging() {
        let engine = default_engine();
        let compiled = engine.compile("log", LOGGING_WAT.as_bytes()).unwrap();
        let mut instance = engine
            .instantiate(&compiled, HashSet::new(), None)
            .unwrap();

        let _result = instance.handle("test").unwrap();
        let logs = instance.take_logs();

        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].level, LogLevel::Info);
        assert_eq!(logs[0].message, "hello from wasm");
    }

    #[test]
    fn test_logs_cleared_between_invocations() {
        let engine = default_engine();
        let compiled = engine.compile("log", LOGGING_WAT.as_bytes()).unwrap();
        let mut instance = engine
            .instantiate(&compiled, HashSet::new(), None)
            .unwrap();

        instance.handle("first").unwrap();
        assert_eq!(instance.take_logs().len(), 1);

        instance.handle("second").unwrap();
        let logs = instance.take_logs();
        assert_eq!(logs.len(), 1); // Only from second invocation
    }

    // --- State tests ---

    #[test]
    fn test_state_set_and_get() {
        let engine = default_engine();
        let compiled = engine.compile("state", STATE_WAT.as_bytes()).unwrap();

        let state = Arc::new(Mutex::new(StateStore::open_in_memory().unwrap()));
        let mut caps = HashSet::new();
        caps.insert(Capability::StateRead);
        caps.insert(Capability::StateWrite);

        let mut instance = engine
            .instantiate(&compiled, caps, Some(state.clone()))
            .unwrap();

        let result = instance.handle("ignored").unwrap();
        assert_eq!(result, "hello");

        // Verify state was actually persisted
        let store = state.lock().unwrap();
        assert_eq!(store.kv_get("ns", "key").unwrap(), Some("hello".to_string()));
    }

    #[test]
    fn test_state_without_capability() {
        let engine = default_engine();
        let compiled = engine.compile("state", STATE_WAT.as_bytes()).unwrap();

        let state = Arc::new(Mutex::new(StateStore::open_in_memory().unwrap()));
        // No capabilities granted
        let mut instance = engine
            .instantiate(&compiled, HashSet::new(), Some(state))
            .unwrap();

        // The handle should still run — host functions return error codes, not trap
        // state_set returns -2 (no cap), state_get returns -2 (no cap)
        // The WAT tries to allocate $vlen (which is -2) bytes — this will likely
        // succeed but produce garbage. The test verifies the plugin doesn't crash.
        let result = instance.handle("ignored");
        // The allocator will get -2 as size, which wraps. This is expected behavior:
        // capability denial is reported via return codes, the plugin must handle them.
        // In this case the plugin doesn't check, so behavior is undefined but shouldn't trap.
        // Just verify it doesn't panic on our side.
        let _ = result;
    }

    #[test]
    fn test_state_delete() {
        let engine = default_engine();
        let compiled = engine
            .compile("state-del", STATE_DELETE_WAT.as_bytes())
            .unwrap();

        let state = Arc::new(Mutex::new(StateStore::open_in_memory().unwrap()));
        let mut caps = HashSet::new();
        caps.insert(Capability::StateRead);
        caps.insert(Capability::StateWrite);

        let mut instance = engine
            .instantiate(&compiled, caps, Some(state.clone()))
            .unwrap();

        let result = instance.handle("ignored").unwrap();
        assert_eq!(result, "ok");

        // Verify state was deleted
        let store = state.lock().unwrap();
        assert_eq!(store.kv_get("ns", "key").unwrap(), None);
    }

    // --- Fuel exhaustion tests ---

    #[test]
    fn test_infinite_loop_fuel_exhaustion() {
        let engine = small_fuel_engine();
        let compiled = engine.compile("inf", INFINITE_WAT.as_bytes()).unwrap();
        let mut instance = engine
            .instantiate(&compiled, HashSet::new(), None)
            .unwrap();

        let result = instance.handle("test");
        let err = result.err().unwrap().to_string();
        // wasmtime traps on fuel exhaustion — the error contains "fuel" or
        // manifests as a trap during execution
        assert!(
            err.contains("execution limit")
                || err.contains("fuel")
                || err.contains("error while executing")
                || err.contains("wasm trap"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_fuel_resets_between_invocations() {
        let engine = default_engine();
        let compiled = engine.compile("echo", ECHO_WAT.as_bytes()).unwrap();
        let mut instance = engine
            .instantiate(&compiled, HashSet::new(), None)
            .unwrap();

        instance.handle("first").unwrap();
        let fuel_after_first = instance.fuel_remaining();

        instance.handle("second").unwrap();
        let fuel_after_second = instance.fuel_remaining();

        // Fuel should be roughly the same after each invocation (reset)
        // Allow some variance for different input sizes
        let diff = (fuel_after_first as i64 - fuel_after_second as i64).unsigned_abs();
        assert!(
            diff < 1000,
            "fuel not properly reset: {fuel_after_first} vs {fuel_after_second}"
        );
    }

    // --- Edge cases ---

    #[test]
    fn test_empty_input() {
        let engine = default_engine();
        let compiled = engine.compile("echo", ECHO_WAT.as_bytes()).unwrap();
        let mut instance = engine
            .instantiate(&compiled, HashSet::new(), None)
            .unwrap();

        let result = instance.handle("").unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_large_input() {
        let engine = default_engine();
        let compiled = engine.compile("echo", ECHO_WAT.as_bytes()).unwrap();
        let mut instance = engine
            .instantiate(&compiled, HashSet::new(), None)
            .unwrap();

        let large = "x".repeat(50_000);
        let result = instance.handle(&large).unwrap();
        assert_eq!(result, large);
    }

    #[test]
    fn test_unicode_input() {
        let engine = default_engine();
        let compiled = engine.compile("echo", ECHO_WAT.as_bytes()).unwrap();
        let mut instance = engine
            .instantiate(&compiled, HashSet::new(), None)
            .unwrap();

        let input = "\u{1F680}\u{1F30D} hello \u{4E16}\u{754C}";
        let result = instance.handle(input).unwrap();
        assert_eq!(result, input);
    }

    #[test]
    fn test_log_level_mapping() {
        assert_eq!(LogLevel::from_i32(0), LogLevel::Error);
        assert_eq!(LogLevel::from_i32(1), LogLevel::Warn);
        assert_eq!(LogLevel::from_i32(2), LogLevel::Info);
        assert_eq!(LogLevel::from_i32(3), LogLevel::Debug);
        assert_eq!(LogLevel::from_i32(4), LogLevel::Trace);
        assert_eq!(LogLevel::from_i32(99), LogLevel::Trace); // unknown -> Trace
    }

    #[test]
    fn test_runtime_config_default() {
        let config = RuntimeConfig::default();
        assert_eq!(config.max_memory_bytes, 16 * 1024 * 1024);
        assert_eq!(config.max_fuel, 1_000_000_000);
    }
}
