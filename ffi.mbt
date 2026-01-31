///|
// Constants mapping to Stdio enum
const STDIO_INHERIT = 0
const STDIO_PIPED = 1
const STDIO_NULL = 2

///|
// IO helpers
#borrow(buf)
extern "c" fn ffi_read(handle : Int64, buf : Bytes, size : Int) -> Int = "process_read"
#borrow(buf)
extern "c" fn ffi_write(handle : Int64, buf : Bytes, size : Int) -> Int = "process_write"
extern "c" fn ffi_close(handle : Int64) -> Int = "process_close"

///|
// External function declarations (FFI)
// These functions are expected to be provided by the runtime environment (e.g. C library)
#borrow(program, args_flat, env_flat, cwd, handles_out)
extern "c" fn ffi_spawn(
  program : Bytes,
  args_flat : Bytes,   // Null separated
  env_flat : Bytes,    // Null separated
  cwd : Bytes,         
  stdin : Int,
  stdout : Int,
  stderr : Int,
  inherit_env : Int,
  handles_out: FixedArray[Int64] // Buffer of size 4
) -> Int = "process_spawn"

extern "c" fn ffi_wait(handle : Int64) -> Int = "process_wait"

extern "c" fn ffi_kill(handle : Int64) -> Int = "process_kill"

extern "c" fn ffi_get_pid(handle : Int64) -> Int = "process_get_pid"
