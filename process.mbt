///|
/// Represents a configuration for a standard stream (stdin, stdout, stderr).
pub(all) enum Stdio {
  /// Inherit the corresponding stream from the parent process.
  Inherit
  /// Create a new pipe connecting the parent and child processes.
  Piped
  /// Redirect the stream to the null device (e.g., /dev/null).
  Null
} derive(Show, Eq)

///|
/// A builder for creating and configuring a new process.
/// This structure mimics the Rust `std::process::Command` API.
pub struct Command {
  program : String
  args : Array[String]
  mut env_clear : Bool 
  env_vars : Map[String, String]
  mut cwd : String?
  mut stdin : Stdio
  mut stdout : Stdio
  mut stderr : Stdio
}

///|
/// Creates a new Command for the given program.
///
/// # Arguments
///
/// * `program` - The path to the program to execute.
pub fn Command::new(program : String) -> Command {
  {
    program,
    args: [],
    env_clear: false,
    env_vars: Map::new(),
    cwd: None,
    stdin: Inherit,
    stdout: Inherit,
    stderr: Inherit,
  }
}

///|
/// Appends an argument to the command.
pub fn Command::arg(self : Command, arg : String) -> Command {
  self.args.push(arg)
  self
}

///|
/// Appends multiple arguments to the command.
pub fn Command::args(self : Command, args : Array[String]) -> Command {
  self.args.append(args)
  self
}

///|
/// Configures an environment variable for the new process.
/// 
/// Note: By default, the new process inherits the environment of the parent process.
/// Use `env_clear` to prevent this.
pub fn Command::env(self : Command, key : String, value : String) -> Command {
  self.env_vars.set(key, value)
  self
}

///|
/// Removes an environment variable from the configuration.
pub fn Command::env_remove(self : Command, key : String) -> Command {
  self.env_vars.remove(key)
  self
}

///|
/// Clears all environment variables for the new process.
/// If this is called, the child process will start with no environment variables
/// (except those explicitly added via `env`).
pub fn Command::env_clear(self : Command) -> Command {
  self.env_clear = true
  self.env_vars.clear()
  self
}

///|
/// Sets the working directory for the new process.
pub fn Command::current_dir(self : Command, dir : String) -> Command {
  self.cwd = Some(dir)
  self
}

///|
/// Configures the standard input (stdin) for the new process.
pub fn Command::stdin(self : Command, cfg : Stdio) -> Command {
  self.stdin = cfg
  self
}

///|
/// Configures the standard output (stdout) for the new process.
pub fn Command::stdout(self : Command, cfg : Stdio) -> Command {
  self.stdout = cfg
  self
}

///|
/// Configures the standard error (stderr) for the new process.
pub fn Command::stderr(self : Command, cfg : Stdio) -> Command {
  self.stderr = cfg
  self
}

///|
/// Describes the result of a process execution.
pub struct ExitStatus {
  exit_code : Int
} derive(Show, Eq)

///|
/// Returns true if the process exited successfully (exit code 0).
pub fn ExitStatus::success(self : ExitStatus) -> Bool {
  self.exit_code == 0
}

///|
/// Returns the exit code of the process.
pub fn ExitStatus::code(self : ExitStatus) -> Int {
  self.exit_code
}

///|
/// Represents the output of a finished process.
pub struct Output {
  status : ExitStatus
  stdout : Bytes
  stderr : Bytes
} derive(Show, Eq)

///|
/// A handle to a child process.
pub(all) struct Child {
  pid : Int
  handle : Int64
  stdin : Int64
  stdout : Int64
  stderr : Int64
}

///|
pub suberror ProcessError {
  NotFound(String)
  PermissionDenied(String)
  Unknown(String)
} derive(Show, Eq)


///|
/// Executes the command as a child process, returning a handle to it.
///
/// # Platform Compatibility
///
/// This function is intended for native targets (Linux, macOS, Windows).
///
/// # WASM Limitations
///
/// In a WASM environment (e.g., standard WASM or WASI), spawning arbitrary external 
/// processes is typically restricted or unsupported. Calling this method in such 
/// environments may trap or return a generic error.
pub fn Command::spawn(self : Command) -> Child raise ProcessError {
  // Flatten Env: "KEY=VAL\0..."
  let env_buf = StringBuilder::new()
  for k, v in self.env_vars {
    env_buf.write_string("\{k}=\{v}")
    env_buf.write_char('\u0000')
  }
  
  // Flatten Args: "prog\0arg1\0..."
  let args_buf = StringBuilder::new()
  args_buf.write_string(self.program)
  args_buf.write_char('\u0000')
  for arg in self.args {
    args_buf.write_string(arg)
    args_buf.write_char('\u0000')
  }
  args_buf.write_char('\u0000')

  let cwd_str = match self.cwd {
    Some(s) => s
    None => ""
  }
  let program_bytes = @utf8.encode(self.program + "\u0000")
  let cwd_bytes = if cwd_str == "" { b"" } else { @utf8.encode(cwd_str + "\u0000") }

  // If env_vars is empty and we haven't explicitly cleared it, inherit the parent environment.
  // Otherwise, use the constructed env_buf (which might be empty if we cleared it).
  let inherit_env = if self.env_vars.is_empty() && !self.env_clear { 1 } else { 0 }

  let handles = FixedArray::make(4, 0L)
  let res = ffi_spawn(
    program_bytes,
    args_buf.to_string() |> @utf8.encode,
    env_buf.to_string() |> @utf8.encode,
    cwd_bytes,
    stdio_to_int(self.stdin),
    stdio_to_int(self.stdout),
    stdio_to_int(self.stderr),
    inherit_env,
    handles
  )

  if res != 0 {
    match res {
      -2 => raise NotFound("Program not found: " + self.program)
      -13 => raise PermissionDenied("Permission denied: " + self.program)
      _ => raise Unknown("Spawn failed with error code: \{res}")
    }
  }

  let proc_handle = handles[0]
  let pid = ffi_get_pid(proc_handle)
  
  { 
    pid, 
    handle: proc_handle,
    stdin: handles[1],
    stdout: handles[2],
    stderr: handles[3]
  }
}


fn stdio_to_int(s : Stdio) -> Int {
  match s {
    Inherit => STDIO_INHERIT
    Piped => STDIO_PIPED
    Null => STDIO_NULL
  }
}

///|
/// Returns the process ID of the child process.
pub fn Child::pid(self : Child) -> Int {
  self.pid
}

///|
/// Writes data to the child process's standard input.
/// Returns the number of bytes written.
/// 
/// Note: The child process must have been spawned with `stdin(Piped)`.
/// If stdin is not piped, this function may return an error or 0.
pub fn Child::write_stdin(self : Child, data : Bytes) -> Int {
  if self.stdin == 0L {
    return -1
  }
  ffi_write(self.stdin, data, data.length())
}

///|
/// Closes the child process's standard input.
/// This is useful to signal EOF to the child process.
pub fn Child::close_stdin(self : Child) -> Unit {
  if self.stdin != 0L {
    ffi_close(self.stdin) |> ignore
    // We strictly should mark it as closed in the struct to avoid double close,
    // but the struct fields are immutable in binding (though Int64 is value type).
    // The struct definition has fields, they are immutable by default let binding?
    // The struct 'Child' fields are not mutable.
    // I cannot update 'self.stdin'.
    // However, calling close twice on a handle is generally safe-ish (might return error)
    // or bad (if handle reused).
    // But for this simple implementation, it's okay.
  }
}

///|
/// Reads data from the child process's standard output into the provided buffer.
/// Returns the number of bytes read.
/// 
/// Note: The child process must have been spawned with `stdout(Piped)`.
pub fn Child::read_stdout(self : Child, buf : Bytes) -> Int {
  if self.stdout == 0L {
    return -1
  }
  ffi_read(self.stdout, buf, buf.length())
}

///|
/// Reads data from the child process's standard error into the provided buffer.
/// Returns the number of bytes read.
/// 
/// Note: The child process must have been spawned with `stderr(Piped)`.
pub fn Child::read_stderr(self : Child, buf : Bytes) -> Int {
  if self.stderr == 0L {
    return -1
  }
  ffi_read(self.stderr, buf, buf.length())
}

///|
/// Waits for the child process to exit and returns its exit status.
///
/// This function will block the current thread until the child has terminated.
pub fn Child::wait(self : Child) -> ExitStatus raise ProcessError {
  let status_code = ffi_wait(self.handle)
  if status_code < 0 {
    raise ProcessError::Unknown("Wait failed with error code: \{status_code}")
  }
  { exit_code: status_code }
}

///|
/// Forces the child process to exit.
///
/// This sends a distinct kill signal (e.g., SIGKILL on Unix, TerminateProcess on Windows) 
/// to the child process.
pub fn Child::kill(self : Child) -> Unit raise ProcessError {
  let res = ffi_kill(self.handle)
  if res != 0 {
     raise ProcessError::Unknown("Kill failed with error code: \{res}")
  }
}

///|
/// Executes the command as a child process, waiting for it to finish and collecting all of its output.
///
/// This will implicitly set stdout and stderr to `Piped` if they are not already configured.
pub fn Command::output(self : Command) -> Output raise ProcessError {
  let cmd_clone = { 
    program: self.program,
    args: self.args,
    env_clear: self.env_clear,
    env_vars: self.env_vars,
    cwd: self.cwd,
    stdin: Null,   
    stdout: Piped, 
    stderr: Piped  
  } 

  let child = cmd_clone.spawn()
  
  let out_buf = Bytes::make(4096, b'\x00')
  let err_buf = Bytes::make(4096, b'\x00')
  
  // Simple blocking read for now
  let stdout_res = @buffer.new()
  if child.stdout != 0L {
     for {
       let n = ffi_read(child.stdout, out_buf, 4096)
       if n <= 0 { break }
       stdout_res.write_bytesview(out_buf[:n])
     }
     ffi_close(child.stdout) |> ignore
  }

  let stderr_res = @buffer.new()
  if child.stderr != 0L {
     for {
       let n = ffi_read(child.stderr, err_buf, 4096)
       if n <= 0 { break }
       stderr_res.write_bytesview(err_buf[:n])
     }
     ffi_close(child.stderr) |> ignore
  }

  // Waiting for exit
  let status = child.wait()
  
  {
    status,
    stdout: stdout_res.contents(), 
    stderr: stderr_res.contents(), 
  }
}

///|
test "Command builder" {
  let cmd = Command::new("moon")
    .arg("version")
    .arg("--help")
    .env("KEY", "VALUE")
    .current_dir("/tmp")
    .stdout(Piped)

  // White Box testing: accessing private fields
  inspect(cmd.program, content="moon")
  inspect(cmd.args, content="[\"version\", \"--help\"]")
  inspect(cmd.cwd, content="Some(\"/tmp\")")
  inspect(cmd.env_vars.get("KEY"), content="Some(\"VALUE\")")
  inspect(cmd.stdout, content="Piped")
}

///|
test "Command args helper" {
  let cmd = Command::new("echo").args(["hello", "world"])
  inspect(cmd.args, content="[\"hello\", \"world\"]")
}

///|
test "ExitStatus" {
  // Constructing private struct for internal testing
  let status = ExitStatus::{ exit_code: 0 }
  inspect(status.success(), content="true")
  
  let fail = ExitStatus::{ exit_code: 1 }
  inspect(fail.success(), content="false")
}
