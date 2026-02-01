# Process Library for MoonBit

This library provides facilities for managing external processes, similar to `std::process::Command` in Rust or `os/exec` in Go.

## Features

- **Command Construction**: Builder pattern for configuring command, arguments, environment, and working directory.
- **I/O Redirection**: Support for piping stdin, stdout, and stderr (`Inherit`, `Piped`, `Null`).
- **Process Management**: 
    - `spawn()` for non-blocking execution yielding a `Child` handle.
    - `Child` handle supports:
        - `pid()`: Access the process ID.
        - `wait()`: Wait for completion.
        - `kill()`: Terminate the process.
        - `write_stdin()`, `read_stdout()`, `read_stderr()`, `close_stdin()`: Manual I/O interaction.
- **Convenience**: `output()` method to capture all stdout/stderr and exit status.

## Usage

### Simple Output Capture

```mbt check
///|
test {
  // Example: Running a simple command and capturing output
  let output = Command::new("moon")
    .arg("version")
    .stdout(Piped) // Capture stdout
    .output() catch {
      e => abort("Failed to execute process: \{e}")
    }
  if output.status.success() {
    println("Command succeeded!")
    // Access output.stdout
  }
}
```

### Manual Pipe Interaction

```mbt check
///|
test {
  // Example: Writing to stdin and reading from stdout
  // Note: "grep" needs to be available in your PATH (use "findstr" on Windows)
  let child = Command::new("grep")
    .arg("hello")
    .stdin(Piped)
    .stdout(Piped)
    .spawn()
  // Write to stdin
  let input = @utf8.encode("hello world\ngoodbye\n")
  let _ = child.write_stdin(input)
  child.close_stdin() // Signal EOF

  // Read from stdout
  let buf = Bytes::make(1024, b'\x00')
  let n = child.read_stdout(buf)
  if n > 0 {
    let _out_str = @utf8.decode(buf) // "hello world\n"
    ()
  }
  let _ = child.wait()

}
```

## Platform Compatibility

This library is primarily designed for **native** compilation targets (Linux, macOS, Windows).

### WASM Limitations

In WebAssembly environments (WASM/WASI), the capability to spawn external subprocesses is typically restricted or non-existent. Attempting to use `spawn` or `output` in a WASM environment may result in runtime errors or traps.

## API Overview

- `Command`: The main entry point.
- `Stdio`: Configuration for input/output streams.
- `Child`: Handle to a running process.
- `ExitStatus`: Status code of a terminated process.
