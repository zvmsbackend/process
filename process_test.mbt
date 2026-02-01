///|
test "spawn_and_wait_success" {
  let output = Command::new("moon").arg("version").output() catch {
      e => fail("Failed to execute moon version: \{e}")
    }
  inspect(output.status.success(), content="true")
}

///|
test "spawn_unknown_command" {
  let res = try {
    Command::new("non_existent_command_12345").spawn() |> ignore
    1
  } catch {
    ProcessError::NotFound(_) => 2
    _ => 3
  }
  inspect(res, content="2")
}

///|
test "capture_output" {
  let output = Command::new("moon").arg("version").output() catch {
      e => fail("Failed to capture output: \{e}")
    }
  let len = output.stdout.length()
  inspect(len > 0, content="true")
}

///|
fn is_windows() -> Bool {
  try {
    Command::new("cmd").arg("/c").arg("exit").arg("0").output() |> ignore
    true
  } catch {
    _ => false
  }
}

///|
test "environment_variables" {
  let (cmd, args) = if is_windows() {
    ("cmd", ["/c", "echo %MY_TEST_VAR%"])
  } else {
    ("sh", ["-c", "echo $MY_TEST_VAR"])
  }
  let output = try {
    let mut c = Command::new(cmd)
    for arg in args {
      c = c.arg(arg)
    }
    c.env("MY_TEST_VAR", "my_test_value").output()
  } catch {
    e => fail("Failed to run env test: \{e}")
  }
  let out_str = @utf8.decode(output.stdout)
  inspect(out_str.contains("my_test_value"), content="true")
}

///|
test "cwd_check" {
  let (cmd, args) = if is_windows() {
    ("cmd", ["/c", "cd"])
  } else {
    ("sh", ["-c", "pwd"])
  }
  let output = try {
    let mut c = Command::new(cmd)
    for arg in args {
      c = c.arg(arg)
    }
    c.current_dir("_build").output()
  } catch {
    e => fail("Failed to run cwd test: \{e}")
  }
  let out_str = @utf8.decode(output.stdout)
  inspect(out_str.contains("_build"), content="true")
}

///|
test "args_with_spaces" {
  let dir_name = "test space dir"

  // 1. Cleanup first
  if is_windows() {
    let _ = Command::new("cmd")
      .arg("/c")
      .arg("rmdir")
      .arg("/s")
      .arg("/q")
      .arg(dir_name)
      .output()

  } else {
    let _ = Command::new("rm").arg("-rf").arg(dir_name).output()

  }

  // 2. Create directory with space
  try {
    if is_windows() {
      Command::new("cmd").arg("/c").arg("mkdir").arg(dir_name).output()
      |> ignore
    } else {
      Command::new("mkdir").arg(dir_name).output() |> ignore
    }
  } catch {
    e => fail("Failed to mkdir: \{e}")
  }

  // 3. Check existence
  let found = if is_windows() {
    let out = Command::new("cmd")
      .arg("/c")
      .arg("if")
      .arg("exist")
      .arg(dir_name)
      .arg("echo")
      .arg("found")
      .output()
    @utf8.decode(out.stdout).contains("found")
  } else {
    let out = Command::new("sh")
      .arg("-c")
      .arg("test -d \"" + dir_name + "\" && echo found")
      .output()
    @utf8.decode(out.stdout).contains("found")
  }

  // 4. Cleanup again
  if is_windows() {
    let _ = Command::new("cmd")
      .arg("/c")
      .arg("rmdir")
      .arg("/s")
      .arg("/q")
      .arg(dir_name)
      .output()

  } else {
    let _ = Command::new("rm").arg("-rf").arg(dir_name).output()

  }
  inspect(found, content="true")
}

///|
test "child_io_manual" {
  // Test manual IO with piped stdin/stdout
  let (cmd, args) = if is_windows() {
    ("findstr", ["foo"])
  } else {
    ("grep", ["foo"])
  }
  let child = Command::new(cmd).args(args).stdin(Piped).stdout(Piped).spawn() catch {
      e => fail("Spawn failed: \{e}")
    }
  let input_data = @utf8.encode("foo bar\nbaz qux\nfoo again\n")
  let written = child.write_stdin(input_data)
  inspect(written == input_data.length(), content="true")

  // Close stdin to signal EOF
  child.close_stdin()

  // Read output
  let out_buf = Bytes::make(1024, b'\x00')
  let mut total_read = 0
  let mut res_str = ""

  // Naive read loop
  for {
    let n = child.read_stdout(out_buf)
    if n <= 0 {
      break
    }
    res_str = res_str + out_buf[:n].to_string()
    total_read = total_read + n
  }
  let _ = child.wait()

  // Should contain "foo bar" and "foo again"
  inspect(
    res_str.contains("foo bar") && res_str.contains("foo again"),
    content="true",
  )
  inspect(res_str.contains("baz qux"), content="false") // grep shouldn't output this
}
