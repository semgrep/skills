---
title: Prevent Command Injection
impact: CRITICAL
impactDescription: Remote code execution allowing attackers to run arbitrary commands on the host system
tags: security, command-injection, cwe-78, cwe-94
---

## Prevent Command Injection

Command injection occurs when untrusted input is passed to system shell commands. Attackers can execute arbitrary commands on the host system, potentially downloading malware, stealing data, or taking complete control of the server.

### Language: Python

**Incorrect (vulnerable to command injection via os.system):**
```python
import os
import flask

app = flask.Flask(__name__)

@app.route("/route_param/<route_param>")
def route_param(route_param):
    # ruleid: os-system-injection
    return os.system(route_param)

@app.route("/route_param_concat/<route_param>")
def route_param_concat(route_param):
    # ruleid: os-system-injection
    return os.system("echo " + route_param)

@app.route("/route_param_format/<route_param>")
def route_param_format(route_param):
    # ruleid: os-system-injection
    return os.system("echo {}".format(route_param))
```

**Correct (safe alternatives):**
```python
import os
import flask

app = flask.Flask(__name__)

@app.route("/ok")
def ok():
    # ok: os-system-injection
    os.system("This is fine")

@app.route("/route_param_ok/<route_param>")
def route_param_ok(route_param):
    # ok: os-system-injection
    return os.system("ls -la")
```

**Incorrect (vulnerable to command injection via subprocess):**
```python
import subprocess
import flask

app = flask.Flask(__name__)

@app.route("a")
def a():
    ip = flask.request.args.get("ip")
    # ruleid: subprocess-injection
    subprocess.run("ping "+ ip)

@app.route("b")
def b():
    host = flask.request.headers["HOST"]
    # ruleid: subprocess-injection
    subprocess.run("echo {} > log".format(host))

@app.route("f")
def f():
    event = flask.request.get_json()
    # ruleid: subprocess-injection
    subprocess.run(["bash", "-c", event['id']], shell=True)
```

**Correct (safe subprocess usage):**
```python
import subprocess
import flask

app = flask.Flask(__name__)

@app.route("ok")
def ok():
    ip = flask.request.args.get("ip")
    # ok: subprocess-injection
    subprocess.run(["ping", ip])

@app.route("ok2")
def ok2():
    ip = flask.request.args.get("ip")
    # ok: subprocess-injection
    subprocess.run("echo 'nothing'")

@app.route("d_ok/<cmd>/<ip>")
def d_ok(cmd, ip):
    # ok: subprocess-injection
    subprocess.capture_output(["ping", cmd, ip])
```

**Incorrect (subprocess with shell=True):**
```python
import subprocess
import sys

# ruleid: subprocess-shell-true
subprocess.call("grep -R {} .".format(sys.argv[1]), shell=True)

# ruleid: subprocess-shell-true
subprocess.run("grep -R {} .".format(sys.argv[1]), shell=True)
```

**Correct (avoid shell=True):**
```python
import subprocess
import sys

# ok: subprocess-shell-true
subprocess.call("echo 'hello'")

# ok: subprocess-shell-true
subprocess.call("echo 'hello'", shell=True)  # safe with static string
```

**Incorrect (dangerous os.spawn):**
```python
import os
import sys

cmd = sys.argv[2]

# ruleid: dangerous-spawn-process
os.spawnlp(os.P_WAIT, cmd)

# ruleid: dangerous-spawn-process
os.spawnve(os.P_WAIT, "/bin/bash", ["-c", cmd], os.environ)
```

**Correct (safe os.spawn usage):**
```python
import os

# ok: dangerous-spawn-process
os.spawnlp(os.P_WAIT, "ls")

# ok: dangerous-spawn-process
os.spawnv(os.P_WAIT, "/bin/ls")
```

---

### Language: JavaScript / Node.js

**Incorrect (vulnerable child_process):**
```javascript
const {exec, spawnSync} = require('child_process');
const cp = require('child_process');

function a(args) {
  // ruleid: detect-child-process
  exec(`cat *.js ${args[0]}| wc -l`, (error, stdout, stderr) => {
    console.log(stdout)
  });
}

function a(userInput) {
  // ruleid: detect-child-process
  cp.spawnSync(userInput);
}
```

**Correct (safe child_process usage):**
```javascript
const {exec, spawnSync} = require('child_process');

// ok: detect-child-process
exec('ls')
```

**Incorrect (dangerous spawn with shell: true):**
```javascript
const {spawn, spawnSync} = require('child_process');

// ruleid: spawn-shell-true
const ls = spawn('ls', ['-lh', '/usr'], {shell: true});

// ruleid: spawn-shell-true
const pid = spawnSync('ls', ['-lh', '/usr'], {shell: '/bin/sh'});
```

**Correct (spawn without shell):**
```javascript
const {spawn, spawnSync} = require('child_process');

// ok: spawn-shell-true
spawn('ls', ['-lh', '/usr'], {shell: false});

// ok: spawn-shell-true
spawn('ls', ['-lh', '/usr'], {});
```

**Incorrect (dangerous spawn shell execution):**
```javascript
const {spawn, spawnSync} = require('child_process');
const cp = require('child_process');

function test1(userInput) {
    let name = "bash";
    // ruleid: dangerous-spawn-shell
    spawnSync(name, ["-c", userInput]);
}

function test2(userInput) {
    // ruleid: dangerous-spawn-shell
    cp.spawn('sh', [userInput]);
}
```

**Correct (safe spawn usage):**
```javascript
const {spawn} = require('child_process');

function testOk(userInput) {
    foobar(userInput);
    // ok: dangerous-spawn-shell
    spawn('ls', ['-la', '/tmp']);
}
```

**Incorrect (git clone with user-controlled URL):**
```javascript
const { spawn } = require('child_process');

function downloadGitCommit(gitBranch, gitUrl, sourceCodePath) {
    // ruleid: spawn-git-clone
    const gitClone = spawn('git', [
        'clone',
        '--branch', gitBranch,
        '--depth', '1',
        gitUrl,
        sourceCodePath
    ]);
    return gitClone;
}
```

**Correct (hardcoded git URL):**
```javascript
const { spawn } = require('child_process');

function downloadGitCommitOk() {
    // ok: spawn-git-clone
    const gitClone = spawn('git', [ 'clone', 'https://hardcoded-url.com' ]);
    return res.send('ok');
}
```

**Incorrect (shelljs exec injection):**
```javascript
const shell = require('shelljs');

function test1(userInput) {
    // ruleid: shelljs-exec-injection
    return shell.exec(userInput, {silent: true})
}

function test2(userInput) {
    const input = `ls ${userInput}`
    // ruleid: shelljs-exec-injection
    return shell.exec(input, {silent: true})
}
```

**Correct (safe shelljs usage):**
```javascript
const shell = require('shelljs');

function okTest3(userInput) {
    // ok: shelljs-exec-injection
    const input = 'ls ./'
    return shell.exec(input, {silent: true})
}
```

**Incorrect (Deno dangerous run):**
```javascript
async function test1(userInput) {
  const p = Deno.run({
    // ruleid: deno-dangerous-run
    cmd: [userInput, "hello"],
    stdout: "piped",
    stderr: "piped",
  });

  await p.status();
}

async function test2(userInput) {
  const p = Deno.run({
    // ruleid: deno-dangerous-run
    cmd: ["bash", "-c", userInput],
    stdout: "piped",
    stderr: "piped",
  });

  await p.status();
}
```

**Correct (safe Deno.run):**
```javascript
async function okTest() {
  const p = Deno.run({
    cmd: ["echo", "hello"],
  });

  await p.status();
}
```

---

### Language: Java

**Incorrect (ProcessBuilder with user input):**
```java
public class TestExecutor {

    private Pair<Integer, String> test1(String command, Logger logAppender) throws IOException {
      String[] cmd = new String[3];
      String osName = System.getProperty("os.name");
      if (osName.startsWith("Windows")) {
          cmd[0] = "cmd.exe";
          cmd[1] = "/C";
      } else {
          cmd[0] = "/bin/bash";
          cmd[1] = "-c";
      }
      cmd[2] = command;

      // ruleid: command-injection-process-builder
      ProcessBuilder builder = new ProcessBuilder(cmd);
      builder.redirectErrorStream(true);
      Process proc = builder.start();
      return Pair.newPair(1, "Killed");
    }

    public String test2(String userInput) {
      ProcessBuilder builder = new ProcessBuilder();
      // ruleid: command-injection-process-builder
      builder.command(userInput);
      return "foo";
    }

    public String test3(String userInput) {
      ProcessBuilder builder = new ProcessBuilder();
      // ruleid: command-injection-process-builder
      builder.command("bash", "-c", userInput);
      return "foo";
    }
}
```

**Correct (safe ProcessBuilder usage):**
```java
public class TestExecutor {

    public String okTest() {
      ProcessBuilder builder = new ProcessBuilder();
      // ok: command-injection-process-builder
      builder.command("bash", "-c", "ls");
      return "foo";
    }
}
```

**Incorrect (Runtime.exec with formatted string):**
```java
import java.lang.Runtime;

class Cls {

    public Cls(String input) {
        Runtime r = Runtime.getRuntime();
        // ruleid: command-injection-formatted-runtime-call
        r.exec("/bin/sh -c some_tool" + input);
    }

    public void test1(String input) {
        Runtime r = Runtime.getRuntime();
        // ruleid: command-injection-formatted-runtime-call
        r.loadLibrary(String.format("%s.dll", input));
    }

    public void test2(String input) {
        // ruleid: command-injection-formatted-runtime-call
        Runtime.getRuntime().exec("bash", "-c", input);
    }
}
```

**Correct (safe Runtime usage):**
```java
import java.lang.Runtime;

class Cls {

    public void okTest(String input) {
        Runtime r = Runtime.getRuntime();
        // ok: command-injection-formatted-runtime-call
        r.exec("echo 'blah'");
    }

    public void okTest2(String input) {
        // ok: command-injection-formatted-runtime-call
        Runtime.getRuntime().loadLibrary("lib.dll");
    }
}
```

**Incorrect (tainted HTTP request to command):**
```java
@WebServlet(value = "/cmdi-00/BenchmarkTest00006")
public class bad1 extends HttpServlet {

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String param = "";
        if (request.getHeader("BenchmarkTest00006") != null) {
            param = request.getHeader("BenchmarkTest00006");
        }

        java.util.List<String> argList = new java.util.ArrayList<String>();
        argList.add("sh");
        argList.add("-c");
        // ruleid: tainted-cmd-from-http-request
        argList.add("echo " + param);

        ProcessBuilder pb = new ProcessBuilder();
        pb.command(argList);
        Process p = pb.start();
    }
}
```

**Correct (safe command construction):**
```java
@WebServlet(value = "/cmdi-00/BenchmarkTest00006")
public class ok1 extends HttpServlet {

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        java.util.List<String> argList = new java.util.ArrayList<String>();
        argList.add("sh");
        argList.add("-c");
        // ok: tainted-cmd-from-http-request
        argList.add("echo " + "param");

        ProcessBuilder pb = new ProcessBuilder();
        pb.command(argList);
        Process p = pb.start();
    }
}
```

---

### Language: C#

**Incorrect (Process.Start with user input):**
```csharp
using System.Diagnostics;

namespace Injections
{
    public class OsCommandInjection
    {
        public void RunOsCommand(string command)
        {
            // ruleid: os-command-injection
            var process = Process.Start(command);
        }

        public void RunOsCommandWithArgs(string command, string arguments)
        {
            // ruleid: os-command-injection
            var process = Process.Start(command, arguments);
        }

        public void RunOsCommandWithProcessParam(string command)
        {
            Process process = new Process();
            process.StartInfo.FileName = command;
            // ruleid: os-command-injection
            process.Start();
        }

        public void RunOsCommandWithStartInfo(string command)
        {
            ProcessStartInfo processStartInfo = new ProcessStartInfo()
            {
                FileName = command
            };
            // ruleid: os-command-injection
            var process = Process.Start(processStartInfo);
        }
    }
}
```

**Correct (safe Process.Start usage):**
```csharp
using System.Diagnostics;

namespace Injections
{
    public class OsCommandInjection
    {
        public void RunOsCommand(string command)
        {
            // ok: os-command-injection
            var process = Process.Start("constant");
        }

        public void RunOsCommandWithArgs(string command, string arguments)
        {
            // ok: os-command-injection
            var process = Process.Start("constant", "constant");
        }

        public void RunOsCommandWithStartInfo(string command)
        {
            ProcessStartInfo processStartInfo = new ProcessStartInfo()
            {
                FileName = "constant"
            };
            // ok: os-command-injection
            var process = Process.Start(processStartInfo);
        }
    }
}
```

---

### Language: Scala

**Incorrect (dangerous process run with user input):**
```scala
class TestOsCommand {

  def executeCommand(value: String) = Action {
    import sys.process._

    // ruleid: scala-dangerous-process-run
    val result = value.!!
    Ok("Result:\n"+result)
  }

  def executeCommand2(value: String) = Action {
    import sys.process._

    // ruleid: scala-dangerous-process-run
    val result = value !
    Ok("Result:\n"+result)
  }
}
```

**Correct (safe process usage):**
```scala
class TestOsCommand {

  def executeCommand4(value: String) = Action {
    import sys.process._

    // ok: scala-dangerous-process-run
    val cmd = "ls -lah"
    val result = cmd.!
    Ok("Result:\n"+result)
  }

  def executeCommand6() = Action {
    import sys.process._

    // ok: scala-dangerous-process-run
    val result = Seq("ls", "-lah").!!
    Ok("Result:\n"+result)
  }
}
```

**Incorrect (dangerous shell run with user input):**
```scala
class Foo {
  def run1(message: String) = {
    import sys.process._
    // ruleid: dangerous-shell-run
    Seq("sh", "-c", message).!
  }

  def run2(message: String) = {
    import sys.process._
    // ruleid: dangerous-shell-run
    val result = Seq("bash", "-c", message).!!
    return result
  }
}
```

**Correct (safe shell usage):**
```scala
class Foo {
  def run3(message: String) = {
    import sys.process._
    // ok: dangerous-shell-run
    Seq("ls", "-la").!!
  }

  def run4(message: String) = {
    import sys.process._
    // ok: dangerous-shell-run
    Seq("sh", "-c", "ls").!!
  }
}
```

**Incorrect (dangerous Seq run):**
```scala
class Foo {
  def run1(command: String, arg1: String) = {
    import sys.process._
    // ruleid: dangerous-seq-run
    Seq(command, arg1).!
  }

  def run2(command: String) = {
    import sys.process._
    // ruleid: dangerous-seq-run
    val result = Seq(command, "--some-arg").!!
    return result
  }
}
```

**Correct (safe Seq usage):**
```scala
class Foo {
  def run3(message: String) = {
    import sys.process._
    // ok: dangerous-seq-run
    Seq("ls", "-la").!!
  }
}
```

---

### Language: Kotlin

**Incorrect (Runtime.exec with formatted string):**
```kotlin
class Cls {
    fun Cls(input: String) {
        val r: Runtime = Runtime.getRuntime()
        // ruleid: command-injection-formatted-runtime-call
        r.exec("/bin/sh -c some_tool" + input)
    }

    fun test1(input: String) {
        val r: Runtime = Runtime.getRuntime()
        // ruleid: command-injection-formatted-runtime-call
        r.loadLibrary(String.format("%s.dll", input))
    }
}
```

**Correct (safe Runtime usage):**
```kotlin
class Cls {
    fun test2(input: String) {
        val r: Runtime = Runtime.getRuntime()
        // ok: command-injection-formatted-runtime-call
        r.exec("echo 'blah'")
    }
}
```

---

### Language: Ruby

**Incorrect (Shell methods with tainted input):**
```ruby
def foo
  # ruleid: avoid-tainted-shell-call
  Shell.cat(params[:filename])

  sh = Shell.cd("/tmp")
  # ruleid: avoid-tainted-shell-call
  sh.open(params[:filename])

  sh = Shell.new
  fn = params[:filename]
  # ruleid: avoid-tainted-shell-call
  sh.open(fn)
end
```

**Correct (safe Shell usage):**
```ruby
def foo
  # ok: avoid-tainted-shell-call
  Shell.cat("/var/log/www/access.log")
end
```

---

### Language: PHP

**Incorrect (command execution with user input):**
```php
<?php
// ruleid: wp-command-execution-audit
exec('rm -rf ' . $dir, $o, $r);

// ruleid: wp-command-execution-audit
$stderr = shell_exec($command);

// ruleid: eval-use
eval($user_input);
?>
```

**Correct (safe command usage):**
```php
<?php
// ok: wp-command-execution-audit
some_other_safe_function($args);

// ok: eval-use
eval('echo "OK"');
?>
```

---

### Language: Go

**Incorrect (dangerous command write):**
```go
import (
  "fmt"
  "os/exec"
)

func test1(password string) {
  cmd := exec.Command("bash")
  cmdWriter, _ := cmd.StdinPipe()
  cmd.Start()

  cmdString := fmt.Sprintf("sshpass -p %s", password)

  // ruleid: dangerous-command-write
  cmdWriter.Write([]byte(cmdString + "\n"))

  cmd.Wait()
}
```

**Correct (safe command usage):**
```go
import (
  "os/exec"
)

func okTest1() {
  cmd := exec.Command("bash")
  cmdWriter, _ := cmd.StdinPipe()
  cmd.Start()

  // ok: dangerous-command-write
  cmdWriter.Write([]byte("sshpass -p 123\n"))
  cmdWriter.Write([]byte("exit" + "\n"))

  cmd.Wait()
}
```

---

### Language: OCaml

**Incorrect (executing external programs):**
```ocaml
#load "unix.cma";;
let p = String.concat "ls " [" "; Sys.argv.(1)]
(* ruleid: ocamllint-exec *)
let a = Unix.execve p
(* ruleid: ocamllint-exec *)
let b = Unix.execvp p
(* ruleid: ocamllint-exec *)
let d = Unix.system p
(* ruleid: ocamllint-exec *)
let e = Sys.command p
```

---

### Framework-Specific: AWS Lambda (Python)

**Incorrect (dangerous subprocess in Lambda):**
```python
import subprocess

def handler(event, context):
  # ruleid: dangerous-subprocess-use
  subprocess.call("grep -R {} .".format(event['id']), shell=True)

  cmd = event['id'].split()
  # ruleid: dangerous-subprocess-use
  subprocess.call([cmd[0], cmd[1], "some", "args"], shell=True)
```

**Correct (safe subprocess in Lambda):**
```python
import subprocess

def handler(event, context):
  # ok: dangerous-subprocess-use
  subprocess.call("echo 'hello'")

  # ok: dangerous-subprocess-use
  subprocess.call(["echo", "a", ";", "rm", "-rf", "/"])
```

**Incorrect (dangerous system call in Lambda):**
```python
import os

def handler(event, context):
    # ruleid: dangerous-system-call
    os.system(f"ls -la {event['dir']}")
```

**Correct (safe system call in Lambda):**
```python
import os

def handler(event, context):
    # ok: dangerous-system-call
    os.system("ls -al")

    # ok: dangerous-system-call
    os.popen("cat contents.txt")
```

---

### Framework-Specific: AWS Lambda (JavaScript)

**Incorrect (child_process in Lambda):**
```javascript
const cp = require('child_process');

exports.handler = async (event) => {
    // ruleid: detect-child-process
    cp.exec(`cat *.js ${event['file']}| wc -l`, (error, stdout, stderr) => {
        console.log(stdout)
    });

    // ruleid: detect-child-process
    cp.spawnSync(event['cmd']);
};
```

**Correct (safe child_process in Lambda):**
```javascript
const cp = require('child_process');

exports.handler = async (event) => {
    // ok: detect-child-process
    cp.exec('ls')
};
```

---

### Framework-Specific: Apache Airflow

**Incorrect (formatted string in BashOperator):**
```python
from airflow.operators.bash_operator import BashOperator
import requests

message = requests.get("https://fakeurl.asdf/message").text
# ruleid: formatted-string-bashoperator
t1 = BashOperator(
    task_id="print_date",
    bash_command="echo " + message,
    dag=dag
)

howlong = requests.get("https://fakeurl.asdf/howlong").text
# ruleid: formatted-string-bashoperator
command = "sleep {}".format(howlong)
t2 = BashOperator(
    task_id="sleep",
    bash_command=command,
    dag=dag
)
```

**Correct (safe BashOperator usage):**
```python
from airflow.operators.bash_operator import BashOperator

# ok: formatted-string-bashoperator
t5 = BashOperator(
    task_id="safe",
    bash_command="echo hello world!",
    dag=dag
)

# ok: formatted-string-bashoperator
templated_command = """
{% for i in range(5) %}
    echo "{{ ds }}"
    echo "{{ params.my_param }}"
{% endfor %}
"""

t4 = BashOperator(
    task_id="safe_templated",
    bash_command=templated_command,
    params={"my_param": "Parameter I passed in"},
    dag=dag
)
```

---

**References:**
- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- CWE-94: Improper Control of Generation of Code ('Code Injection')
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [OWASP Top 10 A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection)
- [Semgrep Python Command Injection Cheat Sheet](https://semgrep.dev/docs/cheat-sheets/python-command-injection/)
- [Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html#do-not-use-dangerous-functions)
- [OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
