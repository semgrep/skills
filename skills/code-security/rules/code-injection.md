---
title: Prevent Code Injection
impact: CRITICAL
---

## Prevent Code Injection

Code injection vulnerabilities occur when an attacker can insert and execute arbitrary code within your application. This includes direct code evaluation (eval, exec), template injection (SSTI), reflection-based attacks, and dynamic method invocation. These vulnerabilities can lead to complete system compromise, data theft, and remote code execution.

**Incorrect (Python - eval/exec with user input):**

```python
# Direct eval with user input - VULNERABLE
def unsafe(request):
    code = request.POST.get('code')
    print("something")
    eval(code)

def unsafe_inline(request):
    eval(request.GET.get('code'))

def unsafe_dict(request):
    eval(request.POST['code'])

# Dynamic string formatting in eval - VULNERABLE
dynamic = "import requests; r = requests.get('{}')"
eval(dynamic.format("https://example.com"))

def eval_something(something):
    eval(something)

user_input = get_userinput()
eval(f"some_func({user_input})")

# exec with user input - VULNERABLE
def unsafe_exec(request):
    code = request.POST.get('code')
    exec(code)

async def run_exec_by_event_loop(request):
    code = request.POST["code"]
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, exec, code)
```

**Correct (Python - static eval/exec with hardcoded strings):**

```python
# Static eval with hardcoded strings - SAFE
eval("x = 1; x = x + 2")

blah = "import requests; r = requests.get('https://example.com')"
eval(blah)

def safe(request):
    code = """
    print('hello')
    """
    eval(dedent(code))

# Static exec with hardcoded strings - SAFE
exec("x = 1; x = x + 2")

blah1 = "import requests; r = requests.get('https://example.com')"
exec(blah1)
```

**Incorrect (Python - globals/locals with user input):**

```python
def test1(request):
    forward = request.GET.get('fwd')
    globs = globals()
    # Attacker can access any global function
    function = globs.get(forward)

    if function:
        return function(request)

def test2(request):
    forward = request.GET.get('fwd')
    # Attacker can access local scope
    function = locals().get(forward)

def test3(request):
    forward = request.GET.get('fwd')
    # Direct __globals__ access is dangerous
    function = test1.__globals__[forward]
```

**Correct (Python - static globals/locals key lookup):**

```python
def okTest():
    # Static key lookup is safe
    function = locals().get("test3")

    if function:
        return function(request)

def okTest2(data):
    # Using globals with static keys is safe
    list_of_globals = globals()
    list_of_globals["foobar"].update(data)
```

**Incorrect (Python - Flask/Django template injection):**

```python
# Flask SSTI - VULNERABLE
@app.route("/error")
def error(e):
    template = '''{  extends "layout.html"  }
{  block body  }
    <div class="center-content error">
        <h1>Oops! That page doesn't exist.</h1>
        <h3>%s</h3>
    </div>
{  endblock  }
'''.format(request.url)
    return flask.render_template_string(template), 404

# Using locals()/globals() as template context - VULNERABLE
def bad1(request):
    response = render(request, 'vulnerable/xss/form.html', locals())
    return response

def bad2(request, path='default'):
    env = globals()
    return render(request, 'vulnerable/xss/path.html', env)
```

**Correct (Python - passing specific variables to templates):**

```python
# Pass specific variables, not entire scope - SAFE
def file_access(request):
    msg = request.GET.get('msg', '')
    return render(request, 'vulnerable/injection/file_access.html',
            {'msg': msg})
```

**Incorrect (Python - AWS Lambda code execution):**

```python
def handler(event, context):
    dynamic1 = "import requests; r = requests.get('{}')"
    # User-controlled event data in exec - VULNERABLE
    exec(dynamic1.format(event['url']))

    dynamic2 = "import requests; r = requests.get('{}')"
    # User-controlled event data in eval - VULNERABLE
    eval(dynamic2.format(event['url']))
```

**Correct (Python - AWS Lambda with static strings):**

```python
def handler(event, context):
    # Static strings are safe
    exec("x = 1; x = x + 2")

    blah1 = "import requests; r = requests.get('https://example.com')"
    exec(blah1)
```

**Incorrect (JavaScript - browser eval with dynamic content):**

```javascript
let dynamic = window.prompt() // arbitrary user input

// Dynamic content in eval - VULNERABLE
eval(dynamic + 'possibly malicious code');

eval(`${dynamic} possibly malicious code`);

eval(dynamic.concat(''));

function evalSomething(something) {
    eval(something);
}

// Template literals with user input - VULNERABLE
window.eval(`alert('${location.href}')`)

let funcName = new URLSearchParams(window.location.search).get('a')
var x = new Function(`return ${funcName}(a,b)`)
```

**Correct (JavaScript - static eval strings):**

```javascript
// Static strings are safe
eval('var x = "static strings are okay";');

const constVar = "function staticStrings() { return 'static strings are okay';}";
eval(constVar);

// Concatenating constants is safe
eval(`${constVar}`);

const secondConstVar = 'this is a const variable';
eval(constVar + secondConstVar);
```

**Incorrect (JavaScript - Express request data in eval):**

```javascript
function test1(req,res) {
  const data = JSON.stringify(req.query.key);
  const command = `(secret) => {${data}}`
  // Request data flows to eval - VULNERABLE
  return eval(command)
}

test2.post(foo, bar, function (req,res) {
  userInput = req.params.input
  var command = "new Function('"+userInput+"')";
  return eval(command)
});
```

**Correct (JavaScript - static command in eval):**

```javascript
function ok1(req,res) {
  var command = "eval('123')";
  // Static command is safe
  return eval(command)
}
```

**Incorrect (JavaScript - unsafe dynamic method invocation):**

```javascript
function test1(data) {
  const message = JSON.parse(data);
  // Attacker controls which function is called - VULNERABLE
  window[message.name](message.payload);
}

function test2(data) {
  const message = JSON.parse(data);
  const action = window[message.name];
  action(message.payload);
}
```

**Correct (JavaScript - whitelist check before dynamic call):**

```javascript
let api = {
  foo: function () { /* do smth */ },
  bar: function () { /* do smth */ }
}

function okTest1(data) {
  const message = JSON.parse(data);
  // Whitelist check before dynamic call - SAFE
  if (!api.hasOwnProperty(message.name)) {
    return;
  }
  api[message.name](message.payload);
}

function okTest2(data) {
  // Static property access is safe
  const result = api["foo"](data);
}
```

**Incorrect (JavaScript - non-literal require):**

```javascript
function dynamicRequire1(packageName) {
    // User controls which module is loaded - VULNERABLE
    var a = require(packageName)
    return a;
}

function dynamicRequire2(source, file) {
    require(path.resolve(process.cwd(), file, source));
}
```

**Correct (JavaScript - static require):**

```javascript
function okDynamicRequire4(userInput) {
    // Static string is safe
    var a = require('b')
}

function okDynamicRequire5(userInput) {
    // Environment variables are generally safe
    var a = require(process.env.VAR)
}
```

**Incorrect (JavaScript - Node.js VM module injection):**

```javascript
const vm = require('vm')

exports.handler = async (event) => {
    var input = event['something']
    var sandbox = {
        foo: input
    }
    // Tainted sandbox - VULNERABLE
    vm.runInNewContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })

    const code = `
        var x = ${event['something']};
    `
    // Tainted code - VULNERABLE
    vm.runInThisContext(code)

    // Tainted script - VULNERABLE
    const script = new vm.Script(`
        function add(a, b) {
          return a + ${event['something']};
        }
    `);
    script.runInThisContext();
}
```

**Correct (JavaScript - static VM sandbox and code):**

```javascript
const vm = require('vm')

exports.handler = async (event) => {
    // Static sandbox - SAFE
    var sandbox2 = {
        foo: 1
    }
    vm.createContext(sandbox2)
    vm.runInContext('safeEval(orderLinesData)', sandbox2, { timeout: 2000 })

    const code2 = `
        var x = 1;
    `
    // Static code - SAFE
    vm.runInThisContext(code2)

    // Static script - SAFE
    const script1 = new vm.Script(`
        function add(a, b) {
          return a + b;
        }
    `);
    script1.runInThisContext();
}
```

**Incorrect (JavaScript - vm2 sandbox injection):**

```javascript
const {VM, NodeVM} = require('vm2');

async function test1(code, input) {
  code = `
    console.log(${input})
  `;

  // Tainted code in VM - VULNERABLE
  return new VM({
    timeout: 40 * 1000,
    sandbox
  }).run(code);
}

function test2(input) {
  const nodeVM = new NodeVM({timeout: 40 * 1000, sandbox});
  // String concatenation with input - VULNERABLE
  return nodeVM.run('console.log(' + input + ')')
}

// Tainted sandbox - VULNERABLE
async function test1(input) {
  const sandbox = {
    setTimeout,
    watch: input
  };

  return new VM({timeout: 40 * 1000, sandbox}).run(code);
}
```

**Correct (JavaScript - static vm2 code):**

```javascript
const {VM, NodeVM} = require('vm2');

async function okTest1(code) {
  code = `
    console.log("Hello world")
  `;

  // Static code - SAFE
  return new VM({
    timeout: 40 * 1000,
    sandbox
  }).run(code);
}

function okTest2() {
  const nodeVM = new NodeVM({timeout: 40 * 1000, sandbox});
  // Static string - SAFE
  return nodeVM.run('console.log("Hello world")')
}
```

**Incorrect (JavaScript - Express template injection SSTI):**

```javascript
app.get('/', function(req, res) {
    let tainted = req.query.id;

    // User data in template compilation - VULNERABLE
    pug.compile(tainted);
    pug.render(tainted);
    jade.compile(tainted);
    jade.render(tainted);
    dot.template(tainted);
    ejs.render(tainted);
    nunjucks.renderString(tainted);
    lodash.template(tainted);
    dot.compile(tainted);
    handlebars.compile(req.query.id);
    mustache.render(req.body._);
    Hogan.compile(tainted);
    Eta.render(tainted);
    Sqrl.render(tainted);
});
```

**Incorrect (JavaScript - AWS Lambda eval injection):**

```javascript
exports.handler = async (event) => {
    // Event data in eval - VULNERABLE
    eval(event['smth'])

    var x = new Function('a', 'b', `return ${event['func']}(a,b)`)

    var y = Function('a', 'b', event['code'])
}
```

**Correct (JavaScript - AWS Lambda static eval):**

```javascript
exports.handler = async (event) => {
    // Static eval is safe
    eval('alert')
}
```

**Incorrect (Ruby - dangerous eval):**

```ruby
# Tainted cookie in eval - VULNERABLE
Array.class_eval(cookies['tainted_cookie'])

b = params['something']
# User input in module_eval - VULNERABLE
Thing.module_eval(b)

# Direct param access - VULNERABLE
eval(b)
eval(b,some_binding)
eval(params['cmd'],b)
eval(params.dig('cmd'))
eval(cookies.delete('foo'))

# Dynamic RubyVM compilation - VULNERABLE
RubyVM::InstructionSequence.compile(foo).eval

iseq = RubyVM::InstructionSequence.compile(foo)
iseq.eval
```

**Correct (Ruby - static eval):**

```ruby
def zen
  41
end

# Static eval is safe
eval("def zen; 42; end")

class Thing
end
a = %q{def hello() "Hello there!" end}
# Not user-controllable, this is safe
Thing.module_eval(a)

def get_binding(param)
  binding
end
b = get_binding("hello")
# Static function call is safe
b.eval("some_func")

eval("some_func",b)

# Static RubyVM compilation is safe
RubyVM::InstructionSequence.compile("1 + 2").eval

iseq = RubyVM::InstructionSequence.compile('num = 1 + 2')
iseq.eval
```

**Incorrect (Ruby - unsafe reflection with constantize):**

```ruby
class HomeController < ApplicationController

  def unsafe_reflection
    table = params["table"]
    # User controls which class is instantiated - VULNERABLE
    model = table.classify.constantize
    @result = model.send(:method)
  end
end
```

**Correct (Ruby - static string reflection):**

```ruby
class HomeController < ApplicationController

  def ok_reflection
    foo = "SomeClass"
    # Static string is safe
    foo.classify.constantize
  end
end
```

**Incorrect (Ruby - unsafe reflection with tap/method/to_proc):**

```ruby
class GroupsController < ApplicationController

  def dynamic_method_invocations
    # User input to to_proc - VULNERABLE
    params[:method].to_sym.to_proc.call(Kernel)

    # User input to method() - VULNERABLE
    (params[:klass].to_s).method(params[:method]).(params[:argument])

    # User input to tap - VULNERABLE
    Kernel.tap(&params[:method].to_sym)

    user_input_value = params[:my_user_input]
    anything.tap(&user_input_value.to_sym)
    anything_else.tap { |thing| thing + user_input_value() }
  end
end
```

**Correct (Ruby - static strings in reflection methods):**

```ruby
class GroupsController < ApplicationController

  def dynamic_method_invocations_ok
    # Static strings are safe
    "SomeClass".to_sym.to_proc.call(Kernel)
    SomeClass.method("some_method").("some_argument")
    Kernel.tap("SomeClass".to_sym)

    user_input_value = params[:my_user_input]
    # Calling method on user input (not with user input) is safe
    user_input_value.tap("some_method")
  end
end
```

**Incorrect (Ruby - dangerous send with user input):**

```ruby
def bad_send
    method = params[:method]
    # User controls which method is called - VULNERABLE
    @result = User.send(method.to_sym)
end
```

**Correct (Ruby - validated send with ternary):**

```ruby
def ok_send
    # Ternary ensures only known methods are called - SAFE
    method = params[:method] == 1 ? :method_a : :method_b
    @result = User.send(method, *args)
end
```

**Incorrect (Ruby - dangerous exec/spawn/system):**

```ruby
def test_params()
  user_input = params['some_key']

  # String interpolation with user input - VULNERABLE
  exec("ls -lah #{user_input}")
  Process.spawn([user_input, "smth"])
  output = exec(["sh", "-c", user_input])
  pid = spawn(["bash", user_input])
end

def test_cookies()
  user_input = cookies['some_cookie']
  exec("ls -lah #{user_input}")
end
```

**Correct (Ruby - static exec/spawn/system commands):**

```ruby
def test_params()
  commands = "ls -lah /raz/dva"
  # Static commands are safe
  system(commands)

  cmd_name = "sh"
  Process.exec([cmd_name, "ls", "-la"])
  Open3.capture2({"FOO" => "BAR"}, [cmd_name, "smth"])
  system("ls -lah /tmp")
  exec(["ls", "-lah", "/tmp"])
end
```

**Incorrect (Ruby - dangerous subshell with interpolation):**

```ruby
def test_calls(user_input)
  # Backticks with interpolation - VULNERABLE
  result = `foo #{user_input} bar`
  result2 = %x{foo #{user_input} bar}
  cmd = `foo #{user_input} bar #{smth_else}`
end
```

**Correct (Ruby - static subshell commands):**

```ruby
def test_calls(user_input)
  # Static commands are safe
  smth = `ls testdir`.split[1]
  ok_cmd = `echo oops && exit 99`

  hardcode = "testdir"
  ok_cmd2 = %{ls #{hardcode} -lah}
end
```

**Incorrect (Ruby - Marshal cookie serialization):**

```ruby
class Bad_cookie_serialization
  # Marshal deserialization is dangerous - VULNERABLE
  Rails.application.config.action_dispatch.cookies_serializer = :hybrid
  Rails.application.config.action_dispatch.cookies_serializer = :marshal
end
```

**Correct (Ruby - JSON cookie serialization):**

```ruby
class Cookie_serialization
  # JSON serialization is safe
  Rails.application.config.action_dispatch.cookies_serializer = :json
end
```

**Incorrect (Java - ScriptEngine injection):**

```java
public class ScriptEngineSample {

    private static ScriptEngineManager sem = new ScriptEngineManager();
    private static ScriptEngine se = sem.getEngineByExtension("js");

    // User input in script evaluation - VULNERABLE
    public static void scripting(String userInput) throws ScriptException {
        Object result = se.eval("test=1;" + userInput);
    }

    public static void scripting1(String userInput) throws ScriptException {
        ScriptEngineManager scriptEngineManager = new ScriptEngineManager();
        ScriptEngine scriptEngine = scriptEngineManager.getEngineByExtension("js");
        Object result = scriptEngine.eval("test=1;" + userInput);
    }
}
```

**Correct (Java - static ScriptEngine evaluation):**

```java
public class ScriptEngineSample {

    // Static script is safe
    public static void scriptingSafe() throws ScriptException {
        ScriptEngineManager scriptEngineManager = new ScriptEngineManager();
        ScriptEngine scriptEngine = scriptEngineManager.getEngineByExtension("js");
        String code = "var test=3;test=test*2;";
        Object result = scriptEngine.eval(code);
    }
}
```

**Incorrect (Java - Spring Expression Language SpEL injection):**

```java
public class SpelSample {

    // User input in SpEL expression - VULNERABLE
    public static void parseExpressionInterface1(String property) {
        ExpressionParser parser = new SpelExpressionParser();
        StandardEvaluationContext testContext = new StandardEvaluationContext(TEST_PERSON);
        Expression exp2 = parser.parseExpression(property+" == 'Benoit'");
        String dynamicValue = exp2.getValue(testContext, String.class);
    }

    public static void parseSpelExpression3(String property) {
        SpelExpressionParser parser = new SpelExpressionParser();
        StandardEvaluationContext testContext = new StandardEvaluationContext(TEST_PERSON);
        Expression exp2 = parser.parseExpression(property+" == 'Benoit'");
    }
}
```

**Correct (Java - static SpEL expression):**

```java
public class SpelSample {

    // Static expression is safe
    public static void parseExpressionInterface2(String property) {
        ExpressionParser parser = new SpelExpressionParser();
        Expression exp1 = parser.parseExpression("'safe expression'");
        String constantValue = exp1.getValue(String.class);
    }
}
```

**Incorrect (Java - OGNL injection):**

```java
public class OgnlReflectionProviderSample {

    // User input in OGNL - VULNERABLE
    public void unsafeOgnlReflectionProvider(String input, OgnlReflectionProvider reflectionProvider, Class type) {
        reflectionProvider.getGetMethod(type, input);
    }

    public void unsafeOgnlReflectionProvider1(String input, ReflectionProvider reflectionProvider) {
        reflectionProvider.getValue(input, null, null);
    }

    public void unsafeOgnlReflectionProvider3(String input, OgnlTextParser reflectionProvider) {
        reflectionProvider.evaluate( input );
    }
}
```

**Correct (Java - static OGNL input):**

```java
public class OgnlReflectionProviderSample {

    // Static input is safe
    public void safeOgnlReflectionProvider1(OgnlReflectionProvider reflectionProvider, Class type) {
        String input = "thisissafe";
        reflectionProvider.getGetMethod(type, input);
    }

    public void safeOgnlReflectionProvider2(OgnlReflectionProvider reflectionProvider, Class type) {
        reflectionProvider.getField(type, "thisissafe");
    }
}
```

**Incorrect (Java - Expression Language EL injection):**

```java
public class ElExpressionSample {

    // User input in EL expression - VULNERABLE
    public void unsafeEL(String expression) {
        FacesContext context = FacesContext.getCurrentInstance();
        ExpressionFactory expressionFactory = context.getApplication().getExpressionFactory();
        ELContext elContext = context.getELContext();
        ValueExpression vex = expressionFactory.createValueExpression(elContext, expression, String.class);
        String result = (String) vex.getValue(elContext);
    }

    public void unsafeELMethod(ELContext elContext, ExpressionFactory expressionFactory, String expression) {
        expressionFactory.createMethodExpression(elContext, expression, String.class, new Class[]{Integer.class});
    }

    private void unsafeELTemplate(String message, ConstraintValidatorContext context) {
         context.disableDefaultConstraintViolation();
         context
             .someMethod()
             .buildConstraintViolationWithTemplate(message)
             .addConstraintViolation();
    }
}
```

**Correct (Java - static EL expression):**

```java
public class ElExpressionSample {

    // Static expression is safe
    public void safeEL() {
        FacesContext context = FacesContext.getCurrentInstance();
        ExpressionFactory expressionFactory = context.getApplication().getExpressionFactory();
        ELContext elContext = context.getELContext();
        ValueExpression vex = expressionFactory.createValueExpression(elContext, "1+1", String.class);
        String result = (String) vex.getValue(elContext);
    }

    private void safeELTemplate(String message, ConstraintValidatorContext context) {
         context.disableDefaultConstraintViolation();
         context
             .someMethod()
             .buildConstraintViolationWithTemplate("somestring")
             .addConstraintViolation();
    }
}
```

**Incorrect (Java - Groovy shell injection):**

```java
public class GroovyShellUsage {

    public static void test1(String uri, String file, String script) {
        GroovyShell shell = new GroovyShell();

        // User input in evaluate - VULNERABLE
        shell.evaluate(new File(file));
        shell.evaluate(new InputStreamReader(new FileInputStream(file)), "script1.groovy");
        shell.evaluate(script);
        shell.evaluate(script, "script1.groovy", "test");
        shell.evaluate(new URI(uri));
    }

    public static void test2(String uri, String file, String script) {
        GroovyShell shell = new GroovyShell();

        // User input in parse - VULNERABLE
        shell.parse(new File(file));
        shell.parse(script);
        shell.parse(new URI(uri));
    }

    public static void test3(String script, ClassLoader loader) {
        GroovyClassLoader groovyLoader = (GroovyClassLoader) loader;

        // User input in parseClass - VULNERABLE
        groovyLoader.parseClass(script);
        groovyLoader.parseClass(script,"test.groovy");
    }
}
```

**Correct (Java - static Groovy shell scripts):**

```java
public class GroovyShellUsage {

    public static void test1() {
        GroovyShell shell = new GroovyShell();
        // Static script is safe
        shell.evaluate("hardcoded script");
    }

    public static void test2() {
        GroovyShell shell = new GroovyShell();
        String hardcodedScript = "test.groovy";
        // Hardcoded path is safe
        shell.parse(hardcodedScript);
    }
}
```

**Incorrect (Java - Seam log injection):**

```java
public class HttpRequestDebugFilter implements Filter {
    Log log = Logging.getLog(HttpRequestDebugFilter.class);

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
        if (request instanceof HttpServletRequest) {
            HttpServletRequest httpRequest = (HttpServletRequest)request;
            // String concatenation in log - VULNERABLE (EL evaluation)
            log.info("request: method="+httpRequest.getMethod()+", URL="+httpRequest.getRequestURI());
        }
    }

    public void logUser(User user) {
        // User data in string concatenation - VULNERABLE
        log.info("Current logged in user : " + user.getUsername());
    }
}
```

**Correct (Java - parameterized Seam logging):**

```java
public class HttpRequestDebugFilter implements Filter {
    Log log = Logging.getLog(HttpRequestDebugFilter.class);

    public void logUser(User user) {
        // Parameterized logging prevents EL injection - SAFE
        log.info("Current logged in user : #0", user.getUsername());
    }
}
```

**Incorrect (Go - dangerous exec.Command with user input):**

```go
func runCommand1(userInput string) {
    // User controls command - VULNERABLE
    cmd := exec.Command(userInput, "foobar")
    cmd.Run()
}

func runCommand2(userInput string) {
    execPath, _ := exec.LookPath(userInput)
    // User controls path lookup - VULNERABLE
    cmd := exec.Command(execPath, "foobar")
    cmd.Run()
}

func runCommand4(userInput string) {
    // User input passed to shell - VULNERABLE
    cmd := exec.Command("bash", "-c", userInput)
    cmd.Run()
}

func runcommand5(s string) (string, error) {
    // Function parameter in shell command - VULNERABLE
    cmd := exec.Command("/usr/bin/env", "bash", "-c", s)
    return cmd.CombinedOutput()
}
```

**Correct (Go - static exec.Command):**

```go
func okCommand1(userInput string) {
    goExec, _ := exec.LookPath("go")
    // Static command is safe
    cmd := exec.Command(goExec, "version")
    cmd.Run()
}

func okCommand2(userInput string) {
    // Static command is safe
    cmd := exec.Command("go", "version")
    cmd.Run()
}

func okCommand3(s string) (string, error) {
    someCommand := "w"
    // Hardcoded command is safe
    cmd := exec.Command("/usr/bin/env", "bash", "-c", someCommand)
    return cmd.CombinedOutput()
}
```

**Incorrect (Go - dangerous exec.Cmd struct with user input):**

```go
func test1(userInput string) {
    cmdPath,_ := userInput;

    // User controls Path - VULNERABLE
    cmd := &exec.Cmd {
        Path: cmdPath,
        Args: []string{ "foo", "bar" },
    }
    cmd.Start();
}

func test3(userInput string) {
    cmdPath,_ := exec.LookPath("bash");

    // User controls Args - VULNERABLE
    cmd := &exec.Cmd {
        Path: cmdPath,
        Args: []string{ cmdPath, "-c", userInput },
    }
    cmd.Start();
}
```

**Correct (Go - static exec.Cmd struct):**

```go
func okTest1(userInput string) {
    cmdPath,_ := exec.LookPath("go");

    // Static path and args are safe
    cmd := &exec.Cmd {
        Path: cmdPath,
        Args: []string{ cmdPath, "bar" },
    }
    cmd.Start();
}
```

**Incorrect (Go - dangerous syscall.Exec with user input):**

```go
func test1(userInput string) {
    // User controls binary path - VULNERABLE
    binary, _ := exec.LookPath(userInput)
    args := []string{"ls", "-a", "-l", "-h"}
    env := os.Environ()
    syscall.Exec(binary, args, env)
}

func test2(userInput string) {
    binary, _ := exec.LookPath("sh")
    // User controls args - VULNERABLE
    args := []string{userInput, "-a", "-l", "-h"}
    syscall.Exec(binary, args, env)
}

func test3(userInput string) {
    binary, _ := exec.LookPath("sh")
    // User input passed to shell - VULNERABLE
    args := []string{binary, "-c", userInput}
    syscall.Exec(binary, args, env)
}
```

**Correct (Go - static syscall.Exec):**

```go
func okTest1(userInput string) {
    // Static command is safe
    binary, _ := exec.LookPath("ls")
    args := []string{"ls", "-a", "-l", "-h"}
    env := os.Environ()
    syscall.Exec(binary, args, env)
}
```

**Incorrect (Go - Otto VM injection):**

```go
func whyyyy(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()
    script := r.Form.Get("script")

    vm := otto.New()

    // User script in VM - VULNERABLE
    vm.Run(script)
}
```

**Correct (Go - static Otto VM script):**

```go
func main() {
    vm := otto.New()
    // Static script is safe
    vm.Run(`
        abc = 2 + 2;
        console.log("The value of abc is " + abc);
    `)
}
```

**Incorrect (PHP - dangerous exec functions with user input):**

```php
// User input in exec - VULNERABLE
exec($user_input);
passthru($user_input);
$proc = proc_open($cmd, $descriptorspec, $pipes);
$handle = popen($user_input, "r");
$output = shell_exec($user_input);
$output = system($user_input, $retval);
pcntl_exec($path);

// Tainted exec - VULNERABLE
$username = $_COOKIE['username'];
exec("wto -n \"$username\" -g", $ret);

$jobName = $_REQUEST['jobName'];
$cmd = sprintf("rsyncmd -l \"$xmlPath\" -r %s >/dev/null", $jobName);
system($cmd);
```

**Correct (PHP - static commands with escapeshellarg):**

```php
// Static command is safe
exec('whoami');

// escapeshellarg prevents injection - SAFE
$fullpath = $_POST['fullpath'];
$filesize = trim(shell_exec('stat -c %s ' . escapeshellarg($fullpath)));

// All user inputs escaped - SAFE
$errorCode = escapeshellarg($_POST['errorCode']);
$func = escapeshellarg($_POST['func']);
$logsCmd = sprintf('%s%s%s',
  "wdlog -l INFO -s 'adminUI' function:string=$func ",
  "errorCode:string=$errorCode ",
  "corid:string='AUI:$uuid' >/dev/null 2>&1"
);
exec($logsCmd);
```

**Incorrect (PHP - dangerous assert with user input):**

```php
$tainted = $_GET['userinput'];

// User input in assert - VULNERABLE (equivalent to eval)
assert($tainted);

Route::get('bad', function ($name) {
  assert($name);
});
```

**Correct (PHP - static assert):**

```php
// Static assertion is safe
assert('2 > 1');
```

**Incorrect (PHP - backticks with user input):**

```php
// Backticks with user input - VULNERABLE
echo `ping -n 3 {$user_input}`;
```

**Incorrect (C# - Razor template injection):**

```csharp
public class HomeController : Controller
{
    [HttpPost]
    [ValidateInput(false)]
    public ActionResult Index(string inert, string razorTpl)
    {
        // User input directly in Razor.Parse - VULNERABLE
        ViewBag.RenderedTemplate = Razor.Parse(razorTpl);
        return View();
    }
}
```

**Correct (C# - sanitized Razor template):**

```csharp
public class HomeController : Controller
{
    [HttpPost]
    [ValidateInput(false)]
    public ActionResult Index(string inter, string razorTpl)
    {
        // Sanitize/transform input before parsing
        var junk = someFunction(razorTpl);
        ViewBag.RenderedTemplate = Razor.Parse(junk);
        return View();
    }
}
```

**Incorrect (Scala - ScalaJS eval with user input):**

```scala
object Smth {
  def call1(code: String) = {
    // String interpolation in eval - VULNERABLE
    js.eval(s"console.log($code)")
    true
  }
}

object FooBar {
  def call2(code: String) = {
    // String concatenation in eval - VULNERABLE
    js.eval("console.log(" + code +")")
    true
  }
}
```

**Correct (Scala - static ScalaJS eval):**

```scala
object Smth {
  def call1(code: String) = {
    // Static eval is safe
    js.eval("FooBar()")
    true
  }
}
```

**Incorrect (Bash - curl pipe to bash):**

```bash
# All of these are VULNERABLE
bash <(curl -Ls "https://raw.githubusercontent.com/pusox/pusox/main/script/_A.sh")

curl http://10.110.1.200/deployment/scripts/setup.bash | /bin/bash -x

curl http://10.110.1.200/deployment/scripts/setup.bash | sudo /bin/bash

/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

**Correct (Bash - download, verify, then execute):**

```bash
# Download first, verify, then execute - SAFER
curl http://10.110.1.200/deployment/scripts/setup.bash -o setup.bash
# Verify checksum here
sha256sum -c setup.bash.sha256
bash setup.bash
```

**Incorrect (Bash - curl eval):**

```bash
x=$(curl -L https://raw.githubusercontent.com/something)
# Eval'ing curl output - VULNERABLE
eval ${x}

yy=`curl $SOME_URL`
eval ${yy}

# Direct eval of curl - VULNERABLE
eval $(curl -L https://raw.githubusercontent.com/something)
```

**Correct (Bash - static eval):**

```bash
# Static eval is safe
eval "x=1"
```

## References

- [OWASP Code Injection](https://owasp.org/www-community/attacks/Code_Injection)
- [OWASP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
- [CWE-94: Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html)
- [CWE-95: Eval Injection](https://cwe.mitre.org/data/definitions/95.html)
- [MDN: Never use eval()](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!)
- [Python eval() is dangerous](https://nedbatchelder.com/blog/201206/eval_really_is_dangerous.html)
- [Node.js VM module security warning](https://nodejs.org/api/vm.html#vm_vm_executing_javascript)
- [Flask/Jinja2 SSTI](https://nvisium.com/blog/2016/03/09/exploring-ssti-in-flask-jinja2.html)
- [Spring Expression Language Injection](https://owasp.org/Top10/A03_2021-Injection)
- [Trojan Source - Bidirectional Character Attacks](https://trojansource.codes/)
