---
title: Prevent Code Injection
impact: CRITICAL
impactDescription: Remote code execution via eval/exec
tags: security, code-injection, rce, cwe-94, cwe-95, owasp-a03
---

## Prevent Code Injection

Code injection vulnerabilities occur when an attacker can insert and execute arbitrary code within your application. This includes direct code evaluation (eval, exec), reflection-based attacks, and dynamic method invocation. These vulnerabilities can lead to complete system compromise, data theft, and remote code execution.

**Incorrect (Python - eval with user input):**

```python
def unsafe(request):
    code = request.POST.get('code')
    eval(code)
```

**Correct (Python - avoid eval entirely, use safe alternatives):**

```python
import ast

def safe_parse(user_expr):
    # ast.literal_eval only allows literals (strings, numbers, tuples, lists, dicts, booleans, None)
    return ast.literal_eval(user_expr)

# For math expressions, use a purpose-built parser instead of eval
```

> **Note:** Avoid `eval()`/`exec()` entirely. Even with hardcoded strings, it normalizes a dangerous pattern. Use `ast.literal_eval()` for parsing data literals, or purpose-built parsers for expressions.

**Incorrect (JavaScript - eval with dynamic content):**

```javascript
let dynamic = window.prompt()

eval(dynamic + 'possibly malicious code');

function evalSomething(something) {
    eval(something);
}
```

**Correct (JavaScript - avoid eval, use safe alternatives):**

```javascript
// Instead of eval for JSON parsing:
const data = JSON.parse(jsonString);

// Instead of eval for dynamic property access:
const value = obj[propertyName];

// Instead of eval for math: use a sandboxed expression parser
```

> **Note:** There is almost never a legitimate reason to use `eval()`. Use `JSON.parse()`, computed property access, or a sandboxed parser. Avoid `new Function()` as well — it executes arbitrary code just like `eval()`.

**Incorrect (Java - ScriptEngine injection):**

```java
public class ScriptEngineSample {

    private static ScriptEngineManager sem = new ScriptEngineManager();
    private static ScriptEngine se = sem.getEngineByExtension("js");

    public static void scripting(String userInput) throws ScriptException {
        Object result = se.eval("test=1;" + userInput);
    }
}
```

**Correct (Java - static ScriptEngine evaluation):**

```java
public class ScriptEngineSample {

    public static void scriptingSafe() throws ScriptException {
        ScriptEngineManager scriptEngineManager = new ScriptEngineManager();
        ScriptEngine scriptEngine = scriptEngineManager.getEngineByExtension("js");
        String code = "var test=3;test=test*2;";
        Object result = scriptEngine.eval(code);
    }
}
```

**Incorrect (Ruby - dangerous eval):**

```ruby
b = params['something']
eval(b)
eval(params['cmd'])
```

**Correct (Ruby - static eval):**

```ruby
eval("def zen; 42; end")

class Thing
end
a = %q{def hello() "Hello there!" end}
Thing.module_eval(a)
```

**Incorrect (PHP - code injection via eval/assert):**

```php
$code = $_GET['code'];
eval($code);

$input = $_POST['input'];
assert($input);  // assert() evaluates strings as code in PHP < 8.0
```

**Correct (PHP - avoid eval, use structured alternatives):**

```php
// Instead of eval for dynamic config, use a data format:
$config = json_decode(file_get_contents('config.json'), true);

// Instead of eval for templates, use a template engine (Twig, Blade)
```

> **Note:** `exec()`/`shell_exec()`/`system()` are OS command execution — see the command-injection rule for those. This rule covers code evaluation via `eval()`, `assert()`, `preg_replace` with `/e`, and similar.

## Key Prevention Patterns

1. **Avoid eval/exec entirely** - Use safer alternatives (`JSON.parse`, `ast.literal_eval`, template engines, computed property access)
2. **Never pass user input to code evaluation functions** - Treat all user input as untrusted
3. **If dynamic code execution is unavoidable** - Validate against a strict allowlist and sandbox the execution
4. **Use parameterized alternatives** - Most languages offer structured APIs that eliminate the need for eval

> For OS command execution (`exec`, `shell_exec`, `system`) and shell-escaping (`escapeshellarg`), see the **command-injection** rule.

## References

- [OWASP Code Injection](https://owasp.org/www-community/attacks/Code_Injection)
- [OWASP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
- [CWE-94: Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html)
- [CWE-95: Eval Injection](https://cwe.mitre.org/data/definitions/95.html)
- [MDN: Never use eval()](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!)
