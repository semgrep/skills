---
title: Code Best Practices
impact: LOW
---

## Code Best Practices

This document outlines coding best practices across multiple languages. Following these patterns helps improve code quality, maintainability, and prevents common mistakes.

**Incorrect (Python - file not closed):**

```python
def func1():
    # ruleid:open-never-closed
    fd = open('foo')
    x = 123
```

**Correct (Python - file properly closed):**

```python
def func2():
    # ok:open-never-closed
    fd = open('bar')
    fd.close()

def func3():
    # ok:open-never-closed
    fd = open('baz')
    try:
        pass
    finally:
        fd.close()
```

**Incorrect (Python - unspecified encoding):**

`open()` uses device locale encodings by default, corrupting files with special characters. Specify the encoding to ensure cross-platform support when opening files in text mode.

```python
def func1():
    # ruleid:unspecified-open-encoding
    fd = open('foo')
    fd.close()

def func2():
    # ruleid:unspecified-open-encoding
    fd = open('foo', mode="w")
    fd.close()
```

**Correct (Python - encoding specified):**

```python
def func7():
    # ok:unspecified-open-encoding
    fd = open('foo', encoding='utf-8')
    fd.close()

def func8():
    # ok:unspecified-open-encoding
    fd = open('foo', encoding="utf-8", mode="w")
    fd.close()
```

**References:**
- https://www.python.org/dev/peps/pep-0597/
- https://docs.python.org/3/library/functions.html#open

**Incorrect (Python - missing __hash__ with __eq__):**

Class that has defined `__eq__` should also define `__hash__` for proper behavior in sets and as dictionary keys.

```python
# ruleid:missing-hash-with-eq
class A:
    def __eq__(self, someother):
        pass
```

**Correct (Python - __hash__ defined with __eq__):**

```python
# ok:missing-hash-with-eq
class A2:
    def __eq__(self, someother):
        pass

    def __hash__(self):
        pass
```

**Incorrect (Python - empty pass body):**

`pass` as the body of a function or loop is often a mistake or unfinished code.

```python
# ruleid:pass-body-range
for i in range(100):
    pass

# ruleid:pass-body-fn
def foo():
    pass
```

**Correct (Python - appropriate use of pass):**

```python
def __init__(self):
    # ok:pass-body-fn
    pass

class foo:
    def somemethod():
        # ok:pass-body-fn
        pass
```

**Incorrect (Python - requests without timeout):**

`requests` calls without a timeout will hang the program if a response is never received. Always set a timeout for all requests.

```python
import requests

url = "www.github.com"

# ruleid: use-timeout
r = requests.get(url)

# ruleid: use-timeout
r = requests.post(url)
```

**Correct (Python - requests with timeout):**

```python
# ok: use-timeout
r = requests.get(url, timeout=50)

def from_import_test1(url):
    from requests import get, post

    # ok: use-timeout
    r = get(url, timeout=3)
```

**References:**
- https://docs.python-requests.org/en/latest/user/advanced/?highlight=timeout#timeouts

**Incorrect (Django - HttpResponse with json.dumps):**

Use Django's `JsonResponse` helper instead of manually serializing JSON.

```python
from django.http import HttpResponse
import json

def foo():
    # ruleid:use-json-response
    dump = json.dumps({})
    return HttpResponse(dump, content_type='application/json')
```

**Incorrect (Flask - json.dumps instead of jsonify):**

`flask.jsonify()` is a Flask helper method which handles the correct settings for returning JSON from Flask routes.

```python
import flask
import json
app = flask.Flask(__name__)

@app.route("/user")
def user():
    user_dict = get_user(request.args.get("id"))
    # ruleid:use-jsonify
    return json.dumps(user_dict)
```

**References:**
- https://flask.palletsprojects.com/en/2.2.x/api/#flask.json.jsonify

**Incorrect (JavaScript - lazy loading modules inside functions):**

Lazy loading can complicate code bundling. `require` calls are run synchronously by Node.js and may block other requests when called from within a function.

```javascript
function smth() {
  // ruleid: lazy-load-module
  const mod = require('module-name')
  return mod();
}
```

**Correct (JavaScript - modules loaded at top level):**

```javascript
// ok: lazy-load-module
const fs = require('fs')
```

**References:**
- https://nodesecroadmap.fyi/chapter-2/dynamism.html
- https://github.com/goldbergyoni/nodebestpractices#-38-require-modules-first-not-inside-functions

**Incorrect (JavaScript - debug statements in code):**

Debug statements like `alert()`, `confirm()`, `prompt()`, and `debugger` should not be in production code.

```javascript
// ruleid:javascript-prompt
var name = prompt('what is your name');
// ruleid: javascript-alert
alert('your name is ' + name);
// ruleid: javascript-confirm
if ( confirm("pushem!") == true) {
    r = "x";
} else {
    r = "Y";
    // ruleid: javascript-debugger
    debugger;
}
```

**Incorrect (JavaScript - async zlib operations in loops):**

Creating and using a large number of zlib objects simultaneously can cause significant memory fragmentation. Cache compression results or make operations synchronous to avoid duplication of effort.

```javascript
const zlib = require('zlib');

const payload = Buffer.from('This is some data');

for (let i = 0; i < 30000; ++i) {
    // ruleid: zlib-async-loop
    zlib.deflate(payload, (err, buffer) => {});
}

[1,2,3].forEach((el) => {
    // ruleid: zlib-async-loop
    zlib.deflate(payload, (err, buffer) => {});
})
```

**Correct (JavaScript - sync zlib or single async call):**

```javascript
for (let i = 0; i < 30000; ++i) {
    // ok: zlib-async-loop
    zlib.deflateSync(payload);
}

// ok: zlib-async-loop
zlib.deflate(payload, (err, buffer) => {});
```

**References:**
- https://nodejs.org/api/zlib.html#zlib_threadpool_usage_and_performance_considerations

**Incorrect (TypeScript - using deprecated Moment.js):**

Moment.js is a legacy project in maintenance mode. Consider using actively supported libraries like `dayjs`.

```typescript
// ruleid: moment-deprecated
import moment from 'moment';
// ruleid: moment-deprecated
import { moment } from 'moment';
```

**Correct (TypeScript - using dayjs):**

```typescript
// ok: moment-deprecated
import dayjs from 'dayjs';
```

**References:**
- https://momentjs.com/docs/#/-project-status/
- https://day.js.org/

**Incorrect (React - spreading props directly):**

Explicitly pass props to HTML components rather than using the spread operator. The spread operator risks passing invalid HTML props or allowing malicious attribute injection.

```jsx
function Test1(props) {
// ruleid: react-props-spreading
    const el = <App {...props} />;
    return el;
}

function Test2(props) {
// ruleid: react-props-spreading
    const el = <MyCustomComponent {...props} some_other_prop={some_other_prop} />;
    return el;
}
```

**Correct (React - explicit props):**

```jsx
function Test2(props, otherProps) {
    const {src, alt} = props;
    const {one_prop, two_prop} = otherProps;
// ok: react-props-spreading
    return <MyCustomComponent one_prop={one_prop} two_prop={two_prop} />;
}
```

**References:**
- https://github.com/yannickcr/eslint-plugin-react/blob/master/docs/rules/jsx-props-no-spreading.md

**Incorrect (React - copying props into state):**

Copying a prop into state causes all updates to be ignored. Read props directly in your component instead.

```jsx
class Test1 extends React.Component {
  constructor() {
    // ruleid:react-props-in-state
    this.state = {
          foo: 'bar',
          color: this.props.color,
          one: 1
    };
  }
}

function Test3({ text }) {
  // ruleid:react-props-in-state
  const [buttonText] = useState(text)
  return <button>{buttonText}</button>
}
```

**Correct (React - using props directly):**

```jsx
class OkTest extends React.Component {
// ok: react-props-in-state
  constructor() {
    this.state = {
          foo: 'bar',
          initialColor: this.props.color,
          one: 1
    };
  }
}

function OkTest1({ color, children }) {
  const textColor = useMemo(
// ok: react-props-in-state
    () => slowlyCalculateTextColor(color),
    [color]
  );
}
```

**References:**
- https://overreacted.io/writing-resilient-components/#principle-1-dont-stop-the-data-flow

**Incorrect (Bash - iterating over ls output):**

Iterating over `ls` output is fragile. Use globs like `dir/*` instead.

```bash
# ruleid:iteration-over-ls-output
for file in $(ls dir); do echo "Found a file: $file"; done

# ruleid:iteration-over-ls-output
for file in $(ls dir)
do
  echo "Found a file: $file"
done
```

**Correct (Bash - using globs):**

```bash
# ok:iteration-over-ls-output
for file in dir/*; do
  echo "Found a file: $file"
done
```

**References:**
- https://github.com/koalaman/shellcheck/wiki/SC2045

**Incorrect (Bash - useless cat):**

Useless calls to `cat` in a pipeline waste resources. Use `<` and `>` for reading from or writing to files.

```bash
# ruleid:useless-cat
cat | a b

# ruleid:useless-cat
cat file | a b

# ruleid:useless-cat
a b | cat > file

# ruleid:useless-cat
a b | cat | c d
```

**Correct (Bash - efficient file operations):**

```bash
# ok:useless-cat
a b

# ok:useless-cat
cat file1 file2 | a b

# ok:useless-cat
cat $files | a b
```

**References:**
- https://github.com/koalaman/shellcheck/wiki/SC2002

**Incorrect (Java - bad hexadecimal conversion):**

`Integer.toHexString()` strips leading zeroes from each byte when read byte-by-byte. This weakens hash values by introducing more collisions. Use `String.format("%02X", ...)` instead.

```java
// ruleid: bad-hexa-conversion
public static String badHash(String password) throws NoSuchAlgorithmException, UnsupportedEncodingException {
    MessageDigest md = MessageDigest.getInstance("SHA-1");
    byte[] resultBytes = md.digest(password.getBytes("UTF-8"));

    StringBuilder stringBuilder = new StringBuilder();
    for (byte b : resultBytes) {
        stringBuilder.append(Integer.toHexString(b & 0xFF));
    }

    return stringBuilder.toString();
}
```

**Correct (Java - proper hexadecimal conversion):**

```java
// ok: bad-hexa-conversion
public static String goodHash(String password) throws NoSuchAlgorithmException, UnsupportedEncodingException {
    MessageDigest md = MessageDigest.getInstance("SHA-1");
    byte[] resultBytes = md.digest(password.getBytes("UTF-8"));

    StringBuilder stringBuilder = new StringBuilder();
    for (byte b : resultBytes) {
        stringBuilder.append(String.format("%02X", b));
    }

    return stringBuilder.toString();
}
```

**References:**
- https://find-sec-bugs.github.io/bugs.htm#BAD_HEXA_CONVERSION

**Incorrect (Kotlin - cookie missing HttpOnly flag):**

The `HttpOnly` flag instructs the browser to forbid client-side scripts from reading the cookie. Always set this flag for security-sensitive cookies.

```kotlin
public class CookieController {
    public fun setCookie(value: String, response: HttpServletResponse) {
        val cookie: Cookie = Cookie("cookie", value)
        // ruleid: cookie-missing-httponly
        response.addCookie(cookie)
    }

    public fun explicitDisable(value: String, response: HttpServletResponse) {
        val cookie: Cookie = Cookie("cookie", value)
        cookie.setSecure(false)
        // ruleid:cookie-missing-httponly
        cookie.setHttpOnly(false)
        response.addCookie(cookie)
    }
}
```

**Correct (Kotlin - cookie with HttpOnly flag):**

```kotlin
public fun setSecureHttponlyCookie(value: String, response: HttpServletResponse ) {
    val cookie: Cookie = Cookie("cookie", value)
    cookie.setSecure(true)
    cookie.setHttpOnly(true)
    // ok: cookie-missing-httponly
    response.addCookie(cookie)
}
```

**References:**
- https://find-sec-bugs.github.io/bugs.htm#HTTPONLY_COOKIE

**Incorrect (C - using memset for sensitive data):**

When handling sensitive information in a buffer, `memset()` can leave sensitive information behind due to compiler optimizations. Use `memset_s()` which securely overwrites memory.

```c
void badcode(char *password, size_t bufferSize) {
  char token[256];
  init(token, password);
  // ruleid: insecure-use-memset
  memset(password, ' ', strlen(password));
  // ruleid: insecure-use-memset
  memset(token, ' ', strlen(localBuffer));
  free(password);
}
```

**Correct (C - using memset_s for sensitive data):**

```c
void okcode(char *password, size_t bufferSize) {
  char token[256];
  init(token, password);
  // ok: insecure-use-memset
  memset_s(password, bufferSize, ' ', strlen(password));
  // ok: insecure-use-memset
  memset_s(token, sizeof(token), ' ', strlen(localBuffer));
  free(password);
}
```

**References:**
- https://cwe.mitre.org/data/definitions/14.html
- https://owasp.org/Top10/A02_2021-Cryptographic_Failures/

**Incorrect (Go - bad tmp file creation):**

File creation in shared tmp directory without using `ioutil.Tempfile` can lead to insecure temporary file vulnerabilities.

```go
func main() {
	// ruleid:bad-tmp-file-creation
	err := ioutil.WriteFile("/tmp/demo2", []byte("This is some data"), 0644)
	if err != nil {
		fmt.Println("Error while writing!")
	}
}
```

**Correct (Go - using ioutil.Tempfile):**

```go
func main_good() {
	// ok:bad-tmp-file-creation
	err := ioutil.Tempfile("/tmp", "my_temp")
	if err != nil {
		fmt.Println("Error while writing!")
	}
}
```

**References:**
- https://owasp.org/Top10/A01_2021-Broken_Access_Control

**Incorrect (Rust - using temp_dir for security operations):**

`temp_dir()` should not be used for security operations as the temporary directory may be shared among users or processes with different privileges.

```rust
use std::env;

// ruleid: temp-dir
let dir = env::temp_dir();
```

**References:**
- https://doc.rust-lang.org/stable/std/env/fn.temp_dir.html

**Incorrect (Elixir - deprecated use Bitwise):**

The syntax `use Bitwise` is deprecated. Use `import Bitwise` instead.

```elixir
# ruleid: deprecated_use_bitwise
use Bitwise
```

**Correct (Elixir - import Bitwise):**

```elixir
import Bitwise
```

**References:**
- https://github.com/elixir-lang/elixir/commit/f1b9d3e818e5bebd44540f87be85979f24b9abfc

**Incorrect (Elixir - inefficient Enum.map then Enum.join):**

Using `Enum.map_join/3` is more efficient than `Enum.map/2 |> Enum.join/2`.

```elixir
# ruleid: enum_map_join
Enum.join(Enum.map(["a", "b", "c"], fn s -> String.upcase(s) end), ", ")

# ruleid: enum_map_join
Enum.map(["a", "b", "c"], fn s -> String.upcase(s) end)
|> Enum.join(", ")

# ruleid: enum_map_join
["a", "b", "c"]
|> Enum.map(fn s -> String.upcase(s) end)
|> Enum.join(", ")
```

**References:**
- https://github.com/rrrene/credo/blob/master/lib/credo/check/refactor/map_join.ex

**Incorrect (OCaml - explicit boolean comparisons):**

Comparing to `true` or `false` explicitly is unnecessary and reduces readability.

```ocaml
let test a =
  (* ruleid:ocamllint-bool-true *)
  let x = a = true in
  (* ruleid:ocamllint-bool-true *)
  let x = a == true in
  (* ruleid:ocamllint-bool-false *)
  let x = a = false in
  (* ruleid:ocamllint-bool-false *)
  let x = a == false in
  ()
```

**Correct (OCaml - implicit boolean evaluation):**

Use `$X` directly instead of `$X = true`, and `not $X` instead of `$X = false`.

**Incorrect (OCaml - List.find outside try block):**

`List.find` should be used inside a try block, or use `List.find_opt` instead.

```ocaml
let test1 xs =
  (* ruleid:list-find-outside-try *)
  if List.find 1 xs
  then 1
  else 2
```

**Correct (OCaml - List.find inside try block):**

```ocaml
let test2 xs =
 (* ok *)
 try
   if List.find 1 xs
   then 1
   else 2
 with Not_found -> 3
```

**Incorrect (Ruby - unscoped find with user input):**

Unscoped `find(...)` with user-controllable input may lead to Insecure Direct Object Reference (IDOR) behavior.

```ruby
class GroupsController < ApplicationController

  def show
    #ruleid: check-unscoped-find
    @user = User.find(params[:id])
  end

  def get
    #ruleid: check-unscoped-find
    @some_record = SomeRecord.find_by_id!(params[:id])
  end
end
```

**Correct (Ruby - scoped find operations):**

```ruby
def show_ok
  #ok: check-unscoped-find
  @user = User.find(session[:id])
end

def show_ok2
  #ok: check-unscoped-find
  current_user = User.find(session[:id])
  #ok: check-unscoped-find
  current_user.accounts.find(param[:id])
end
```

**References:**
- https://brakemanscanner.org/docs/warning_types/unscoped_find/

**Incorrect (PHP - phpinfo in production):**

The `phpinfo` function may reveal sensitive information about your environment.

```php
<?php

// ruleid: phpinfo-use
echo phpinfo();
```

**References:**
- https://www.php.net/manual/en/function.phpinfo

**Incorrect (Swift - sensitive data in UserDefaults):**

Sensitive data stored in UserDefaults is not adequately protected. Use the Keychain for data of a sensitive nature.

```swift
let passphrase = getPass()

// ruleid: swift-user-defaults
UserDefaults.standard.set(passphrase, forKey: "passphrase")
// ruleid: swift-user-defaults
UserDefaults.standard.set(passWord, forKey: "userPassword")

// ruleid: swift-user-defaults
UserDefaults.standard.set("12717-127163-a71367-127ahc", forKey: "apiKey")

let apiKey = "12717-127163-a71367-127ahc"
// ruleid: swift-user-defaults
UserDefaults.standard.set(apiKey, forKey: "GOOGLE_TOKEN")
```

**Correct (Swift - non-sensitive data in UserDefaults):**

```swift
let username = getUsername()

// okid: swift-user-defaults
UserDefaults.standard.set(username, forKey: "userName")
```

**References:**
- https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/Articles/ValidatingInput.html
- https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/

**Incorrect (Terraform - S3 bucket with public read access):**

S3 buckets with public read access expose data to unauthorized users.

```hcl
resource "aws_s3_bucket" "a" {
  bucket = "my-tf-test-bucket"
  # ruleid: s3-public-read-bucket
  acl    = "public-read"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
}

resource "aws_s3_bucket" "b" {
  bucket = "my-tf-test-bucket-b"
  # ruleid: s3-public-read-bucket
  acl    = "authenticated-read"
}
```

**Correct (Terraform - S3 bucket with policy):**

```hcl
resource "aws_s3_bucket" "c" {
  bucket = "s3-website-test.hashicorp.com"
  # ok: s3-public-read-bucket
  acl    = "public-read"
  policy = file("policy.json")

  website {
    index_document = "index.html"
    error_document = "error.html"
  }
}
```

**References:**
- https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#acl
- https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html#canned-acl

**Incorrect (C# - open redirect vulnerability):**

A query string parameter may contain a URL value that could cause the web application to redirect to a malicious website. Always validate redirect URLs.

```csharp
[HttpPost]
public ActionResult LogOn(LogOnModel model, string returnUrl)
{
    if (ModelState.IsValid)
    {
        if (MembershipService.ValidateUser(model.UserName, model.Password))
        {
            FormsService.SignIn(model.UserName, model.RememberMe);
            if (!String.IsNullOrEmpty(returnUrl))
            {
                // ruleid: open-redirect
                return Redirect(returnUrl);
            }
        }
    }
}
```

**Correct (C# - validated redirect URL):**

```csharp
[HttpPost]
public ActionResult LogOn(LogOnModel model, string returnUrl)
{
    if (ModelState.IsValid)
    {
        if (MembershipService.ValidateUser(model.UserName, model.Password))
        {
            FormsService.SignIn(model.UserName, model.RememberMe);
            if (IsLocalUrl(returnUrl))
            {
                // ok: open-redirect
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }
        }
    }
}
```

**References:**
- https://cwe.mitre.org/data/definitions/601.html
