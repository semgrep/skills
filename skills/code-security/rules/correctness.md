---
title: Code Correctness
impact: MEDIUM
---

# Code Correctness Rules

This document covers common coding mistakes and bugs that can lead to runtime errors, unexpected behavior, or logic issues. These are not security vulnerabilities per se, but correctness issues that affect program reliability.

## Table of Contents

- [Python](#python)
- [JavaScript/TypeScript](#javascripttypescript)
- [Go](#go)
- [Java](#java)
- [C](#c)
- [C#](#c-1)
- [Ruby](#ruby)
- [Scala](#scala)
- [Elixir](#elixir)
- [Bash](#bash)
- [OCaml](#ocaml)

---

## Python

### Mutable Default Arguments

Python only instantiates default function arguments once and shares the instance across function calls. Mutating a default mutable argument modifies the instance used by all future calls.

**INCORRECT** - Mutating default list:
```python
def append_func1(default=[]):
    # ruleid: default-mutable-list
    default.append(5)
```

**INCORRECT** - Mutating default dict:
```python
def assign_func1(default={}):
    # ruleid: default-mutable-dict
    default["potato"] = 5
```

**CORRECT** - Copy before mutating:
```python
def not_append_func2(default=[]):
    # list() returns a copy
    default = list(default)
    default.append(5)

def not_assign_func2(default={}):
    # dict() returns a copy
    default = dict(default)
    default[123] = 456
```

### Modifying Collections While Iterating

Modifying a list or dictionary while iterating over it leads to runtime errors or infinite loops.

**INCORRECT** - Modifying list while iterating:
```python
a = [1, 2, 3, 4]
# ruleid:list-modify-while-iterate
for i in a:
    print(i)
    a.pop(0)

b = [1, 2, 3, 4]
# ruleid:list-modify-while-iterate
for i in b:
    print(i)
    b.append(0)
```

**INCORRECT** - Deleting from dict while iterating:
```python
d = {'a': 1, 'b': 2}
# ruleid:dict-del-while-iterate
for k,v in d.items():
    del d[k]
```

**CORRECT** - Iterate over a copy or different collection:
```python
d = []
e = [1, 2, 3, 4]
# ok:list-modify-while-iterate
for i in e:
    print(i)
    d.append(i)
```

### Return/Yield in __init__

Returning a value (other than None) or yielding inside `__init__` causes a runtime error.

**INCORRECT**:
```python
class A:
    def __init__(a, b, c):
        # ruleid:return-in-init
        return A(a, b, c)

class C:
    def __init__(a, b, c):
        # ruleid:yield-in-init
        yield
```

**CORRECT**:
```python
class B:
    def __init__(a, b, c):
        # ok:return-in-init
        return  # Returning None is OK

class H:
    def __init__(self, x):
        # ok:return-in-init
        return None
```

### Exception Handling Issues

#### Suppressed Exceptions in Finally

Using `break`, `continue`, or `return` in a `finally` block suppresses exceptions.

**INCORRECT**:
```python
try:
  for i in range(3):
    # ruleid: suppressed-exception-handling-finally-break
    try:
      1 / 0
    except ZeroDivisionError:
      raise ZeroDivisionError("Error: you're trying to divide by zero!")
    finally:
      print("finally executed")
      break  # This suppresses the exception!
except ZeroDivisionError:
  print("outer ZeroDivisionError caught")
```

**CORRECT**:
```python
try:
  for i in range(3):
    # ok: suppressed-exception-handling-finally-break
    try:
      1 / 0
    except ZeroDivisionError:
      raise ZeroDivisionError("Error: you're trying to divide by zero!")
    finally:
      print("finally executed")
except ZeroDivisionError:
  print("outer ZeroDivisionError caught")
```

#### Raising Non-Exceptions

In Python 3, you can only raise objects that inherit from `BaseException`.

**INCORRECT**:
```python
# ruleid:raise-not-base-exception
raise "error here"

# ruleid:raise-not-base-exception
raise 5
```

**CORRECT**:
```python
# ok:raise-not-base-exception
raise Exception()
```

### File Handling Issues

#### Writing to Read-Only File

**INCORRECT**:
```python
fout = open("example.txt", 'r')
print("stuff")
# ruleid:writing-to-file-in-read-mode
fout.write("whoops, I'm not writable!")
fout.close()
```

**CORRECT**:
```python
fout = open("example.txt", 'w')
print("stuff")
# ok:writing-to-file-in-read-mode
fout.write("I'm writable!")
fout.close()
```

#### File Redefined Before Close

**INCORRECT**:
```python
def test1():
    # ruleid:file-object-redefined-before-close
    fin = open("file1.txt", 'r')
    data = fin.read()
    fin = open("file2.txt", 'r')  # First file never closed!
    data2 = fin.read()
    fin.close()
```

**CORRECT**:
```python
def test2():
    #ok:file-object-redefined-before-close
    fin = open("file1.txt", 'r')
    data = fin.read()
    fin.close()

    fin = open("file2.txt", 'r')
    data2 = fin.read()
    fin.close()
```

### Tempfile Without Flush

When using a tempfile's name before flushing or closing, the file may not exist yet.

**INCORRECT**:
```python
def main_d():
    fout = tempfile.NamedTemporaryFile('w')
    debug_print(astr)
    fout.write(astr)

    # ruleid:tempfile-without-flush
    cmd = [binary_name, fout.name, *[str(path) for path in targets]]
```

**CORRECT**:
```python
def main():
    with tempfile.NamedTemporaryFile("w") as fout:
        debug_print(astr)
        fout.write(astr)
        # ok:tempfile-without-flush
        fout.flush()
        cmd = [binary_name, fout.name, *[str(path) for path in targets]]
```

### Caching Generators

Generators can only be consumed once, so caching them causes errors on subsequent retrievals.

**INCORRECT**:
```python
# ruleid: cannot-cache-generators
@functools.lru_cache(maxsize=10)
def generator():
    yield 1
```

**CORRECT**:
```python
# ok: cannot-cache-generators
@functools.lru_cache(maxsize=10)
def not_a_generator():
    return 1
```

### Useless Comparisons

**INCORRECT**:
```python
# ruleid:useless-eqeq
x == x  # Always True

# ruleid:useless-eqeq
print(x != x)  # Always False
```

### is vs is not Confusion

**INCORRECT**:
```python
x = 'foo'

# ruleid: is-not-is-not
if x is (not 'hello there'):  # This converts 'hello there' to boolean first!
    pass

# ruleid: is-not-is-not
if x is (not None):  # This checks if x is False!
    pass
```

**CORRECT**:
```python
# OK
if x is not None:  # Proper identity check
    pass
```

### String Concatenation in Lists

Python implicitly concatenates adjacent strings, which can cause bugs when you forget a comma.

**INCORRECT**:
```python
# ruleid:string-concat-in-list
bad = ["123" "456" "789"]  # Results in ["123456789"], not 3 elements!

bad = [
    # ruleid:string-concat-in-list
    "abc"
    "cde"
    "efg",
    "hijk"
]
```

**CORRECT**:
```python
# ok:string-concat-in-list
good = ["123", "456", "789"]
```

### Test Missing Assert

Comparisons in tests without assertions are useless.

**INCORRECT**:
```python
class TestSomething(unittest.TestCase):
    def test_something(self):
        # ruleid: test-is-missing-assert
        a == b  # This does nothing!
```

**CORRECT**:
```python
class TestSomething(unittest.TestCase):
    def test_something(self):
        # ok: test-is-missing-assert
        assert a == b, "message"
```

### PDB Left in Code

**INCORRECT**:
```python
import pdb as db

def foo():
    # ruleid:pdb-remove
    db.set_trace()
```

### Multiple Inheritance Attribute Override

**INCORRECT**:
```python
class A:
    def method1(self, args):
        pass

class B:
    def method1(self, args):
        print('hello there')

# ruleid: baseclass-attribute-override
class C(A, B):  # Both A and B have method1!
    def __init__():
        print("initialized")
```

### Socket Shutdown/Close Pattern

When `socket.shutdown()` fails, `socket.close()` may not be called, leaking resources.

**INCORRECT**:
```python
sock = socket.socket(af, socktype, proto)

try:
    # ruleid: socket-shutdown-close
    sock.shutdown(socket.SHUT_RDWR)
    sock.close()  # Not called if shutdown fails!
except OSError:
    pass
```

**CORRECT**:
```python
try:
    # ok: socket-shutdown-close
    sock.shutdown(socket.SHUT_RDWR)
except OSError:
    pass

try:
    sock.close()
except OSError:
    pass
```

### Django-Specific Issues

#### Model Save Without super()

**INCORRECT**:
```python
class Bad(models.Model):
    title = models.CharField(max_length=255)
    slug = models.SlugField(unique=True, max_length=255)

    # ruleid: django-db-model-save-super
    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.title)
        # Missing super().save()!
```

**CORRECT**:
```python
class Post(models.Model):
    title = models.CharField(max_length=255)
    slug = models.SlugField(unique=True, max_length=255)

    # ok: django-db-model-save-super
    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.title)
        super(Post, self).save(*args, **kwargs)
```

#### String Field Missing null=True

For unique text fields with `blank=True`, `null=True` must also be set to avoid constraint violations.

**INCORRECT**:
```python
class FakeModel(Model):
    # ruleid: string-field-must-set-null-true
    fieldTwo = models.CharField(
        unique=True,
        blank=True,
        max_length=30
    )
```

**CORRECT**:
```python
class FakeModel(Model):
    # ok: string-field-must-set-null-true
    fieldThree = models.CharField(
        unique=True,
        null=True,
        blank=True,
        max_length=100
    )
```

#### Non-Text Field Missing null=True

For non-text fields, `null=True` should be set if `blank=True` is set.

**INCORRECT**:
```python
class FakeModel(models.Model):
    # ruleid: nontext-field-must-set-null-true
    fieldInt = models.IntegerField(
        blank=True,
        max_value=30
    )
```

**CORRECT**:
```python
class FakeModel(models.Model):
    # ok: nontext-field-must-set-null-true
    fieldIntNull = models.IntegerField(
        null=True,
        blank=True,
        max_value=100
    )
```

### Flask-Specific Issues

#### Duplicate Handler Names

**INCORRECT**:
```python
from flask import Flask

app = Flask(__name__)

# ruleid: flask-duplicate-handler-name
@app.route('/hello')
def hello():
    return 'hello'

@app.route('/hi', methods=["POST"])
def hello():  # Same function name!
  return 'hi'
```

#### Accessing Request Body in GET Handler

**INCORRECT**:
```python
@app.route('/', method="GET")
def handler_with_get_json(ff):
  # ruleid:avoid-accessing-request-in-wrong-handler
  r = request.json  # GET requests don't have a body!
  return r
```

### SQLAlchemy Filter Operator Issues

Use comparison operators, not Python keywords, in SQLAlchemy filters.

**INCORRECT**:
```python
def test_bad_is_1():
    # ruleid:bad-operator-in-filter
    Model.query.filter(Model.id is 5).first()

def test_bad_and_1():
    # ruleid:bad-operator-in-filter
    Model.query.filter(Model.id == 5 and Model.name == 'hi').first()
```

**CORRECT** - Use `==`, `!=`, `sqlalchemy.and_`, `sqlalchemy.or_`, `sqlalchemy.not_`, and `sqlalchemy.in_` instead.

---

## JavaScript/TypeScript

### React setState No-Op

Calling setState with the current state value is always a no-op.

**INCORRECT**:
```jsx
const [actionsExpanded, setActionsExpanded] = useState<boolean>(false);

<Button
  onClick={() => {
    // ruleid:calling-set-state-on-current-state
    setActionsExpanded(actionsExpanded);  // This does nothing!
  }}
>
```

**CORRECT**:
```jsx
<Button
  onClick={() => {
    // ok
    setActionsExpanded(!actionsExpanded);  // Toggle the state
  }}
>
```

### Missing Template String Indicator

**INCORRECT**:
```javascript
function name2() {
  // ruleid: missing-template-string-indicator
  return `this is {start.line}`  // Missing $ before {
}
```

**CORRECT**:
```javascript
function name() {
  // ok: missing-template-string-indicator
  return `this is ${start.line}`
}
```

### Useless Assignment

**INCORRECT**:
```javascript
// ruleid:useless-assignment
var x1 = 1;
x1 = 2;  // First assignment is useless

// ruleid:useless-assignment
let x2 = 1;
x2 = 2;
```

**CORRECT**:
```javascript
// ok:useless-assignment
x4 = {value1: 42};
x4 = {x4, value2: 43};  // Uses previous value

// ok:useless-assignment
y = [1, 2];
y = y.map(function(e) { return e * 2; });
```

### JSON.stringify as Object Keys

JSON.stringify does not produce stable key ordering.

**INCORRECT**:
```javascript
// ruleid:no-stringify-keys
hashed[JSON.stringify(obj)] = obj;
```

**CORRECT**:
```javascript
import stableStringify from "json-stable-stringify";

//ok
hashed[stableStringify(obj)] = obj;
```

### Useless Comparison

**INCORRECT**:
```javascript
// ruleid:eqeq-is-bad
x == x  // Always true
```

---

## Go

### Loop Pointer Export

Loop variables are shared across iterations, so exporting their pointers leads to bugs.

**INCORRECT**:
```go
func() {
    values := []string{"a", "b", "c"}
    var funcs []func()
    // ruleid:exported_loop_pointer
    for _, val := range values {
        funcs = append(funcs, func() {
            fmt.Println(&val)  // All functions print the same pointer!
        })
    }
}
```

**CORRECT**:
```go
func() {
    values := []string{"a", "b", "c"}
    var funcs []func()
    // ok:exported_loop_pointer
    for _, val := range values {
        val := val // pin! Create a new variable
        funcs = append(funcs, func() {
            fmt.Println(&val)
        })
    }
}
```

### path.Join vs filepath.Join

`path.Join` always uses forward slashes, which breaks on Windows.

**INCORRECT**:
```go
func a(p string) {
	// ruleid: use-filepath-join
	fmt.Println(path.Join(p, "baz"))
}
```

**CORRECT**:
```go
func a(p string) {
	// ok: use-filepath-join
	fmt.Println(filepath.Join(a.Path, "baz"))
}
```

### Integer Overflow from Atoi

Converting `strconv.Atoi` result to int16/int32 can overflow.

**INCORRECT**:
```go
func mainInt16Ex1() {
	// ruleid: integer-overflow-int16
	bigValue, err := strconv.Atoi("2147483648")
	if err != nil {
		panic(err)
	}
	value := int16(bigValue)  // Overflow!
	fmt.Println(value)
}
```

**CORRECT** - Use `strconv.ParseInt` with the appropriate bit size.

### Incorrect File Permissions

File permissions above 0600 violate the principle of least privilege.

**INCORRECT**:
```go
func test_chmod() {
	// ruleid: incorrect-default-permission
	err := os.Chmod("/tmp/somefile", 0777)
}

func test_mkdir() {
	// ruleid: incorrect-default-permission
	err := os.Mkdir("/tmp/mydir", 0777)
}
```

**CORRECT**:
```go
func test_chmod() {
	// ok: incorrect-default-permission
	err := os.Chmod("/tmp/somefile", 0400)
}

func test_mkdir() {
	// ok: incorrect-default-permission
	err := os.MkdirAll("/tmp/mydir", 0600)
}
```

### Useless Comparison

**INCORRECT**:
```go
var y = "hello";
// ruleid:eqeq-is-bad
fmt.Println(y == y)  // Always true
```

---

## Java

### String Comparison with ==

Strings should be compared with `.equals()`, not `==`.

**INCORRECT**:
```java
public class Example {
    public int foo(String a, int b) {
        // ruleid:no-string-eqeq
        if (a == "hello") return 1;
        // ruleid:no-string-eqeq
        if ("hello" == a) return 2;
    }
}
```

**CORRECT**:
```java
public class Example {
    public int foo(String a, int b) {
        //ok:no-string-eqeq
        if (b == 2) return -1;  // Primitives are OK
        //ok:no-string-eqeq
        if (null == "hello") return 12;  // null checks are OK
    }
}
```

### Useless Self-Comparison

**INCORRECT**:
```java
class Bar {
    void main() {
        boolean myBoolean;

        // ruleid:eqeq
        if (myBoolean == myBoolean) {
            continue;
        }

        // ruleid:eqeq
        if (myBoolean != myBoolean) {
            continue;
        }
    }
}
```

### Assignment in Condition

**INCORRECT**:
```java
class Bar {
    void main() {
        boolean myBoolean;

        // ruleid:assignment-comparison
        if (myBoolean = true) {  // Assignment, not comparison!
            continue;
        }
    }
}
```

**CORRECT**:
```java
// ok:assignment-comparison
if (myBoolean) {
}
```

---

## C

### ato* Function Family

The `ato*()` functions can cause undefined behavior and integer overflows.

**INCORRECT**:
```c
#include <stdlib.h>

int main() {
    const char *buf = "";

    // ruleid:incorrect-use-ato-fn
    int i = atoi(buf);

    // ruleid:incorrect-use-ato-fn
    long j = atol(buf);

    // ruleid:incorrect-use-ato-fn
    long long k = atoll(buf);
}
```

**CORRECT**:
```c
#include <stdlib.h>

int main() {
    const char *buf = "";

    // ok:incorrect-use-ato-fn
    long l = strtol(buf, NULL, 10);

    // ok:incorrect-use-ato-fn
    long long m = strtol(buf, NULL, 10);
}
```

### sscanf for Number Conversions

`sscanf()` can cause undefined behavior and integer overflows.

**INCORRECT**:
```c
const char *float_str = "3.1415926535897932384626433832";

float f;
// ruleid:incorrect-use-sscanf-fn
read = sscanf(float_str, "%f", &f);

int i;
// ruleid:incorrect-use-sscanf-fn
read = sscanf(int_str, "%d", &i);
```

**CORRECT**:
```c
// ok:incorrect-use-sscanf-fn
f = strtof(float_str, NULL);

// ok:incorrect-use-sscanf-fn
li = strtol(int_str, NULL, 0);
```

---

## C#

### Double.Epsilon for Equality

`Double.Epsilon` is unsuitable for equality comparisons of non-zero values.

**INCORRECT**:
```csharp
static bool IsApproximatelyEqual(double value1, double value2, double epsilon)
{
   double divisor = Math.Max(value1, value2);
   //ruleid: correctness-double-epsilon-equality
   return Math.Abs((value1 - value2) / divisor) <= Double.Epsilon;
}

static bool lazyEqualLeftCompare(double v1, double v2){
   //ruleid: correctness-double-epsilon-equality
   return Math.Abs(v1 - v2) <= Double.Epsilon;
}
```

**CORRECT** - Use the framework's `Equals()` method or a more appropriate epsilon value:
```csharp
static bool isZero(double arg){
   double zero = 0;
   //ok - comparing to zero is acceptable
   return Math.Abs(arg - zero) <= Double.Epsilon;
}
```

### RegionInfo Interop

When persisting RegionInfo between processes, use full culture names, not two-letter codes.

**INCORRECT**:
```csharp
// Creates a RegionInfo using the ISO 3166 two-letter code.
RegionInfo myRI1 = new RegionInfo( "US" );

using (AnonymousPipeServerStream pipeServer = ...){
using(StreamWriter sw = new StreamWriter(pipeServer)){
   //ruleid: correctness-regioninfo-interop
   sw.WriteLine(myRI1);  // Two-letter code may not persist correctly
}}
```

**CORRECT**:
```csharp
// Creates a RegionInfo using a CultureInfo.LCID.
RegionInfo myRI2 = new RegionInfo( new CultureInfo("en-US",false).LCID );

using(StreamWriter sw = new StreamWriter(pipeServer)){
   //ok
   sw.WriteLine(myRI2);
}
```

---

## Ruby

### Rails: Render After Save

Do not call `render` after `save` on an ActiveRecord object. Reloading will repeat the operation.

**INCORRECT**:
```ruby
def createbad
  @article = Article.new(title: "...", body: "...")
  @article.save
  # ruleid: rails-no-render-after-save
  render @article
end
```

**CORRECT**:
```ruby
def create
  @article = Article.new(title: "...", body: "...")

  if @article.save
    redirect_to @article  # Use redirect, not render
  else
    # ok: rails-no-render-after-save
    render :new, status: :unprocessable_entity
  end
end
```

---

## Scala

### Positive Number indexOf Check

Checking `indexOf > 0` ignores the first element (index 0).

**INCORRECT**:
```scala
def bad1(){
   val color = "blue"
   val strings = List("blue", "bob")
   // ruleid: positive-number-index-of
   if(strings.indexOf(color) > 0){  // Misses index 0!
      println("This is if statement");
   }
}
```

**CORRECT**:
```scala
def ok1() {
   val color = "blue"
   val strings = List("blue", "bob")
   // ok: positive-number-index-of
   if(strings.indexOf(color) > -1){  // Correct: checks all indices
      println("This is if statement");
   }
}

def ok2(){
   val name = "bob"
   // ok: positive-number-index-of
   if(name.indexOf("b") >= 0){  // Also correct
      println("This is if statement");
   }
}
```

---

## Elixir

### Atom Exhaustion

Atoms are never garbage collected. Dynamic atom creation from user input leads to memory leaks.

**INCORRECT**:
```elixir
# ruleid: atom_exhaustion
String.to_atom("dynamic")

# ruleid: atom_exhaustion
List.to_atom(~c"dynamic")
```

**CORRECT** - Use `String.to_existing_atom` or `List.to_existing_atom` instead.

---

## Bash

### Unquoted Variable Expansion

Unquoted variables are split on whitespace, which can cause bugs.

**INCORRECT**:
```bash
# ruleid: unquoted-variable-expansion-in-command
exec $foo

# ruleid: unquoted-variable-expansion-in-command
exec ${foo}

# ruleid: unquoted-variable-expansion-in-command
exec $1
```

**CORRECT**:
```bash
# ok: unquoted-variable-expansion-in-command
exec "$foo"

# ok: unquoted-variable-expansion-in-command
exec "${foo}"

# ok: unquoted-variable-expansion-in-command
exec "$1"
```

### Unquoted Command Substitution

**INCORRECT**:
```bash
# ruleid: unquoted-command-substitution-in-command
exec $(foo)

# ruleid: unquoted-command-substitution-in-command
exec `foo`
```

**CORRECT**:
```bash
# ok: unquoted-command-substitution-in-command
exec "$(foo)"

# ok: unquoted-command-substitution-in-command
exec "`foo`"
```

---

## OCaml

### Physical vs Structural Equality

Use `=` and `<>` for structural comparison, not `==` and `!=`.

**INCORRECT**:
```ocaml
let test xs ys =
  (* ruleid:physical-not-equal *)
  if xs != ys
  then 1
  else 2

let test2 xs ys =
  (* ruleid:physical-equal *)
  if xs == ys
  then 1
  else 2
```

**CORRECT** - Use `=` for structural equality and `<>` for structural inequality.

### Useless Comparisons

**INCORRECT**:
```ocaml
let test a b =
  (* ruleid:useless-compare *)
  let c = compare (a+b) (a+b) in  (* Always returns 0 *)
  if c <> 0 then c
  else
    compare a b

let test a b =
  (* ruleid:useless-equal *)
  if a+b = a+b  (* Always true *)
  then 1
  else 2
```

### Useless If

**INCORRECT**:
```ocaml
let test a b =
  (* ruleid:ocamllint-useless-if *)
  if foo
  then a+b
  else a+b  (* Both branches are identical! *)
```
