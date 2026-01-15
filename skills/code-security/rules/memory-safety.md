---
title: Ensure Memory Safety
impact: CRITICAL
---

## Ensure Memory Safety

Memory safety vulnerabilities are among the most critical security issues in software development. They can lead to arbitrary code execution, data corruption, denial of service, and information disclosure. This guide covers common memory safety issues including buffer overflows, use-after-free, double-free, format string vulnerabilities, and out-of-bounds memory access.

**Incorrect (C - double free vulnerability, CWE-415):**

```c
int bad_code1() {
    char *var = malloc(sizeof(char) * 10);
    free(var);
    // ruleid: double-free
    free(var);
    return 0;
}
```

**Correct (C - set pointer to NULL after free):**

```c
int okay_code1() {
    char *var = malloc(sizeof(char) * 10);
    free(var);
    var = NULL;
    // ok: double-free
    free(var);
    return 0;
}

int okay_code2() {
    char *var = malloc(sizeof(char) * 10);
    free(var);
    var = malloc(sizeof(char) * 10);
    // ok: double-free
    free(var);
    return 0;
}
```

**Incorrect (C - use after free vulnerability, CWE-416):**

```c
typedef struct name {
    char *myname;
    void (*func)(char *str);
} NAME;

int bad_code1() {
    NAME *var;
    var = (NAME *)malloc(sizeof(struct name));
    free(var);
    // ruleid: use-after-free
    var->func("use after free");
    return 0;
}

int bad_code2() {
    NAME *var;
    var = (NAME *)malloc(sizeof(struct name));
    free(var);
    // ruleid: use-after-free
    other_func(var->myname);
    return 0;
}

int bad_code3(){
    struct NAME *var;
    var = malloc(sizeof(s_auth));
    free(var);
    // ruleid: use-after-free
    if(var->auth){
        printf("you have logged in already");
    }
    else{
        printf("you do not have the permision to log in.");
    }
    return 0;
}

int bad_code4(){
    int initial = 1000;
    struct lv *lv = malloc(sizeof(*lv));
    lv->length = initial;
    lv->value = malloc(initial);
    free(lv);
    // ruleid: use-after-free
    free(lv->value);
    return 0;
}

int bad_code6() {
    NAME *var;
    var = (NAME *)malloc(sizeof(struct name));
    free(var);
    // ruleid: use-after-free
    (*var).func("use after free");
    return 0;
}

int bad_code7() {
    char *var;
    char buf[10];
    var = (char *)malloc(100);
    free(var);
    // ruleid: use-after-free
    char buf[0] = var[0];
    return 0;
}
```

**Correct (C - safe use after free patterns):**

```c
int okay_code1() {
    NAME *var;
    var = (NAME *)malloc(sizeof(struct name));
    free(var);
    var = NULL;
    // This will segmentation fault
    // ok: use-after-free
    var->func("use after free");
    return 0;
}

int okay_code2() {
    NAME *var;
    var = (NAME *)malloc(sizeof(struct name));
    free(var);
    var = NULL;
    // This will segmentation fault
    // ok: use-after-free
    other_func(var->myname);
    return 0;
}

int ok_code4(){
    int initial = 1000;
    struct lv *lv = malloc(sizeof(*lv));
    lv->length = initial;
    lv->value = malloc(initial);
    // ok: use-after-free
    free(lv->value);
    // ok: use-after-free
    free(lv);
    return 0;
}

int ok_code6() {
    NAME *var;
    var = (NAME *)malloc(sizeof(struct name));
    free(var);
    var = (NAME *)malloc(sizeof(struct name));
    // ok: use-after-free
    (*var).func("use after free");
    return 0;
}
```

**Incorrect (C - function use after free, CWE-416):**

```c
typedef struct name {
    char *myname;
    void (*func)(char *str);
} NAME;

int bad_code1() {
    NAME *var;
    char buf[10];
    var = (NAME *)malloc(sizeof(struct name));
    free(var);
    // ruleid: function-use-after-free
    strcpy(buf, (char*)var);
    // ruleid: function-use-after-free
    other_func((char*)(*var));
    // ruleid: function-use-after-free
    other_func((char*)var[0]);
    // ruleid: function-use-after-free
    var->func(var->myname);
    return 0;
}

int bad_code2() {
    NAME *var;
    char buf[10];
    var = (NAME *)malloc(sizeof(struct name));
    free(var);
    // ruleid: function-use-after-free
    strcpy(buf, (char*)*var);
    // ruleid: function-use-after-free
    other_func((char*)var);
    // ruleid: function-use-after-free
    other_func((char*)var->myname);
    return 0;
}
```

**Correct (C - safe function use after free patterns):**

```c
int okay_code1() {
    NAME *var;
    var = (NAME *)malloc(sizeof(struct name));
    free(var);
    var = NULL;
    // This will segmentation fault
    // ok: function-use-after-free
    other_func((char*)var);
    other_func((char*)var->myname);
    other_func((char*)*var);
    return 0;
}

int okay_code2() {
    NAME *var;
    var = (NAME *)malloc(sizeof(struct name));
    free(var);
    var = NULL;
    var = (NAME *)malloc(sizeof(struct name));
    // This will segmentation fault
    // ok: function-use-after-free
    other_func((char*)var);
    other_func((char*)var->myname);
    other_func((char*)*var);
    return 0;
}
```

**Incorrect (C - insecure format string functions, CWE-134):**

```c
void bad_vsprintf(int argc, char **argv) {
    char format[256];

    //ruleid: insecure-use-printf-fn
    strncpy(format, argv[1], 255);
    char buffer[100];
    vsprintf (buffer,format, args);

    //ruleid: insecure-use-printf-fn
    vsprintf(buffer, argv[1], args);
}

void bad_sprintf(int argc, char **argv) {
    char format[256];

    int a = 10, b = 20, c=30;
    //ruleid: insecure-use-printf-fn
    strcpy(format, argv[1]);
    char buffer[200];
    sprintf(buffer, format, a, b, c);


    char buffer[256];
    int i = 3;
    //ruleid: insecure-use-printf-fn
    sprintf(buffer, argv[2], a, b, c);
}

void bad_printf() {
    //ruleid: insecure-use-printf-fn
    printf(argv[2], 1234);

    char format[300];
    //ruleid: insecure-use-printf-fn
    strcpy(format, argv[1]);
    printf(format, 1234);
}
```

**Correct (C - safe format string usage):**

```c
void safe_vsprintf(int argc, char **argv) {
    //ok: insecure-use-printf-fn
    vsprintf("%s\n",argv[0]);

    //ok: insecure-use-printf-fn
    vsnprintf(buffer, format, args);
}

void safe_sprintf(int argc, char **argv) {
    //ok: insecure-use-printf-fn
    sprintf("%s\n",argv[0]);

    //ok: insecure-use-printf-fn
    snprintf(buffer, format, a,b,c);
}

void safe_printf() {
    //ok: insecure-use-printf-fn
    printf("hello");

    //ok: insecure-use-printf-fn
    printf("%s\n",argv[0]);
}
```

**Incorrect (JavaScript - Buffer noassert out-of-bounds, CWE-119):**

```javascript
// ruleid:detect-buffer-noassert
a.readUInt8(0, true)

// ruleid:detect-buffer-noassert
a.writeFloatLE(0, true)
```

**Correct (JavaScript - Buffer with bounds checking):**

```javascript
// ok:detect-buffer-noassert
a.readUInt8(0)

// ok:detect-buffer-noassert
a.readUInt8(0, false)
```

**Incorrect (JavaScript - unsafe format string, CWE-134):**

```javascript
const util = require('util')

function test1(data) {
  const {user, ip} = data
  foobar(user)
  // ruleid: unsafe-formatstring
  console.log("Unauthorized access attempt by " + user, ip);
}

function test2(data) {
  const {user, ip} = data
  foobar(user)
  const logs = `Unauthorized access attempt by ${user}`
  // ruleid: unsafe-formatstring
  console.log(logs, ip);
}

function test3(data) {
  const {user, ip} = data
  foobar(user)
  const logs = `Unauthorized access attempt by ${user} %d`
  // ruleid: unsafe-formatstring
  return util.format(logs, ip);
}
```

**Correct (JavaScript - safe format string usage):**

```javascript
const util = require('util')

function okTest1(data) {
  const {user, ip} = data
  foobar(user)
  const logs = `Unauthorized access attempt by user`
  // ok: unsafe-formatstring
  console.log(logs, ip);
}

function okTest2(data) {
  const {user, ip} = data
  foobar(user)
  // ok: unsafe-formatstring
  console.log("Unauthorized access attempt by " + user);
}

function okTest3(data) {
  const {user, ip} = data
  foobar(user)
  // ok: unsafe-formatstring
  return util.format("Unauthorized access attempt by %d", ip);
}
```

**Incorrect (C# - MemoryMarshal CreateSpan out-of-bounds read, CWE-125):**

```csharp
namespace MemMarshalCreateSpan {
    public class MemMarshalCreateSpan {
        public void MarshalTest() {
            // ruleid: memory-marshal-create-span
            Span<T> ToSpan() => MemoryMarshal.CreateSpan(ref _e0, 1);

            // ruleid: memory-marshal-create-span
            Span<T> ToSpan() => MemoryMarshal.CreateReadOnlySpan(ref _e0, 2);

            // ruleid: memory-marshal-create-span
            Span<byte> span = MemoryMarshal.CreateSpan(ref Unsafe.AsRef(writer.Span.GetPinnableReference()), 4);

            // ruleid: memory-marshal-create-span
            Span<byte> span = MemoryMarshal.CreateReadOnlySpan(ref Unsafe.AsRef(writer.Span.GetPinnableReference()), 8);
        }
    }
}
```

**Correct (C# - safe Span creation with bounds checking):**

Use standard Span creation methods with bounds checking, or validate the length parameter before calling MemoryMarshal methods.

**Incorrect (PHP - base_convert loses precision, CWE-190):**

```php
<?php

// ruleid: base-convert-loses-precision
$token = base_convert(bin2hex(hash('sha256', uniqid(mt_rand(), true), true)), 16, 36);

// ruleid: base-convert-loses-precision
base_convert(hash_hmac('sha256', $command . ':' . $token, $secret), 16, 36);

// ruleid: base-convert-loses-precision
$randString = base_convert(sha1(uniqid(mt_rand(), true)), 16, 36);

// ruleid: base-convert-loses-precision
$uniqueId = substr(base_convert(md5(uniqid(rand(), true)), 16, 36), 1, 20);

// ruleid: base-convert-loses-precision
$token = base_convert(sha1($i),7, 36);

// ruleid: base-convert-loses-precision
$salt = base_convert(bin2hex(random_bytes(20)), 16, 36);

$stringHash = substr(md5($string), 0, 8);
// ruleid: base-convert-loses-precision
base_convert($stringHash, 16, 10);

// ruleid: base-convert-loses-precision
$seed = base_convert(md5(microtime().$_SERVER['DOCUMENT_ROOT']), 16, $numeric ? 10 : 35);

$bytes = random_bytes(32);
// ruleid: base-convert-loses-precision
base_convert(bin2hex($bytes), 16, 36);

// ruleid: base-convert-loses-precision
base_convert(bin2hex(openssl_random_pseudo_bytes(8)), 16, 36);

// ruleid: base-convert-loses-precision
$salt = base_convert(bin2hex($this->security->get_random_bytes(20)), 16,36);
```

**Correct (PHP - safe base_convert usage with small numbers):**

```php
<?php

// ok: base-convert-loses-precision
var_dump(base_convert("0775", 8, 10));

// ok: base-convert-loses-precision
$token = 'gleez_profiler/'.base_convert($counter++, 10, 32);

// ok: base-convert-loses-precision
$color1Index = base_convert(substr($uid, 0, 2), 16, 10) % $totalColors;

// ok: base-convert-loses-precision
$id_converted = base_convert($row, 10, 36);

// ok: base-convert-loses-precision
$value = base_convert(substr($value, 2), 16, 10);

// ok: base-convert-loses-precision
base_convert(rand(1, 1000000000), 10, 36);

// taking only 7 hex chars makes it fit into a 64-bit integer
$stringHash = substr(md5($string), 0, 7);
// ok: base-convert-loses-precision
base_convert($stringHash, 16, 10);

// ok: base-convert-loses-precision
base_convert(bin2hex(iconv('UTF-8', 'UCS-4', $m)), 16, 10);

// ok: base-convert-loses-precision
$currentByteBits = str_pad(base_convert(bin2hex(fread($fp,1)), 16, 2),8,'0',STR_PAD_LEFT);

// ok: base-convert-loses-precision
base_convert(bin2hex(random_bytes(7)), 16, 36);
```

**Incorrect (Python/Flask - API method string format injection, CWE-134):**

```python
import requests

class FOO(resource):
    method_decorators = decorator()

    # ruleid:flask-api-method-string-format
    def get(self, arg1):
        print("foo")
        string = "foo".format(arg1)
        foo = requests.get(string)

    # ruleid:flask-api-method-string-format
    def get2(self,arg2):
        someFn()
        bar = requests.get("foo".format(arg2))
```

**Correct (Python/Flask - safe API method patterns):**

```python
import requests

class FOO(resource):
    method_decorators = decorator()

    # ok:flask-api-method-string-format
    def get(self, somearg):
        createRecord(somearg)

    # ok:flask-api-method-string-format
    def get(self, somearg):
        otherFunc("hello world")
```
