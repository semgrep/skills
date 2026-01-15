---
title: Prevent Regular Expression DoS
impact: MEDIUM
impactDescription: Service disruption through CPU exhaustion via malicious regex patterns
tags: security, redos, regex, cwe-1333, cwe-400, cwe-185
---

## Prevent Regular Expression DoS (ReDoS)

Regular Expression Denial of Service (ReDoS) occurs when attackers exploit inefficient regular expression patterns to cause excessive CPU consumption. Certain regex patterns with nested quantifiers or overlapping alternatives can experience "catastrophic backtracking" when matched against malicious input, causing the regex engine to take exponential time to evaluate.

Common vulnerable patterns include:
- Nested quantifiers: `(a+)+`, `(a*)*`, `(a|a)+`
- Overlapping alternatives: `(a|aa)+`
- Unbounded repetition with overlap: `.*.*`

### Language: JavaScript / TypeScript

**Incorrect (vulnerable ReDoS pattern):**
```javascript
// ruleid: detect-redos
const re = new RegExp("([a-z]+)+$", "i");
// ruleid: detect-redos
const re = new RegExp(/([a-z]+)+$/, "i");

var r = /^\w+([-_+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$/
// ruleid: detect-redos
new RegExp(r, "i");
// ruleid: detect-redos
r.test(a)
// ruleid: detect-redos
"a".match(r)
```

**Correct (safe regex patterns):**
```javascript
// ok: detect-redos
"a".match(b)
// ok: detect-redos
"a".match("([a-z])")
var c = /([a-z])/
// ok: detect-redos
c.test(a)
```

**References:**
- [OWASP ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- [Regular-Expressions.info ReDoS](https://www.regular-expressions.info/redos.html)
- CWE-1333: Inefficient Regular Expression Complexity

---

**Incorrect (non-literal RegExp with user input):**
```javascript
function bad (name) {
  //ruleid: detect-non-literal-regexp
  const reg = new RegExp("\\w+" + name)
  return reg.exec(name)
}
```

**Correct (hardcoded regex patterns):**
```javascript
function ok (name) {
  //ok: detect-non-literal-regexp
  const reg = new RegExp("\\w+")
  return reg.exec(name)
}

function jsliteral (name) {
  const exp = /a.*/;
  //ok: detect-non-literal-regexp
  const reg = new RegExp(exp);
  return reg.exec(name);
}
```

**References:**
- [OWASP ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- CWE-1333: Inefficient Regular Expression Complexity

---

**Incorrect (incomplete string sanitization):**
```javascript
function escapeQuotes(s) {
    // ruleid:incomplete-sanitization
    return s.replace("'", "''");
}

function removeTabs(s) {
    // ruleid:incomplete-sanitization
    return s.replace('\t', "");
}

function escapeHtml(html) {
  // ruleid:incomplete-sanitization
  return html
    .replace("<", "")
    .replace(">", "");
}
```

**Correct (use regex with global flag):**
```javascript
function okTest(s) {
    return s.replace("foo", "bar");
}

function okEscapeQuotes(s) {
    return s.replace(/'/g, "''");
}
```

**References:**
- [OWASP Injection](https://owasp.org/Top10/A03_2021-Injection)
- CWE-116: Improper Encoding or Escaping of Output

---

**Incorrect (Ajv allErrors: true enables DoS):**
```javascript
import express from 'express';
import Ajv from 'ajv';

function test1() {
    const settings = { allErrors: true, smth: 'else' }
    // ruleid: ajv-allerrors-true
    const ajv1 = new Ajv(settings);
    return ajv1
}

function test2() {
    // ruleid: ajv-allerrors-true
    var ajv = new Ajv({ allErrors: true, smth: 'else' });
    ajv.addSchema(schema, 'input');
}


function test3() {
    // ruleid: ajv-allerrors-true
    var ajv = new Ajv({  smth: 'else', allErrors: true });
    ajv.addSchema(schema, 'input');
}

function test4() {
    // ruleid: ajv-allerrors-true
    var ajv = new Ajv({  smth: 'else', smth: 'else', allErrors: true, smth: 'else' });
    ajv.addSchema(schema, 'input');
}
```

**Correct (disable allErrors in production):**
```javascript
function okTest1() {
    // ok: ajv-allerrors-true
    let ajv = new Ajv({ allErrors: process.env.DEBUG });
    ajv.addSchema(schema, 'input');
}

function okTest2() {
    // ok: ajv-allerrors-true
    var ajv = new Ajv({  smth: 'else', allErrors: false });
    ajv.addSchema(schema, 'input');
}
```

**References:**
- [Ajv allErrors Option](https://ajv.js.org/options.html#allerrors)
- CWE-400: Uncontrolled Resource Consumption

---

### Language: TypeScript

**Incorrect (CORS regex with unescaped dots):**
```typescript
const corsDomains = [
  /localhost\:/,
  /(.+\.)*foo\.com$/,
  /(.+\.)*foobar\.com$/, // matches *.foobar.com,
  // ruleid: cors-regex-wildcard
  /^(http|https):\/\/(qix|qux).biz.baz.foobar.com$/,
  /^(http|https):\/\/www\.bar\.com$/,
  // ruleid: cors-regex-wildcard
  /^(http|https):\/\/www.foo.com$/,
];

const CORS = [
  /localhost\:/,
  /(.+\.)*foo\.com$/,
  /(.+\.)*foobar\.com$/, // matches *.foobar.com,
  // ruleid: cors-regex-wildcard
  /^(http|https):\/\/(qix|qux).biz.baz.foobar.com$/,
  /^(http|https):\/\/www\.bar\.com$/,
  // ruleid: cors-regex-wildcard
  /^(http|https):\/\/www.foo.com$/,
];

// ruleid: cors-regex-wildcard
const corsOrigin = /^(http|https):\/\/www.foo.com$/;
```

**Correct (escape dots in CORS regex):**
```typescript
const urls = [
  /localhost\:/,
  /(.+\.)*foo\.com$/,
  /(.+\.)*foobar\.com$/, // matches *.foobar.com,
  /^(http|https):\/\/(qix|qux).biz.baz.foobar.com$/,
  /^(http|https):\/\/www\.bar\.com$/,
  /^(http|https):\/\/www.foo.com$/,
];
```

**References:**
- [OWASP Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design)
- CWE-183: Permissive List of Allowed Inputs

---

### Language: Python

**Incorrect (inefficient regex pattern):**
```python
import re

redos = r"^(a+)+$"
regex = r"^[0-9]+$"

data = "foo"

# ruleid: regex_dos
pattern = re.compile(redos)
pattern.search(data)

# ruleid: regex_dos
pattern = re.compile(redos)
pattern.match(data)

# ruleid: regex_dos
pattern = re.compile(redos)
pattern.findall(data)
```

**Correct (safe regex patterns):**
```python
import re

redos = r"^(a+)+$"
regex = r"^[0-9]+$"

data = "foo"

# ok: regex_dos
pattern = re.compile(regex)
pattern.search(data)

# ok: regex_dos
pattern = re.compile(regex)
pattern.fullmatch(data)

# ok: regex_dos
pattern = re.compile(regex)
pattern.split(data)

# ok: regex_dos
pattern.escape(redos)

# ok: regex_dos
pattern = re.compile(redos)
pattern.purge()
```

**References:**
- [Python re module](https://docs.python.org/3/library/re.html)
- CWE-1333: Inefficient Regular Expression Complexity

---

**Incorrect (missing Django REST Framework throttle config):**
```python
# ruleid: missing-throttle-config
REST_FRAMEWORK = {
    'PAGE_SIZE': 10
}
```

**Correct (throttle config enabled):**
```python
# ok: missing-throttle-config
REST_FRAMEWORK = {
    'PAGE_SIZE': 10,
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle'
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/day',
        'user': '1000/day'
    },
    "SOMETHING_ELSE": {1: 2}
}
```

**References:**
- [Django REST Framework Throttling](https://www.django-rest-framework.org/api-guide/throttling/#setting-the-throttling-policy)
- CWE-400: Uncontrolled Resource Consumption

---

### Language: Ruby

**Incorrect (user-controlled regex):**
```ruby
def some_rails_controller
  foo = params[:some_regex]
  #ruleid: check-regex-dos
  Regexp.new(foo).match("some_string")
end

def some_rails_controller
  foo = Record[something]
  #ruleid: check-regex-dos
  Regexp.new(foo).match("some_string")
end

def some_rails_controller
  foo = Record.read_attribute("some_attribute")
  #ruleid: check-regex-dos
  Regexp.new(foo).match("some_string")
end

def use_params_in_regex
#ruleid: check-regex-dos
@x = something.match /#{params[:x]}/
end
```

**Correct (safe regex usage):**
```ruby
def some_rails_controller
  bar = ENV['someEnvVar']
  #ok: check-regex-dos
  Regexp.new(bar).match("some_string")
end

def regex_on_params
#ok: check-regex-dos
@x = params[:x].match /foo/
end
```

**References:**
- [OWASP ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- CWE-1333: Inefficient Regular Expression Complexity

---

**Incorrect (incorrectly-bounded Rails validation regex):**
```ruby
class Account < ActiveRecord::Base
  #ruleid: check-validation-regex
  validates :username, :length => 6..20, :format => /([a-z][0-9])+/i
  #ruleid: check-validation-regex
  validates :phone, :format => { :with => /(\d{3})-(\d{3})-(\d{4})/, :on => :create }, :presence => true
  #ruleid: check-validation-regex
  validates :first_name, :format => /\w+/
  serialize :cc_info #safe from CVE-2013-0277
  attr_accessible :blah_admin_blah
end

class Account < ActiveRecord::Base
  #ruleid: check-validation-regex
  validates_format_of :name, :with => /^[a-zA-Z]+$/
  #ruleid: check-validation-regex
  validates_format_of :blah, :with => /\A[a-zA-Z]+$/
  #ruleid: check-validation-regex
  validates_format_of :blah2, :with => /^[a-zA-Z]+\Z/
  #ruleid: check-validation-regex
  validates_format_of :something, :with => /[a-zA-Z]\z/
end
```

**Correct (properly-bounded regex with \A and \Z):**
```ruby
class Account < ActiveRecord::Base
  #ok: check-validation-regex
  validates_format_of :good_valid, :with => /\A[a-zA-Z]\z/ #No warning
  #ok: check-validation-regex
  validates_format_of :not_bad, :with => /\A[a-zA-Z]\Z/ #No warning
end
```

Ruby regex behavior is multiline by default. Use `\A` for beginning of string and `\Z` (or `\z`) for end of string instead of `^` and `$`.

**References:**
- [Brakeman Format Validation](https://brakemanscanner.org/docs/warning_types/format_validation/)
- CWE-185: Incorrect Regular Expression

---

### Language: C#

**Incorrect (regex without timeout on untrusted input):**
```csharp
using System.Text.RegularExpressions;

namespace RegularExpressionsDos
{
    public class RegularExpressionsDos
    {
        // ruleid: regular-expression-dos
        public void ValidateRegex(string search)
        {
            Regex rgx = new Regex("^A(B|C+)+D");
            rgx.Match(search);

        }

        // ruleid: regular-expression-dos
        public void ValidateRegex2(string search)
        {
            Regex rgx = new Regex("^A(B|C+)+D", new RegexOptions { });
            rgx.Match(search);

        }

        // ruleid: regular-expression-dos
        public void Validate4(string search)
        {
            var pattern = @"^A(B|C+)+D";
            var result = Regex.Match(search, pattern);
        }

        // ruleid: regular-expression-dos
        public void Validate5(string search)
        {
            var pattern = @"^A(B|C+)+D";
            var result = Regex.Match(search, pattern, new RegexOptions { });
        }
    }
}
```

**Correct (regex with timeout):**
```csharp
using System.Text.RegularExpressions;

namespace RegularExpressionsDos
{
    public class RegularExpressionsDos
    {
        // ok: regular-expression-dos
        public void ValidateRegex3(string search)
        {
            Regex rgx = new Regex("^A(B|C+)+D", new RegexOptions { }, TimeSpan.FromSeconds(2000));
            rgx.Match(search);

        }

        // ok: regular-expression-dos
        public void Validate5(string search)
        {
            var pattern = @"^A(B|C+)+D";
            var result = Regex.Match(search, pattern, new RegexOptions { }, TimeSpan.FromSeconds(2000));
        }
    }
}
```

**References:**
- [OWASP ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- [.NET Regular Expressions](https://docs.microsoft.com/en-us/dotnet/standard/base-types/regular-expressions#regular-expression-examples)
- CWE-1333: Inefficient Regular Expression Complexity

---

**Incorrect (regex with excessive or infinite timeout):**
```csharp
using System.Text.RegularExpressions;

namespace RegularExpressionsDosInfiniteTimeout
{
    public class RegularExpressionsDosInfiniteTimeout
    {
        // ruleid: regular-expression-dos-infinite-timeout
        Regex rgx = new Regex(pattern, RegexOptions.IgnoreCase, TimeSpan.FromSeconds(10));

        // ruleid: regular-expression-dos-infinite-timeout
        Regex rgx = new Regex(pattern, RegexOptions.IgnoreCase, TimeSpan.InfiniteMatchTimeout);

        // ruleid: regular-expression-dos-infinite-timeout
        Regex rgx = new Regex(pattern, RegexOptions.IgnoreCase, TimeSpan.FromMinutes(1));

        // ruleid: regular-expression-dos-infinite-timeout
        Regex rgx = new Regex(pattern, RegexOptions.IgnoreCase, TimeSpan.FromHours(1));
    }
}
```

**Correct (regex with short timeout):**
```csharp
using System.Text.RegularExpressions;

namespace RegularExpressionsDosInfiniteTimeout
{
    public class RegularExpressionsDosInfiniteTimeout
    {
        // ok
        Regex rgx = new Regex(pattern, RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));
    }
}
```

Consider setting the timeout to a short amount of time like 2 or 3 seconds. If you are sure you need an infinite timeout, double check that your context meets the conditions outlined in the "Notes to Callers" section at the bottom of this page: https://docs.microsoft.com/en-us/dotnet/api/system.text.regularexpressions.regex.-ctor?view=net-6.0

**References:**
- [OWASP ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- [Regex.InfiniteMatchTimeout](https://docs.microsoft.com/en-us/dotnet/api/system.text.regularexpressions.regex.infinitematchtimeout)
- [Regex Constructor](https://docs.microsoft.com/en-us/dotnet/api/system.text.regularexpressions.regex.-ctor?view=net-6.0)
- CWE-1333: Inefficient Regular Expression Complexity

---

### Language: Go

**Incorrect (decompression without size limit - zip bomb):**
```go
// cf. https://github.com/securego/gosec/blob/master/testutils/source.go#L684

package main
import (
	"bytes"
	"compress/zlib"
	"io"
	"os"
)
func blah() {
	buff := []byte{120, 156, 202, 72, 205, 201, 201, 215, 81, 40, 207,
		47, 202, 73, 225, 2, 4, 0, 0, 255, 255, 33, 231, 4, 147}
	b := bytes.NewReader(buff)
	r, err := zlib.NewReader(b)
	if err != nil {
		panic(err)
	}
	// ruleid: potential-dos-via-decompression-bomb
	_, err := io.Copy(os.Stdout, r)
	if err != nil {
		panic(err)
	}
	r.Close()
}

func blah2() {
	buff := []byte{120, 156, 202, 72, 205, 201, 201, 215, 81, 40, 207,
		47, 202, 73, 225, 2, 4, 0, 0, 255, 255, 33, 231, 4, 147}
	b := bytes.NewReader(buff)
	r, err := zlib.NewReader(b)
	if err != nil {
		panic(err)
	}
	buf := make([]byte, 8)
	// ruleid: potential-dos-via-decompression-bomb
	_, err := io.CopyBuffer(os.Stdout, r, buf)
	if err != nil {
		panic(err)
	}
	r.Close()
}

func blah3() {
	r, err := zip.OpenReader("tmp.zip")
	if err != nil {
		panic(err)
	}
	defer r.Close()
	for i, f := range r.File {
		out, err := os.OpenFile("output" + strconv.Itoa(i), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			panic(err)
		}
		rc, err := f.Open()
		if err != nil {
			panic(err)
		}
		// ruleid: potential-dos-via-decompression-bomb
		_, err = io.Copy(out, rc)
		out.Close()
		rc.Close()
		if err != nil {
			panic(err)
		}
	}
}
```

**Correct (use io.CopyN with size limit):**
```go
func benign() {
	s, err := os.Open("src")
	if err != nil {
		panic(err)
	}
	defer s.Close()
	d, err := os.Create("dst")
	if err != nil {
		panic(err)
	}
	defer d.Close()
	// ok: potential-dos-via-decompression-bomb
	_, err = io.Copy(d, s)
	if  err != nil {
		panic(err)
	}
}

func ok() {
	buff := []byte{120, 156, 202, 72, 205, 201, 201, 215, 81, 40, 207,
		47, 202, 73, 225, 2, 4, 0, 0, 255, 255, 33, 231, 4, 147}
	b := bytes.NewReader(buff)
	r, err := zlib.NewReader(b)
	if err != nil {
		panic(err)
	}
	buf := make([]byte, 8)
	// ok: potential-dos-via-decompression-bomb
	_, err := io.CopyN(os.Stdout, r, buf, 1024*1024*4)
	if err != nil {
		panic(err)
	}
	r.Close()
}
```

By limiting the max bytes read with `io.CopyN()`, you can mitigate zip bomb attacks.

**References:**
- [Go io.CopyN](https://golang.org/pkg/io/#CopyN)
- [gosec decompression-bomb rule](https://github.com/securego/gosec/blob/master/rules/decompression-bomb.go)
- CWE-400: Uncontrolled Resource Consumption

---

**References:**
- CWE-1333: Inefficient Regular Expression Complexity
- CWE-400: Uncontrolled Resource Consumption
- CWE-185: Incorrect Regular Expression
- [OWASP ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- [Regular-Expressions.info ReDoS](https://www.regular-expressions.info/redos.html)
