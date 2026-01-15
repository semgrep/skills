---
title: Prevent Cross-Site Scripting (XSS)
impact: CRITICAL
impactDescription: Client-side code execution, session hijacking, credential theft
tags: security, xss, cwe-79
---

## Prevent Cross-Site Scripting (XSS)

XSS occurs when untrusted data is included in web pages without proper validation or escaping. Attackers can execute scripts in victim's browser to steal cookies, session tokens, or other sensitive data.

---

### Language: JavaScript

#### Browser DOM Manipulation

**Incorrect (vulnerable to XSS):**
```javascript
function bad1(userInput) {
  // ruleid: insecure-innerhtml
  el.innerHTML = '<div>' + userInput + '</div>';
}

function bad2(userInput) {
  // ruleid: insecure-innerhtml
  document.body.innerHTML = userInput;
}

function bad3(userInput) {
  const name = '<div>' + userInput + '</div>';
  // ruleid: insecure-innerhtml
  document.body.innerHTML = name;
}
```

**Correct (properly escaped):**
```javascript
function ok1() {
  const name = "<div>it's ok</div>";
  // ok: insecure-innerhtml
  el.innerHTML = name;
}

function ok2() {
  // ok: insecure-innerhtml
  document.body.innerHTML = "<div>it's ok</div>";
}
```

**References:**
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- [OWASP Injection Guide](https://owasp.org/Top10/A03_2021-Injection)

---

#### DOM-based XSS via URL

**Incorrect (vulnerable to DOM-based XSS):**
```javascript
// ruleid:dom-based-xss
document.write("<OPTION value=1>"+document.location.href.substring(document.location.href.indexOf("default=")+8)+"</OPTION>");
```

**Correct (safe static content):**
```javascript
// ok:dom-based-xss
document.write("<OPTION value=2>English</OPTION>");
```

**References:**
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- [OWASP DOM Based XSS](https://owasp.org/www-community/attacks/DOM_Based_XSS)

---

#### document.write with Variables

**Incorrect (user-controlled data in document methods):**
```javascript
function bad1(userInput) {
// ruleid: insecure-document-method
  el.innerHTML = '<div>' + userInput + '</div>';
}

function bad2(userInput) {
// ruleid: insecure-document-method
  document.body.outerHTML = userInput;
}

function bad3(userInput) {
  const name = '<div>' + userInput + '</div>';
// ruleid: insecure-document-method
  document.write(name);
}
```

**Correct (static content only):**
```javascript
function ok1() {
  const name = "<div>it's ok</div>";
// ok: insecure-document-method
  el.innerHTML = name;
}

function ok2() {
// ok: insecure-document-method
  document.write("<div>it's ok</div>");
}
```

**References:**
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- [OWASP Injection Guide](https://owasp.org/Top10/A03_2021-Injection)

---

#### jQuery Methods

**Incorrect (user input in jQuery methods):**
```javascript
(function ($) {

  function bad1() {
    var content = '<div>' + window.location.hash + '</div>';
    // ruleid: jquery-insecure-method
    $( "div" ).html( content );
  }

  function bad2() {
    // ruleid: jquery-insecure-method
    $( userInput ).appendTo( "#foo" );
  }

  function bad4() {
    // ruleid: jquery-insecure-method
    $('<div>' + window.location.hash + '</div>').insertBefore( ".inner" );
    // ruleid: jquery-insecure-method
    $('.inner').prepend(window.location.hash);
  }

  function bad5(userInput) {
    // ruleid: jquery-insecure-method
    $( ".inner" ).wrap( "<div class='new'>" + userInput + "</div>" );
    // ruleid: jquery-insecure-method
    $( "p" ).wrapAll(userInput);
  }

})(jQuery);
```

**Correct (static content):**
```javascript
(function ($) {

  function ok1() {
    const item = '<div></div>';
    // ok: jquery-insecure-method
    $( ".inner" ).wrap(item);
  }

  function ok2(userInput) {
    // ok: jquery-insecure-method
    $( "div" ).html( '<div></div>' );
  }

  function ok3(userInput) {
    jQuery(document).ready(function($){
      // ok: jquery-insecure-method
      $('<input type="checkbox"/>').prependTo('.checklist-box li');
    });
  }

})(jQuery);
```

**References:**
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- [OWASP XSS Attacks](https://owasp.org/www-community/attacks/xss/)
- [jQuery XSS Vulnerability](https://bugs.jquery.com/ticket/9521)

---

#### Express.js Response

**Incorrect (direct response write with user input):**
```javascript
const express = require('express')
const router = express.Router()

router.get('/greeting', (req, res) => {
    const { name } = req.query;
    // ruleid: direct-response-write
    res.send('<h1> Hello :' + name + "</h1>")
})

app.get('/', function (req, res) {
    var user = req.query.name;
    msg = "Hi " + user
    // ruleid: direct-response-write
    res.send('Response</br>' + msg);
});

app.get('/xss', function (req, res) {
    var html = "ASadad" + req.query.name + "Asdadads"
    // ruleid: direct-response-write
    res.write('Response</br>' + html);
});
```

**Correct (use templates or sanitization):**
```javascript
const express = require('express')
const router = express.Router()
var xss = require("xss");

// Template handles escaping
router.get('/greet-template', (req, res) => {
    name = req.query.name
    // ok: direct-response-write
    res.render('index', { user_name: name });
})

// Using XSS sanitization library
router.get('/greet-template', (req, res) => {
    a = req.query.name
    // ok: direct-response-write
    res.send('<h1> Hello :' + xss(a) + "</h1>")
})

app.get('/noxss', function (req, res) {
    var resp = req.query.name;
    // ok: direct-response-write
    res.write('Response</br>');
});
```

**References:**
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

---

#### Manual Sanitization (Anti-pattern)

**Incorrect (manual replace-based sanitization):**
```javascript
function encodeProductDescription (tableData: any[]) {
  for (let i = 0; i < tableData.length; i++) {
    // ruleid: detect-replaceall-sanitization
    tableData[i].description = tableData[i].description.replaceAll('<', '&lt;').replaceAll('>', '&gt;')
  }
}
```

**Correct (use proper sanitization library):**
```javascript
function encodeProductDescription (tableData: any[]) {
  for (let i = 0; i < tableData.length; i++) {
    // ok - use DOMPurify or sanitize-html instead
    tableData[i].description = DOMPurify.sanitize(tableData[i].description)
  }
}
```

**References:**
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- [DOMPurify](https://www.npmjs.com/package/dompurify)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

---

### Language: TypeScript / React

#### dangerouslySetInnerHTML

**Incorrect (non-constant value in dangerouslySetInnerHTML):**
```typescript
import DOMPurify from "dompurify"
import sanitize from "xss"

function TestComponent2(foo) {
    // ruleid:react-dangerouslysetinnerhtml
    let params = {smth: 'test123', dangerouslySetInnerHTML: {__html: foo.bar},a:b};
    return React.createElement('div', params);
}
```

**Correct (sanitized or static content):**
```typescript
import DOMPurify from "dompurify"
import sanitize from "xss"

function TestComponent1() {
    // ok:react-dangerouslysetinnerhtml
  return <div dangerouslySetInnerHTML={createMarkup()} />;
}

function OkComponent1() {
    // ok:react-dangerouslysetinnerhtml
  return <li className={"foobar"} dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(foo)}} />;
}

function OkComponent3() {
    // ok:react-dangerouslysetinnerhtml
    let params = {smth: 'test123', dangerouslySetInnerHTML: {__html: sanitize(foo)},a:b};
    return React.createElement('div', params);
}

function OkComponent4() {
    // ok:react-dangerouslysetinnerhtml
    let params = {smth: 'test123', dangerouslySetInnerHTML: {__html: "hi"},a:b};
    return React.createElement('div', params);
}
```

**References:**
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- [React dangerouslySetInnerHTML](https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html)

---

#### React Unsanitized Property

**Incorrect (setting innerHTML/outerHTML directly):**
```typescript
function Test2(input) {
  // ruleid: react-unsanitized-property
    ReactDOM.findDOMNode(this.someRef).outerHTML = input.value;
  }
```

**Correct (static content):**
```typescript
  function OkTest1() {
  // ok: react-unsanitized-property
    this.element.innerHTML = "<a href='/about.html'>About</a>";
  }

  function OkTest2() {
  // ok: react-unsanitized-property
    ReactDOM.findDOMNode(this.someRef).outerHTML = "<a href='/about.html'>About</a>";
  }
```

**References:**
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- [React dangerouslySetInnerHTML](https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html)

---

#### Angular DomSanitizer Bypass

**Incorrect (bypassing Angular security):**
```typescript
import { DomSanitizer, SecurityContext } from '@angular/platform-browser'
import DOMPurify from 'dompurify'

class SomeClass {
    constructor(private sanitizer: DomSanitizer){}

    bypass(value: string){
        // ruleid:angular-bypasssecuritytrust
        let html = this.sanitizer.bypassSecurityTrustHtml(value);
        // ruleid:angular-bypasssecuritytrust
        let style = this.sanitizer.bypassSecurityTrustStyle(value);
        // ruleid:angular-bypasssecuritytrust
        let script = this.sanitizer.bypassSecurityTrustScript(value);
        // ruleid:angular-bypasssecuritytrust
        let resource_url = this.sanitizer.bypassSecurityTrustResourceUrl(value);
        // ruleid:angular-bypasssecuritytrust
        let url = this.sanitizer.bypassSecurityTrustUrl(value);
    }
}
```

**Correct (static content or pre-sanitized):**
```typescript
import { DomSanitizer, SecurityContext } from '@angular/platform-browser'
import DOMPurify from 'dompurify'

class SomeClass {
    constructor(private sanitizer: DomSanitizer){}

    bypass(value: string){
        // ok:angular-bypasssecuritytrust
        let url1 = this.sanitizer.bypassSecurityTrustUrl("a");
        // ok:angular-bypasssecuritytrust
        let html1 = this.sanitizer.bypassSecurityTrustHtml("value");
        // ok:angular-bypasssecuritytrust
        let html2 = this.sanitizer.bypassSecurityTrustHtml(DOMPurify.sanitize("value"))
    }
}
```

**References:**
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- [Angular DomSanitizer](https://angular.io/api/platform-browser/DomSanitizer)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

---

### Language: Vue

#### v-html Directive

**Incorrect (using v-html with user content):**
```vue
<div>
  <!-- ruleid: avoid-v-html -->
  <span dir="auto" class="markdown" v-html="entry.post"></span>
</div>
```

**Correct (using template interpolation):**
```vue
<div>
  <!-- ok: avoid-v-html -->
  <span dir="auto" class="markdown">{{entry.post}}</span>
</div>
```

**References:**
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- [Vue Raw HTML Guide](https://vuejs.org/v2/guide/syntax.html#Raw-HTML)

---

### Language: Python

#### Flask Unsanitized Response

**Incorrect (user input in response):**
```python
from flask import make_response, request

def test1():
    # ruleid: response-contains-unsanitized-input
    x = request.args.get("x")
    return make_response("found {}".format(x))


def test1():
    # ruleid: response-contains-unsanitized-input
    x = request.args.get("x")
    y = make_response("found {}".format(x))
    return y


def test3():
    # ruleid: response-contains-unsanitized-input
    x = request.args.get("x")
    return make_response(f"found {x}")
```

**Correct (sanitized input):**
```python
from flask import make_response, request

def test2():
    # ok: response-contains-unsanitized-input
    x = request.args.get("x")
    y = some_safe_operation_on(x)
    return make_response("found {}".format(y))
```

**References:**
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- [Flask Security Guide](https://flask.palletsprojects.com/en/1.0.x/security/)
- [OWASP XSS Attacks](https://owasp.org/www-community/attacks/xss/)

---

#### Django HttpResponse

**Incorrect (request data in HttpResponse):**
```python
import urllib
from django.http import HttpResponse, HttpResponseBadRequest

def search_certificates(request):
    # ruleid: reflected-data-httpresponse
    user_filter = request.GET.get("user", "")
    if not user_filter:
        msg = _("user is not given.")
        return HttpResponseBadRequest(msg)

    user = User.objects.get(Q(email=user_filter) | Q(username=user_filter))
    if user.DoesNotExist:
        return HttpResponse(_("user '{user}' does not exist").format(user_filter))

def inline_test(request):
    # ruleid: reflected-data-httpresponse
    return HttpResponse("Received {}".format(request.POST.get('message')))
```

**Correct (properly handled response):**
```python
from django.http import HttpResponse

def previewNode(request, uid):
    """Preview evaluante node"""
    try:
        if uid in engines:
            # ok: reflected-data-httpresponse
            _nodeId = request.data.get('nodeId')
            engines[uid].stoppable = True
            _res = engines[uid].model.previewNode(_nodeId)
            if _res is None:
                return HttpResponse('', status=204)
            return HttpResponse(_res)
        return manageNoEngine()
    except Exception as e:
        return genericApiException(e, engines[uid])
```

**References:**
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- [Django Book XSS Prevention](https://django-book.readthedocs.io/en/latest/chapter20.html#cross-site-scripting-xss)

---

#### Jinja2 Autoescape

**Incorrect (autoescape disabled):**
```python
import jinja2
from jinja2 import Environment, select_autoescape
templateLoader = jinja2.FileSystemLoader( searchpath="/" )
something = ''

# ruleid:incorrect-autoescape-disabled
Environment(loader=templateLoader, load=templateLoader, autoescape=something)

# ruleid:incorrect-autoescape-disabled
templateEnv = jinja2.Environment(autoescape=False, loader=templateLoader )

Environment(loader=templateLoader,
            load=templateLoader,
# ruleid:incorrect-autoescape-disabled
            autoescape=False)

def fake_func():
    return 'foobar'

# ruleid:incorrect-autoescape-disabled
Environment(loader=templateLoader, autoescape=fake_func())
```

**Correct (autoescape enabled):**
```python
import jinja2
from jinja2 import Environment, select_autoescape
templateLoader = jinja2.FileSystemLoader( searchpath="/" )

# ok:incorrect-autoescape-disabled
Environment(loader=templateLoader, load=templateLoader, autoescape=True)

# ok:incorrect-autoescape-disabled
templateEnv = jinja2.Environment(autoescape=True,
        loader=templateLoader )

# ok:incorrect-autoescape-disabled
Environment(loader=templateLoader, autoescape=select_autoescape())

Environment(loader=templateLoader,
# ok:incorrect-autoescape-disabled
            autoescape=select_autoescape(['html', 'htm', 'xml']))
```

**References:**
- CWE-116: Improper Encoding or Escaping of Output
- [Bandit Jinja2 Autoescape](https://bandit.readthedocs.io/en/latest/plugins/b701_jinja2_autoescape_false.html)
- [Jinja2 API Basics](https://jinja.palletsprojects.com/en/2.11.x/api/#basics)

---

### Language: Go

#### Direct ResponseWriter Write

**Incorrect (writing formatted strings to ResponseWriter):**
```go
package main

import (
    "fmt"
    "net/http"
)

func indexPage(w http.ResponseWriter, r *http.Request) {
    const template = `
    <html>
    <body>
      <h1>Random Movie Quotes</h1>
      <h2>%s</h2>
      <h4>~%s, %s</h4>
    </body>
    </html>`

    quote := getMovieQuote()
    quoteText := quote["quote"]
    movie := quote["movie"]
    year := quote["year"]

    w.WriteHeader(http.StatusAccepted)
    // ruleid: no-direct-write-to-responsewriter
    w.Write([]byte(fmt.Sprintf(template, quoteText, movie, year)))
}

func errorPage(w http.ResponseWriter, r *http.Request) {
    params := r.URL.Query()
    urls, ok := params["url"]
    url := urls[0]

    const template = `
    <html>
    <body>
      <h1>error; page not found. <a href="%s">go back</a></h1>
    </body>
    </html>`

    w.WriteHeader(http.StatusAccepted)
    // ruleid: no-direct-write-to-responsewriter
    w.Write([]byte(fmt.Sprintf(template, url)))
}
```

**Correct (static content or use html/template):**
```go
package main

import (
    "net/http"
)

func healthCheck(w http.ResponseWriter, r *http.Request) {
    // ok: no-direct-write-to-responsewriter
    w.Write([]byte("alive"))
}
```

**References:**
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- [Go Security Pearls - XSS](https://blogtitle.github.io/robn-go-security-pearls-cross-site-scripting-xss/)

---

#### Insecure Template Types

**Incorrect (using insecure template types):**
```go
package main

import "fmt"
import "html/template"

func main() {
    var g = "foo"

    // ruleid:go-insecure-templates
    const a template.HTML = fmt.Sprintf("<a href=%q>link</a>")
    // ruleid:go-insecure-templates
    var b template.CSS = "a { text-decoration: underline; } "
    // ruleid:go-insecure-templates
    var c template.HTMLAttr =  fmt.Sprintf("herf=%q")
    // ruleid:go-insecure-templates
    const d template.JS = "{foo: 'bar'}"
    // ruleid:go-insecure-templates
    var e template.JSStr = "setTimeout('alert()')";
    // ruleid:go-insecure-templates
    var f template.Srcset = g;
}
```

**Correct (use safe template parsing):**
```go
package main

import "html/template"

func main() {
    // ok:go-insecure-templates
    tmpl, err := template.New("test").ParseFiles("file.txt")
    myTpl.Execute(w, data);
}
```

**References:**
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- [Go html/template HTML Type](https://golang.org/pkg/html/template/#HTML)

---

### Language: Ruby

#### raw() Function

**Incorrect (using raw() to bypass escaping):**
```ruby
require "abstract_unit"

class OutputSafetyHelperTest < ActionView::TestCase
  tests ActionView::Helpers::OutputSafetyHelper

  def setup
    @string = "hello"
  end

  test "raw returns the safe string" do
    # ruleid: avoid-raw
    result = raw(@string)
    assert_equal @string, result
  end

  test "raw handles nil values correctly" do
    # ruleid: avoid-raw
    assert_equal "", raw(nil)
  end

  test "safe_join should html_escape any items" do
    # ruleid: avoid-raw
    joined = safe_join([raw("<p>foo</p>"), "<p>bar</p>"], "<br />")
  end
end
```

**References:**
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- [Rails raw() Method](https://api.rubyonrails.org/classes/ActionView/Helpers/OutputSafetyHelper.html#method-i-raw)
- [Preventing XSS in Rails](https://www.netsparker.com/blog/web-security/preventing-xss-ruby-on-rails-web-applications/)

---

#### html_safe() Method

**Incorrect (using html_safe() to bypass escaping):**
```ruby
# ruleid: avoid-html-safe
"foo".html_safe

# ruleid: avoid-html-safe
"<div>foo</div>".html_safe + "<bar>"

# ruleid: avoid-html-safe
html = "<div>".html_safe

# ruleid: avoid-html-safe
"<div>".html_safe.tap
```

**Correct (no html_safe on user input):**
```ruby
# ok: avoid-html-safe
"foo".length

# ok: avoid-html-safe
html = "<div>"
```

**References:**
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- [Brakeman XSS Checks](https://github.com/presidentbeef/brakeman/blob/main/docs/warning_types/cross_site_scripting/index.markdown)
- [Preventing XSS in Rails](https://www.netsparker.com/blog/web-security/preventing-xss-ruby-on-rails-web-applications/)

---

### Language: Java

#### ServletResponse Writer XSS

**Incorrect (writing request parameters directly):**
```java
package servlets;

import java.io.PrintWriter;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Cls extends HttpServlet
{
    protected void danger(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String input1 = req.getParameter("input1");
        // ruleid:servletresponse-writer-xss
        resp.getWriter().write(input1);
    }

    protected void danger2(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String input1 = req.getParameter("input1");
        // ruleid:servletresponse-writer-xss
        PrintWriter writer = resp.getWriter();
        writer.write(input1);
    }
}
```

**Correct (encode output):**
```java
package servlets;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Cls extends HttpServlet
{
    protected void ok(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String input1 = req.getParameter("input1");
        // ok:servletresponse-writer-xss
        resp.getWriter().write(Encode.forHtml(input1));
    }
}
```

**References:**
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- [Find Security Bugs - XSS Servlet](https://find-sec-bugs.github.io/bugs.htm#XSS_SERVLET)
- [OWASP Injection Guide](https://owasp.org/Top10/A03_2021-Injection)

---

### Language: PHP

#### Echo with Request Data

**Incorrect (echoing user input):**
```php
<?php

// example key-value: name=%3Cscript%3Econfirm%28%29%3C%2Fscript%3E
function dangerousEchoUsage() {
    $name = $_REQUEST['name'];
    // ruleid: echoed-request
    echo "Hello : $name";
    // ruleid: echoed-request
    echo "Hello : " . $name;
}

function doSmth() {
    $name = $_REQUEST['name'];
    // ruleid: echoed-request
    echo "Hello :".$name;
}

function doSmth2() {
    // ruleid: echoed-request
    echo "Hello ".$_POST['name']." !";
}

function doSmth3() {
    $name = $_GET['name'];
    if (str_contains($name, 'foobar')) {
        // ruleid: echoed-request
        echo "Hello :".$name;
    }
}
```

**Correct (use htmlentities or htmlspecialchars):**
```php
<?php

function safeEchoUsage() {
    $name = $_REQUEST['name'];
    // ok: echoed-request
    echo "Hello : " . htmlentities($name);
}

function doOK1() {
    // ok: echoed-request
    echo "Hello ".htmlentities($_POST['name'])." !";
}

function doOK2() {
    $input = $_GET['name'];
    // ok: echoed-request
    echo "Hello ".htmlspecialchars($input)." !";
}

function doOK3() {
    $safevar = "Hello ".htmlentities(trim($_GET['name']));
    // ok: echoed-request
    echo $safevar;
}

function doOK4() {
    // ok: echoed-request - Laravel escape function
    echo "Hello ".e($_POST['name'])." !";
}

function doOK5() {
    // ok: echoed-request - WordPress escape function
    $safevar = esc_attr($_GET['name']);
    echo "Hello $safevar !";
}
```

**References:**
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- [PHP htmlentities()](https://www.php.net/manual/en/function.htmlentities.php)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

---

### Language: Scala

#### Play Framework HTML Response

**Incorrect (user input in HTML response):**
```scala
package controllers

import play.api._
import play.api.mvc.{Action, Controller}
import play.twirl.api.Html;

class XssController extends Controller {

  def vulnerable1(value: String) = Action { implicit request: Request[AnyContent] =>
    // ruleid: tainted-html-response
    Ok(s"Hello $value !").as("text/html")
  }

  def vulnerable2(value: String) = Action.async { implicit request: Request[AnyContent] =>
    // ruleid: tainted-html-response
    Ok("Hello " + value + " !").as("tExT/HtML")
  }

  def vulnerable6(value:String) = Action { implicit request: Request[AnyContent] =>
    // ruleid: tainted-html-response
    Ok(views.html.xssHtml.render(Html.apply("Hello "+value+" !")))
  }
}
```

**Correct (use templates or escape):**
```scala
package controllers

import play.api._
import play.api.mvc.{Action, Controller}
import play.twirl.api.Html;

class XssController extends Controller {

  def safeJson(value: String) = Action.async { implicit request: Request[AnyContent] =>
    // ok: tainted-html-response
    Ok("Hello " + value + " !").as("text/json")
  }

  def safeTemplate(value:String) = Action {
    // ok: tainted-html-response
    Ok(views.html.template.render(value))
  }

  def variousSafe(value: String) = Action { implicit request: Request[AnyContent] =>
    // ok: tainted-html-response
    Ok("Hello "+value+" !")
    // ok: tainted-html-response
    Ok(s"Hello $value !").as("text/json")
    // ok: tainted-html-response
    Ok("<b>Hello !</b>").as("text/html")
    // ok: tainted-html-response
    Ok(views.html.xssHtml.render(Html.apply("<b>Hello !</b>")))

    val escapedValue = org.apache.commons.lang3.StringEscapeUtils.escapeHtml4(value)
    // ok: tainted-html-response
    Ok("Hello " + escapedValue + " !").as("text/html")

    val owaspEscapedValue = org.owasp.encoder.Encode.forHtml(value)
    // ok: tainted-html-response
    Ok("Hello " + owaspEscapedValue + " !").as("text/html")
  }
}
```

**References:**
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- [OWASP Injection Guide](https://owasp.org/Top10/A03_2021-Injection)

---

## General Prevention Guidelines

1. **Always escape output** - Use context-appropriate encoding (HTML, JavaScript, URL, CSS)
2. **Use framework-provided templating** - Most frameworks auto-escape by default
3. **Validate and sanitize input** - Whitelist allowed characters/patterns
4. **Use Content Security Policy (CSP)** - Add defense-in-depth via HTTP headers
5. **Use sanitization libraries** - DOMPurify, sanitize-html, OWASP Java Encoder
6. **Never trust user input** - Treat all external data as potentially malicious
7. **Set HttpOnly flag on cookies** - Prevents JavaScript access to session cookies
