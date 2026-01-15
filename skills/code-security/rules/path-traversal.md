---
title: Prevent Path Traversal
impact: CRITICAL
impactDescription: Arbitrary file access, information disclosure, file manipulation
tags: security, path-traversal, cwe-22, cwe-23, cwe-73, cwe-98
---

## Prevent Path Traversal

Path traversal occurs when user input is used to construct file paths without proper validation, allowing attackers to access files outside intended directories using sequences like "../". This can lead to sensitive data exposure, arbitrary file reads/writes, and system compromise.

---

### Language: Ruby

#### Rails send_file Vulnerability

**Incorrect (vulnerable to path traversal):**
```ruby
def test_send_file
    # ruleid: check-send-file
    send_file params[:file]
end

def test_send_file2
    # ruleid: check-send-file
    send_file cookies[:something]
end

def test_send_file8
    # ruleid: check-send-file
    send_file request.env[:badheader]
end
```

**Correct (safe):**
```ruby
def test_send_file_ok
    # ok: check-send-file
    send_file "some_safe_file.txt"
end

def test_send_file5
    # ok: check-send-file
    send_file cookies.encrypted[:something]
end
```

**References:**
- CWE-73: External Control of File Name or Path
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)

---

#### Rails render Local File Include

**Incorrect (vulnerable to path traversal):**
```ruby
def test_dynamic_render
    page = params[:page]
    #ruleid: check-render-local-file-include
    render :file => "/some/path/#{page}"
end

def test_render_with_modern_param
    page = params[:page]
    #ruleid: check-render-local-file-include
    render file: "/some/path/#{page}"
end

def test_render_with_first_positional_argument
    page = params[:page]
    #ruleid: check-render-local-file-include
    render page
end
```

**Correct (path validated):**
```ruby
def test_render_with_modern_param
    page = params[:page]
    #ok: check-render-local-file-include
    render file: File.basename("/some/path/#{page}")
end

def test_param_ok
    map = make_map
    thing = map[params.id]
    # ok: check-render-local-file-include
    render :file => "/some/path/#{thing}"
end

def test_render_static_template_name
    # ok: check-render-local-file-include
    render :update, locals: { username: params[:username] }
end
```

**References:**
- CWE-22: Path Traversal
- [OWASP Local File Inclusion Testing](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)

---

#### Rails Tainted File Access

**Incorrect (vulnerable to path traversal):**
```ruby
def foo
    # ruleid: avoid-tainted-file-access
    File.open("/tmp/#{params[:name]}")

    # ruleid: avoid-tainted-file-access
    Dir.open("/tmp/#{params[:name]}")

    # ruleid: avoid-tainted-file-access
    File.delete("/tmp/#{params[:name]}")

    # ruleid: avoid-tainted-file-access
    File.readlines("/tmp/#{params[:name]}")
end
```

**Correct (safe):**
```ruby
def foo
    # ok: avoid-tainted-file-access
    File.open("/tmp/usr/bin")

    # ok: avoid-tainted-file-access
    File.basename("/tmp/#{params[:name]}")
end
```

**References:**
- CWE-22: Path Traversal
- [Brakeman File Access Warnings](https://github.com/presidentbeef/brakeman/blob/main/docs/warning_types/file_access/index.markdown)

---

#### Rails File Disclosure

**Incorrect (vulnerable):**
```ruby
def bad_file_disclosure
    # ruleid: file-disclosure
    config.serve_static_assets = true
end
```

**Correct (safe):**
```ruby
def ok_file_disclosure
    # ok: file-disclosure
    config.serve_static_assets = false
end
```

**References:**
- CWE-22: Path Traversal
- [Rails Security Advisory](https://groups.google.com/g/rubyonrails-security/c/23fiuwb1NBA/m/MQVM1-5GkPMJ)

---

### Language: JavaScript/TypeScript

#### Non-Literal fs Filename

**Incorrect (vulnerable to path traversal):**
```javascript
const {readFile} = require('fs/promises')
const fs = require('fs')

function test1(fileName) {
  // ruleid:detect-non-literal-fs-filename
  readFile(fileName)
    .then((resolve, reject) => {
      foobar()
    })
}

async function test2(fileName) {
  // ruleid:detect-non-literal-fs-filename
  const data = await fs.promises.mkdir(fileName, {})
  foobar(data)
}

function test3(fileName) {
  const data = new Uint8Array(Buffer.from('Hello Node.js'));
  // ruleid:detect-non-literal-fs-filename
  fs.writeFile(fileName, data, (err) => {
    if (err) throw err;
    console.log('The file has been saved!');
  });
}
```

**Correct (safe):**
```javascript
function okTest1(data) {
  const data = new Uint8Array(Buffer.from('Hello Node.js'));
  // ok:detect-non-literal-fs-filename
  fs.writeFile('message.txt', data, (err) => {
    if (err) throw err;
    console.log('The file has been saved!');
  });
}

async function okTest2() {
  let filehandle;
  try {
    // ok:detect-non-literal-fs-filename
    filehandle = await fs.promises.open('thefile.txt', 'r');
  } finally {
    if (filehandle !== undefined)
      await filehandle.close();
  }
}
```

**References:**
- CWE-22: Path Traversal
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)

---

#### path.join/path.resolve Traversal

**Incorrect (vulnerable to path traversal):**
```javascript
var path = require('path');

function test1() {
    function someFunc(entry) {
        // ruleid:path-join-resolve-traversal
        var extractPath = path.join(opts.path, entry.path);
        return extractFile(extractPath);
    }
    someFunc();
}

function test2() {
    function someFunc(val) {
        createFile({
            // ruleid:path-join-resolve-traversal
            filePath: path.resolve(opts.path, val)
        })
        return true
    }
    someFunc()
}
```

**Correct (path sanitized):**
```javascript
function okTest3(req,res) {
    let somePath = req.body.path;
    somePath = somePath.replace(/^(\.\.(\/|\\|$))+/, '');
    // ok:path-join-resolve-traversal
    return path.join(opts.path, somePath);
}

function okTest4(req,res) {
    let somePath = sanitizer(req.body.path);
    // ok:path-join-resolve-traversal
    return path.join(opts.path, somePath);
}

function okTest5(req,res) {
    let somePath = req.body.path;
    // ok:path-join-resolve-traversal
    let result = path.join(opts.path, somePath);
    if (result.indexOf(opts.path) === 0) {
        return path;
    }
    return null
}
```

**References:**
- CWE-22: Path Traversal
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)

---

#### Express res.sendFile

**Incorrect (vulnerable to path traversal):**
```typescript
import path = require('path')
import { Request, Response, NextFunction } from 'express'

module.exports = function badNormal () {
  return (req: Request, res: Response, next: NextFunction) => {
    const file = req.params.file
    // ruleid: express-res-sendfile
    res.sendFile(path.resolve('ftp/', file))
    // ruleid: express-res-sendfile
    res.sendFile(path.join('/ftp/', file))
    // ruleid: express-res-sendfile
    res.sendFile(file)
  }
}
```

**Correct (safe with root option or static file):**
```typescript
module.exports = function goodNormal () {
  return (req: Request, res: Response, next: NextFunction) => {
    const file = 'foo'
    // ok: express-res-sendfile
    res.sendFile(path.resolve('ftp/', file))
    // ok: express-res-sendfile
    res.sendfile(req.params.foo, {root: '/'});
    // ok: express-res-sendfile
    res.sendfile(req.params.foo, options);
  }
}
```

**References:**
- CWE-73: External Control of File Name or Path
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)

---

#### Express path.join/resolve Traversal

**Incorrect (vulnerable to path traversal):**
```javascript
const path = require('path')
const express = require('express')
const app = express()

app.get('/test1', (req, res) => {
    // ruleid:express-path-join-resolve-traversal
    var extractPath = path.join(opts.path, req.query.path);
    extractFile(extractPath);
    res.send('Hello World!');
})

app.post('/test2', function test2(req, res) {
    // ruleid:express-path-join-resolve-traversal
    createFile({filePath: path.resolve(opts.path, req.body)})
    res.send('Hello World!')
})
```

**Correct (sanitized):**
```javascript
app.post('/ok-test3', function (req,res) {
    let somePath = req.body.path;
    somePath = somePath.replace(/^(\.\.(\/|\\|$))+/, '');
    // ok:express-path-join-resolve-traversal
    return path.join(opts.path, somePath);
})

app.post('/ok-test4', function (req,res) {
    let somePath = sanitizer(req.body.path);
    // ok:express-path-join-resolve-traversal
    return path.join(opts.path, somePath);
})
```

**References:**
- CWE-22: Path Traversal
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)

---

### Language: Python

#### Django FileResponse Path Traversal

**Incorrect (vulnerable to path traversal):**
```python
from django.http import FileResponse

def func(request):
    # ruleid: request-data-fileresponse
    filename = request.POST.get("filename")
    f = open(filename, 'rb')
    return FileResponse(f)
```

**Correct (safe):**
```python
def safe(request):
    # ok: request-data-fileresponse
    url = request.GET.get("url")
    print(url)
    f = open("blah.txt", 'r')
    return FileResponse(f)
```

**References:**
- CWE-22: Path Traversal
- [Django Security](https://django-book.readthedocs.io/en/latest/chapter20.html#cross-site-scripting-xss)

---

#### Django open() Path Traversal

**Incorrect (vulnerable to path traversal):**
```python
def unsafe(request):
    # ruleid: path-traversal-open
    filename = request.POST.get('filename')
    contents = request.POST.get('contents')
    print("something")
    f = open(filename, 'r')
    f.write(contents)
    f.close()

def unsafe_with(request):
    # ruleid: path-traversal-open
    filename = request.POST.get("filename")
    with open(filename, 'r') as fin:
        data = fin.read()
    return HttpResponse(data)
```

**Correct (safe):**
```python
def safe(request):
    # ok: path-traversal-open
    filename = "/tmp/data.txt"
    f = open(filename)
    f.write("hello")
    f.close()
```

**References:**
- CWE-22: Path Traversal
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)

---

#### Django os.path.join Path Traversal

**Incorrect (vulnerable to path traversal):**
```python
from django.http import HttpResponse
import os

def foo_1(request):
  # ruleid: path-traversal-join
  param = request.GET.get('param')
  file_path = os.path.join("MY_SECRET", param)
  f = open(file_path, 'r')
  return HttpResponse(content=f, content_type="text/plain")

def user_pic(request):
    base_path = os.path.join(os.path.dirname(__file__), '../../badguys/static/images')
    # ruleid: path-traversal-join
    filename = request.GET.get('p')
    data = open(os.path.join(base_path, filename), 'rb').read()
    return HttpResponse(data, content_type=mimetypes.guess_type(filename)[0])
```

**Correct (path validated with abspath):**
```python
def foo_2(request):
  # ok due to abspath
  param = request.GET.get('param')
  file_path = os.path.join("MY_SECRET", param)
  file_path = os.path.abspath(file_path)
  f = open(file_path, 'r')
  return HttpResponse(content=f, content_type="text/plain")
```

**References:**
- CWE-22: Path Traversal
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)

---

#### Flask send_file Path Traversal

**Incorrect (vulnerable to path traversal):**
```python
from flask import send_file

app = Flask(__name__)

@app.route("/<path:filename>")
def download_file(filename):
  # ruleid:avoid_send_file_without_path_sanitization
  return send_file(filename)
```

**Correct (not a Flask route or use send_from_directory):**
```python
def download_not_flask_route(filename):
  # ok:avoid_send_file_without_path_sanitization
  return send_file(filename)
```

**References:**
- CWE-73: External Control of File Name or Path
- [OWASP Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design)

---

#### Flask open() Path Traversal

**Incorrect (vulnerable to path traversal):**
```python
import flask

app = flask.Flask(__name__)

@app.route("/route_param/<route_param>")
def route_param(route_param):
    print("blah")
    # ruleid: path-traversal-open
    return open(route_param, 'r').read()

@app.route("/get_param", methods=["GET"])
def get_param():
    param = flask.request.args.get("param")
    # ruleid: path-traversal-open
    f = open(param, 'w')
    f.write("hello world")

@app.route("/post_param", methods=["POST"])
def post_param():
    param = flask.request.form['param']
    if True:
        # ruleid: path-traversal-open
        with open(param, 'r') as fin:
            data = json.load(fin)
    return data
```

**Correct (static path):**
```python
@app.route("/ok")
def ok():
    # ok: path-traversal-open
    open("static/path.txt", 'r')

@app.route("/route_param_ok/<route_param>")
def route_param_ok(route_param):
    print("blah")
    # ok: path-traversal-open
    return open("this is safe", 'r').read()
```

**References:**
- CWE-22: Path Traversal
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)

---

### Language: Java

#### Spring Tainted File Path

**Incorrect (vulnerable to path traversal):**
```java
@RestController
public class PreflightController {
    @RequestMapping(
            CONTENT_DISPOSITION_STATIC_FILE_LOCATION + FrameworkConstants.SLASH + "{fileName}")
    public ResponseEntity<byte[]> fetchFile(@PathVariable("fileName") String fileName)
            throws IOException {
        InputStream inputStream =
                // ruleid: tainted-file-path
                new FileInputStream(
                        unrestrictedFileUpload.getContentDispositionRoot().toFile()
                                + FrameworkConstants.SLASH
                                + fileName);
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(HttpHeaders.CONTENT_DISPOSITION, "attachment");
        return new ResponseEntity<byte[]>(
                IOUtils.toByteArray(inputStream), httpHeaders, HttpStatus.OK);
    }

    public static void bad(@RequestParam String user) {
        // ruleid: tainted-file-path
        BufferedReader fileReader = new BufferedReader(new FileReader("/home/" + user + "/" + filename));
    }
}
```

**Correct (sanitized with FilenameUtils):**
```java
public static void ok(@RequestParam String filename) {
    ApplicationContext appContext =
       new ClassPathXmlApplicationContext(new String[] {"If-you-have-any.xml"});

    // ok: tainted-file-path
    Resource resource =
       appContext.getResource("classpath:com/" + org.apache.commons.io.FilenameUtils.getName(filename));
}
```

**References:**
- CWE-23: Relative Path Traversal
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)

---

#### HttpServlet Path Traversal

**Incorrect (vulnerable to path traversal):**
```java
public class Cls extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response)
    throws ServletException, IOException {
        String image = request.getParameter("image");
        // ruleid:httpservlet-path-traversal
        File file = new File("static/images/", image);

        if (!file.exists()) {
            log.info(image + " could not be created.");
            response.sendError();
        }
        response.sendRedirect("/index.html");
    }
}
```

**Correct (sanitized with FilenameUtils):**
```java
public void ok(HttpServletRequest request, HttpServletResponse response)
throws ServletException, IOException {
    // ok:httpservlet-path-traversal
    String image = request.getParameter("image");
    File file = new File("static/images/", FilenameUtils.getName(image));

    if (!file.exists()) {
        log.info(image + " could not be created.");
        response.sendError();
    }
    response.sendRedirect("/index.html");
}
```

**References:**
- CWE-22: Path Traversal
- [OWASP Path Traversal](https://www.owasp.org/index.php/Path_Traversal)

---

#### JAX-RS Path Traversal

**Incorrect (vulnerable to path traversal):**
```java
@Path("/")
public class Cls {
    // ruleid:jax-rs-path-traversal
    @GET
    @Path("/images/{image}")
    @Produces("images/*")
    public Response getImage(@javax.ws.rs.PathParam("image") String image) {
        File file = new File("resources/images/", image); //Weak point

        if (!file.exists()) {
            return Response.status(Status.NOT_FOUND).build();
        }
        return Response.ok().entity(new FileInputStream(file)).build();
    }
}
```

**Correct (sanitized with FilenameUtils):**
```java
// ok:jax-rs-path-traversal
@GET
@Path("/images/{image}")
@Produces("images/*")
public Response ok(@javax.ws.rs.PathParam("image") String image) {
    File file = new File("resources/images/", FilenameUtils.getName(image)); //Fix

    if (!file.exists()) {
        return Response.status(Status.NOT_FOUND).build();
    }
    return Response.ok().entity(new FileInputStream(file)).build();
}
```

**References:**
- CWE-22: Path Traversal
- [OWASP Path Traversal](https://www.owasp.org/index.php/Path_Traversal)

---

### Language: C#

#### Unsafe Path.Combine

**Incorrect (vulnerable to path traversal):**
```csharp
public class Foo{
    public static bytes[] GetFileBad(string filename) {
        if (string.IsNullOrEmpty(filename))
        {
            throw new ArgumentNullException("error");
        }
        string filepath = Path.Combine("\\FILESHARE\images", filename);
        // ruleid: unsafe-path-combine
        return File.ReadAllBytes(filepath);
    }
}
```

**Correct (sanitized with Path.GetFileName):**
```csharp
public static bytes[] GetFileSafe(string filename) {
    if (string.IsNullOrEmpty(filename))
    {
        throw new ArgumentNullException("error");
    }
    filename = Path.GetFileName(filename);
    // ok: unsafe-path-combine
    string filepath = Path.Combine("\\FILESHARE\images", filename);
    return File.ReadAllBytes(filepath);
}

public static bytes[] GetFileSafe2(string filename) {
    if (string.IsNullOrEmpty(filename) || Path.GetFileName(filename) != filename)
    {
        throw new ArgumentNullException("error");
    }
    string filepath = Path.Combine("\\FILESHARE\images", filename);
    // ok: unsafe-path-combine
    return File.ReadAllBytes(filepath);
}

public static bytes[] GetFileSafe3(string filename) {
    if (string.IsNullOrEmpty(filename))
    {
        throw new ArgumentNullException("error");
    }
    // ok: unsafe-path-combine
    string filepath = Path.Combine("\\FILESHARE\images", Path.GetFileName(filename));
}
```

**References:**
- CWE-22: Path Traversal
- [Path.Combine Security Issues](https://www.praetorian.com/blog/pathcombine-security-issues-in-aspnet-applications/)
- [Microsoft Path.Combine Documentation](https://docs.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-6.0#remarks)

---

### Language: PHP

#### File Inclusion (LFI/RFI)

**Incorrect (vulnerable to path traversal/RFI):**
```php
<?php
$user_input = $_GET["tainted"];

// ruleid: file-inclusion
include($user_input);

// ruleid: file-inclusion
include_once($user_input);

// ruleid: file-inclusion
require($user_input);

// ruleid: file-inclusion
require_once($user_input);

// ruleid: file-inclusion
include(__DIR__ . $user_input);
?>
```

**Correct (constant paths):**
```php
<?php
// ok: file-inclusion
include('constant.php');

// ok: file-inclusion
require_once('constant.php');

// ok: file-inclusion
include(__DIR__ . 'constant.php');

// ok: file-inclusion
include_safe(__DIR__ . $user_input);

// ok: file-inclusion
require_once(CONFIG_DIR . '/constant.php');

// ok: file-inclusion
require_once( dirname( __FILE__ ) . '/admin.php' );
?>
```

**References:**
- CWE-98: PHP Remote File Inclusion
- [PHP include Documentation](https://www.php.net/manual/en/function.include.php)
- [File Inclusion Vulnerability Types](https://en.wikipedia.org/wiki/File_inclusion_vulnerability#Types_of_Inclusion)

---

#### unlink() Path Traversal

**Incorrect (vulnerable to path traversal):**
```php
<?php
$data = $_GET["data"];
// ruleid: unlink-use
unlink("/storage/" . $data . "/test");
?>
```

**Correct (constant path):**
```php
<?php
// ok: unlink-use
unlink('/storage/foobar/test');
?>
```

**References:**
- CWE-22: Path Traversal
- [PHP unlink Documentation](https://www.php.net/manual/en/function.unlink)

---

#### WordPress File Operations

**Incorrect (potential path traversal):**
```php
<?php
// ruleid: wp-file-download-audit
$json = file_get_contents( 'php://input' );

// ruleid: wp-file-download-audit
readfile($zip_name);

// ruleid: wp-file-inclusion-audit
require $located;

// ruleid: wp-file-inclusion-audit
include_once($extension_upload_value);

// ruleid: wp-file-manipulation-audit
wp_delete_file( $file_path );

// ruleid: wp-file-manipulation-audit
unlink($file_path);
?>
```

**References:**
- CWE-22: Path Traversal
- CWE-73: External Control of File Name or Path
- [WordPress Plugin Security Testing Cheat Sheet](https://github.com/wpscanteam/wpscan/wiki/WordPress-Plugin-Security-Testing-Cheat-Sheet)

---

### Language: Scala

#### Source.fromFile Path Traversal

**Incorrect (vulnerable to path traversal):**
```scala
class Test {
  def bad1(value:String) = Action {
    if (!Files.exists(Paths.get("public/lists/" + value))) {
      NotFound("File not found")
    } else {
      // ruleid: path-traversal-fromfile
      val result = Source.fromFile("public/lists/" + value).getLines().mkString // Weak point
      Ok(result)
    }
  }

  def bad3(value:String) = Action {
    if (!Files.exists(Paths.get("public/lists/" + value))) {
      NotFound("File not found")
    } else {
      // ruleid: path-traversal-fromfile
      val result = Source.fromFile("%s/%s".format("public/lists", value)).getLines().mkString
      Ok(result)
    }
  }
}
```

**Correct (sanitized with FilenameUtils):**
```scala
def ok(value:String) = Action {
    val filename = "public/lists/" + FilenameUtils.getName(value)

    if (!Files.exists(Paths.get(filename))) {
      NotFound("File not found")
    } else {
      // ok: path-traversal-fromfile
      val result = Source.fromFile(filename).getLines().mkString // Fix
      Ok(result)
    }
  }
```

**References:**
- CWE-22: Path Traversal
- [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control)

---

### Language: Go

#### Zip File Extraction Traversal

**Incorrect (vulnerable to zip slip):**
```go
func unzip(archive, target string) error {
	// ruleid: path-traversal-inside-zip-extraction
	reader, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(target, 0750); err != nil {
		return err
	}

	for _, file := range reader.File {
		path := filepath.Join(target, file.Name)
		if file.FileInfo().IsDir() {
			os.MkdirAll(path, file.Mode())
			continue
		}

		fileReader, err := file.Open()
		if err != nil {
			return err
		}
		defer fileReader.Close()

		targetFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			return err
		}
		defer targetFile.Close()

		if _, err := io.Copy(targetFile, fileReader); err != nil {
			return err
		}
	}
	return nil
}
```

**References:**
- CWE-22: Path Traversal
- [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control)

---

#### filepath.Clean Misuse

**Incorrect (Clean does not prevent traversal):**
```go
func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/bad1", func(w http.ResponseWriter, r *http.Request) {
		// ruleid: filepath-clean-misuse
		filename := filepath.Clean(r.URL.Path)
		filename := filepath.Join(root, strings.Trim(filename, "/"))
		contents, err := ioutil.ReadFile(filename)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write(contents)
	})

	mux.HandleFunc("/bad2", func(w http.ResponseWriter, r *http.Request) {
		// ruleid: filepath-clean-misuse
		filename := path.Clean(r.URL.Path)
		filename := filepath.Join(root, strings.Trim(filename, "/"))
		contents, err := ioutil.ReadFile(filename)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write(contents)
	})
}
```

**Correct (prefix with "/" or use SecureJoin):**
```go
mux.HandleFunc("/ok2", func(w http.ResponseWriter, r *http.Request) {
    // ok: filepath-clean-misuse
    filename := path.Clean("/" + r.URL.Path)
    filename := filepath.Join(root, strings.Trim(filename, "/"))
    contents, err := ioutil.ReadFile(filename)
    if err != nil {
        w.WriteHeader(http.StatusNotFound)
        return
    }
    w.Write(contents)
})
```

**Best Practice:** Use `filepath.FromSlash(path.Clean("/"+strings.Trim(req.URL.Path, "/")))` or the `SecureJoin` function from `github.com/cyphar/filepath-securejoin`.

**References:**
- CWE-22: Path Traversal
- [Go path.Clean Documentation](https://pkg.go.dev/path#Clean)
- [Go Path Traversal Article](https://dzx.cz/2021/04/02/go_path_traversal/)
- [Grafana Zero-Day Path Traversal](https://labs.detectify.com/2021/12/15/zero-day-path-traversal-grafana/)
- [filepath-securejoin Package](https://pkg.go.dev/github.com/cyphar/filepath-securejoin#section-readme)
