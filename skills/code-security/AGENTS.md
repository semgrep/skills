# Code Security

**Version 0.1.0**  
Semgrep Engineering  
January 2026

> **Note:**  
> This document is mainly for agents and LLMs to follow when maintaining,  
> generating, or refactoring codebases with a focus on security best practices. Humans  
> may also find it useful, but guidance here is optimized for automation  
> and consistency by AI-assisted workflows.

---

## Abstract

Comprehensive code security guide, designed for AI agents and LLMs.

---

## Table of Contents

1. [SQL Injection](#1-sql-injection) — **CRITICAL**
   - 1.1 [Prevent SQL Injection](#11-prevent-sql-injection)
2. [Command Injection](#2-command-injection) — **CRITICAL**
   - 2.1 [Prevent Command Injection](#21-prevent-command-injection)
3. [Cross-Site Scripting](#3-cross-site-scripting) — **CRITICAL**
   - 3.1 [Prevent Cross-Site Scripting (XSS)](#31-prevent-cross-site-scripting-xss)
4. [XML External Entity](#4-xml-external-entity) — **CRITICAL**
   - 4.1 [Prevent XML External Entity (XXE) Injection](#41-prevent-xml-external-entity-xxe-injection)
5. [Path Traversal](#5-path-traversal) — **CRITICAL**
   - 5.1 [Prevent Path Traversal](#51-prevent-path-traversal)
6. [Insecure Deserialization](#6-insecure-deserialization) — **CRITICAL**
   - 6.1 [Prevent Insecure Deserialization](#61-prevent-insecure-deserialization)
7. [Code Injection](#7-code-injection) — **CRITICAL**
   - 7.1 [Prevent Code Injection](#71-prevent-code-injection)
8. [Hardcoded Secrets](#8-hardcoded-secrets) — **CRITICAL**
   - 8.1 [Avoid Hardcoded Secrets](#81-avoid-hardcoded-secrets)
9. [Memory Safety](#9-memory-safety) — **CRITICAL**
   - 9.1 [Ensure Memory Safety](#91-ensure-memory-safety)
10. [Insecure Cryptography](#10-insecure-cryptography) — **HIGH**
   - 10.1 [Avoid Insecure Cryptography](#101-avoid-insecure-cryptography)
11. [Insecure Transport](#11-insecure-transport) — **HIGH**
   - 11.1 [Use Secure Transport](#111-use-secure-transport)
12. [Server-Side Request Forgery](#12-server-side-request-forgery) — **HIGH**
   - 12.1 [Prevent Server-Side Request Forgery](#121-prevent-server-side-request-forgery)
13. [JWT Authentication](#13-jwt-authentication) — **HIGH**
   - 13.1 [Secure JWT Authentication](#131-secure-jwt-authentication)
14. [Cross-Site Request Forgery](#14-cross-site-request-forgery) — **HIGH**
   - 14.1 [Prevent Cross-Site Request Forgery](#141-prevent-cross-site-request-forgery)
15. [Prototype Pollution](#15-prototype-pollution) — **HIGH**
   - 15.1 [Prevent Prototype Pollution](#151-prevent-prototype-pollution)
16. [Unsafe Functions](#16-unsafe-functions) — **HIGH**
   - 16.1 [Avoid Unsafe Functions](#161-avoid-unsafe-functions)
17. [Terraform AWS Security](#17-terraform-aws-security) — **HIGH**
   - 17.1 [Secure AWS Terraform Configurations](#171-secure-aws-terraform-configurations)
18. [Terraform Azure Security](#18-terraform-azure-security) — **HIGH**
   - 18.1 [Secure Azure Terraform Configurations](#181-secure-azure-terraform-configurations)
19. [Terraform GCP Security](#19-terraform-gcp-security) — **HIGH**
   - 19.1 [Secure GCP Terraform Configurations](#191-secure-gcp-terraform-configurations)
20. [Kubernetes Security](#20-kubernetes-security) — **HIGH**
   - 20.1 [Secure Kubernetes Configurations](#201-secure-kubernetes-configurations)
21. [Docker Security](#21-docker-security) — **HIGH**
   - 21.1 [Secure Docker Configurations](#211-secure-docker-configurations)
22. [GitHub Actions Security](#22-github-actions-security) — **HIGH**
   - 22.1 [Secure GitHub Actions](#221-secure-github-actions)
23. [Regular Expression DoS](#23-regular-expression-dos) — **MEDIUM**
   - 23.1 [Prevent Regular Expression DoS](#231-prevent-regular-expression-dos)
24. [Race Conditions](#24-race-conditions) — **MEDIUM**
   - 24.1 [Prevent Race Conditions](#241-prevent-race-conditions)
25. [Code Correctness](#25-code-correctness) — **MEDIUM**
   - 25.1 [Code Correctness](#251-code-correctness)
26. [Best Practices](#26-best-practices) — **LOW**
   - 26.1 [Code Best Practices](#261-code-best-practices)
27. [Performance](#27-performance) — **LOW**
   - 27.1 [Performance Best Practices](#271-performance-best-practices)
28. [Maintainability](#28-maintainability) — **LOW**
   - 28.1 [Code Maintainability](#281-code-maintainability)

---

## 1. SQL Injection

**Impact: CRITICAL**

SQL injection allows attackers to manipulate database queries, leading to data theft, modification, or deletion. OWASP Top 10.

### 1.1 Prevent SQL Injection

**Impact: CRITICAL (Attackers can read, modify, or delete database data)**

SQL injection allows attackers to manipulate database queries by injecting malicious SQL through user input. Never concatenate user input into SQL queries - always use parameterized queries or prepared statements.

Vulnerable patterns: String concatenation (+), format strings (.format(), %, f-strings, String.Format()), template literals with variables.

**Incorrect: string concatenation**

```python
import psycopg2

def get_user(user_input):
    conn = psycopg2.connect("dbname=test")
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    cur.execute(query)
```

**Incorrect: format string**

```python
def get_user(user_input):
    cur.execute("SELECT * FROM users WHERE id = {}".format(user_input))
```

**Incorrect: f-string**

```python
def get_user(user_input):
    cur.execute(f"SELECT * FROM users WHERE id = {user_input}")
```

**Correct: parameterized query**

```python
def get_user(user_input):
    conn = psycopg2.connect("dbname=test")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = %s", [user_input])
```

**Incorrect: template literal with variable**

```javascript
const { Pool } = require('pg')
const pool = new Pool()

async function getUser(userId) {
  const sql = `SELECT * FROM users WHERE id = ${userId}`
  const { rows } = await pool.query(sql)
  return rows
}
```

**Incorrect: string concatenation**

```javascript
async function getUser(userId) {
  const sql = "SELECT * FROM users WHERE id = " + userId
  const { rows } = await pool.query(sql)
  return rows
}
```

**Correct: parameterized query**

```javascript
async function getUser(userId) {
  const sql = 'SELECT * FROM users WHERE id = $1'
  const { rows } = await pool.query(sql, [userId])
  return rows
}
```

**Incorrect: string concatenation with Statement**

```java
public ResultSet getUser(String input) throws SQLException {
    Statement stmt = connection.createStatement();
    String sql = "SELECT * FROM users WHERE name = '" + input + "'";
    return stmt.executeQuery(sql);
}
```

**Incorrect: String.format**

```java
public ResultSet getUser(String input) throws SQLException {
    Statement stmt = connection.createStatement();
    return stmt.executeQuery(String.format("SELECT * FROM users WHERE name = '%s'", input));
}
```

**Correct: PreparedStatement with parameters**

```java
public ResultSet getUser(String input) throws SQLException {
    PreparedStatement pstmt = connection.prepareStatement(
        "SELECT * FROM users WHERE name = ?");
    pstmt.setString(1, input);
    return pstmt.executeQuery();
}
```

**Incorrect: string concatenation**

```go
func getUser(db *sql.DB, userInput string) {
    query := "SELECT * FROM users WHERE name = '" + userInput + "'"
    db.Query(query)
}
```

**Incorrect: fmt.Sprintf**

```go
func getUser(db *sql.DB, email string) {
    query := fmt.Sprintf("SELECT * FROM users WHERE email = '%s'", email)
    db.Query(query)
}
```

**Correct: parameterized query**

```go
func getUser(db *sql.DB, userInput string) {
    db.Query("SELECT * FROM users WHERE name = $1", userInput)
}
```

**Incorrect: string concatenation**

```ruby
def get_user(user_input)
  conn = PG.connect(dbname: 'test')
  query = "SELECT * FROM users WHERE name = '" + user_input + "'"
  conn.exec(query)
end
```

**Incorrect: string interpolation**

```ruby
def get_user(user_input)
  conn = PG.connect(dbname: 'test')
  conn.exec("SELECT * FROM users WHERE name = '#{user_input}'")
end
```

**Correct: parameterized query**

```ruby
def get_user(user_input)
  conn = PG.connect(dbname: 'test')
  conn.exec_params('SELECT * FROM users WHERE name = $1', [user_input])
end
```

**Incorrect: String.Format**

```csharp
public void GetUser(string userInput)
{
    SqlCommand command = connection.CreateCommand();
    command.CommandText = String.Format(
        "SELECT * FROM users WHERE name = '{0}'", userInput);
}
```

**Incorrect: string concatenation**

```csharp
public void GetUser(string userInput)
{
    SqlCommand command = new SqlCommand(
        "SELECT * FROM users WHERE name = '" + userInput + "'");
}
```

**Correct: SqlParameter**

```csharp
public void GetUser(string userInput)
{
    string sql = "SELECT * FROM users WHERE name = @Name";
    SqlCommand command = new SqlCommand(sql);
    command.Parameters.Add("@Name", SqlDbType.NVarChar);
    command.Parameters["@Name"].Value = userInput;
}
```

**References:**

---

## 2. Command Injection

**Impact: CRITICAL**

OS command injection allows attackers to execute arbitrary system commands, leading to full system compromise. CWE-78.

### 2.1 Prevent Command Injection

**Impact: CRITICAL (Remote code execution allowing attackers to run arbitrary commands on the host system)**

Command injection occurs when untrusted input is passed to system shell commands. Attackers can execute arbitrary commands on the host system, potentially downloading malware, stealing data, or taking complete control of the server.

**Incorrect: vulnerable to command injection via subprocess**

```python
import subprocess
import flask

app = flask.Flask(__name__)

@app.route("/ping")
def ping():
    ip = flask.request.args.get("ip")
    subprocess.run("ping " + ip, shell=True)
```

**Correct: use array form without shell=True**

```python
import subprocess
import flask

app = flask.Flask(__name__)

@app.route("/ping")
def ping():
    ip = flask.request.args.get("ip")
    subprocess.run(["ping", ip])
```

**Incorrect: vulnerable child_process with user input**

```javascript
const { exec } = require('child_process');

function runCommand(userInput) {
    exec(`cat ${userInput}`, (error, stdout, stderr) => {
        console.log(stdout);
    });
}
```

**Correct: use spawn with array arguments**

```javascript
const { spawn } = require('child_process');

function runCommand(userInput) {
    const proc = spawn('cat', [userInput]);
    proc.stdout.on('data', (data) => {
        console.log(data.toString());
    });
}
```

**Incorrect: ProcessBuilder with user input via shell**

```java
public class CommandRunner {

    public void runCommand(String userInput) throws IOException {
        String[] cmd = {"/bin/bash", "-c", userInput};
        ProcessBuilder builder = new ProcessBuilder(cmd);
        Process proc = builder.start();
    }
}
```

**Correct: use ProcessBuilder with array arguments, no shell**

```java
public class CommandRunner {

    public void runCommand(String filename) throws IOException {
        ProcessBuilder builder = new ProcessBuilder("cat", filename);
        Process proc = builder.start();
    }
}
```

**Incorrect: dangerous command with user input via stdin**

```go
import (
    "fmt"
    "os/exec"
)

func runCommand(userInput string) {
    cmd := exec.Command("bash")
    cmdWriter, _ := cmd.StdinPipe()
    cmd.Start()

    cmdString := fmt.Sprintf("echo %s", userInput)
    cmdWriter.Write([]byte(cmdString + "\n"))

    cmd.Wait()
}
```

**Correct: use exec.Command with explicit arguments**

```go
import (
    "os/exec"
)

func runCommand(filename string) {
    cmd := exec.Command("cat", filename)
    output, _ := cmd.Output()
    println(string(output))
}
```

**Incorrect: Shell methods with tainted input**

```ruby
require 'shell'

def read_file(params)
    Shell.cat(params[:filename])
end
```

**Correct: use hardcoded or validated paths**

```ruby
require 'shell'

def read_log
    Shell.cat("/var/log/www/access.log")
end
```

**References:**

---

## 3. Cross-Site Scripting

**Impact: CRITICAL**

XSS allows attackers to inject malicious scripts into web pages, leading to session hijacking, defacement, or malware distribution. CWE-79.

### 3.1 Prevent Cross-Site Scripting (XSS)

**Impact: CRITICAL (Client-side code execution, session hijacking, credential theft)**

XSS occurs when untrusted data is included in web pages without proper validation or escaping. Attackers can execute scripts in victim's browser to steal cookies, session tokens, or other sensitive data.

**Incorrect: vulnerable to XSS**

```javascript
function renderUserContent(userInput) {
  document.body.innerHTML = '<div>' + userInput + '</div>';
}
```

**Correct: use textContent or sanitization**

```javascript
function renderUserContent(userInput) {
  const div = document.createElement('div');
  div.textContent = userInput;
  document.body.appendChild(div);
}
```

**References:**

**Incorrect: user input in response**

```python
from flask import make_response, request

def search():
    query = request.args.get("q")
    return make_response(f"Results for: {query}")
```

**Correct: escape output**

```python
from flask import make_response, request
from markupsafe import escape

def search():
    query = request.args.get("q")
    return make_response(f"Results for: {escape(query)}")
```

**References:**

**Incorrect: request data in HttpResponse**

```python
from django.http import HttpResponse

def greet(request):
    name = request.GET.get("name", "")
    return HttpResponse(f"Hello, {name}!")
```

**Correct: use template or escape**

```python
from django.http import HttpResponse
from django.utils.html import escape

def greet(request):
    name = request.GET.get("name", "")
    return HttpResponse(f"Hello, {escape(name)}!")
```

**References:**

**Incorrect: writing request parameters directly**

```java
public class UserServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        String name = req.getParameter("name");
        resp.getWriter().write("<h1>Hello " + name + "</h1>");
    }
}
```

**Correct: encode output**

```java
import org.owasp.encoder.Encode;

public class UserServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        String name = req.getParameter("name");
        resp.getWriter().write("<h1>Hello " + Encode.forHtml(name) + "</h1>");
    }
}
```

**References:**

**Incorrect: writing user input to ResponseWriter**

```go
func greetHandler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    template := "<html><body><h1>Hello %s</h1></body></html>"
    w.Write([]byte(fmt.Sprintf(template, name)))
}
```

**Correct: use html/template**

```go
func greetHandler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    tmpl := template.Must(template.New("greet").Parse(
        "<html><body><h1>Hello {{.}}</h1></body></html>"))
    tmpl.Execute(w, name)
}
```

**References:**

**Incorrect: echoing user input**

```php
<?php
function greet() {
    $name = $_REQUEST['name'];
    echo "Hello: " . $name;
}
```

**Correct: use htmlspecialchars**

```php
<?php
function greet() {
    $name = $_REQUEST['name'];
    echo "Hello: " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
}
```

**References:**

---

## 4. XML External Entity

**Impact: CRITICAL**

XXE attacks exploit XML parsers to access local files, perform SSRF, or cause denial of service. CWE-611.

### 4.1 Prevent XML External Entity (XXE) Injection

**Impact: CRITICAL (File disclosure, SSRF, denial of service)**

XXE occurs when XML input containing a reference to an external entity is processed by a weakly configured XML parser. Attackers can access local files, perform SSRF, or cause DoS.

**Incorrect: vulnerable to XXE**

```java
class BadDocumentBuilderFactory {
    public void parseXml() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.newDocumentBuilder();
    }
}
```

**Correct: XXE disabled**

```java
class GoodDocumentBuilderFactory {
    public void parseXml() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.newDocumentBuilder();
    }
}
```

**References:**

**Incorrect: vulnerable to XXE**

```python
def parse_xml():
    from xml.etree import ElementTree
    tree = ElementTree.parse('data.xml')
    root = tree.getroot()
```

**Correct: safe usage**

```python
def parse_xml():
    from defusedxml.etree import ElementTree
    tree = ElementTree.parse('data.xml')
    root = tree.getroot()
```

**References:**

**Incorrect: vulnerable to XXE**

```javascript
var libxmljs = require("libxmljs");

module.exports.parseXml = function(req, res) {
    libxmljs.parseXml(req.body, { noent: true, noblanks: true });
}
```

**Correct: XXE disabled**

```javascript
var libxmljs = require("libxmljs");

module.exports.parseXml = function(req, res) {
    libxmljs.parseXml(req.body, { noent: false, noblanks: true });
}
```

**References:**

**Incorrect: vulnerable to XXE**

```csharp
public void ParseXml(string input) {
    XmlReaderSettings rs = new XmlReaderSettings();
    rs.DtdProcessing = DtdProcessing.Parse;
    XmlReader myReader = XmlReader.Create(new StringReader(input), rs);

    while (myReader.Read()) {
        Console.WriteLine(myReader.Value);
    }
}
```

**Correct: XXE disabled**

```csharp
public void ParseXml(string input) {
    XmlReaderSettings rs = new XmlReaderSettings();
    rs.DtdProcessing = DtdProcessing.Prohibit;
    XmlReader myReader = XmlReader.Create(new StringReader(input), rs);

    while (myReader.Read()) {
        Console.WriteLine(myReader.Value);
    }
}
```

**References:**

**Incorrect: vulnerable to XXE**

```go
import (
    "fmt"
    "github.com/lestrrat-go/libxml2/parser"
)

func parseXml() {
    const s = `<!DOCTYPE d [<!ENTITY e SYSTEM "file:///etc/passwd">]><t>&e;</t>`
    p := parser.New(parser.XMLParseNoEnt)
    doc, err := p.ParseString(s)
    if err != nil {
        fmt.Println(err)
        return
    }
    fmt.Println(doc)
}
```

**Correct: XXE disabled**

```go
import (
    "fmt"
    "github.com/lestrrat-go/libxml2/parser"
)

func parseXml() {
    const s = `<!DOCTYPE d [<!ENTITY e SYSTEM "file:///etc/passwd">]><t>&e;</t>`
    p := parser.New()
    doc, err := p.ParseString(s)
    if err != nil {
        fmt.Println(err)
        return
    }
    fmt.Println(doc)
}
```

**References:**

---

## 5. Path Traversal

**Impact: CRITICAL**

Path traversal allows attackers to access files outside intended directories using sequences like "../". CWE-22.

### 5.1 Prevent Path Traversal

**Impact: CRITICAL (Arbitrary file access, information disclosure, file manipulation)**

Path traversal occurs when user input is used to construct file paths without proper validation, allowing attackers to access files outside intended directories using sequences like "../". This can lead to sensitive data exposure, arbitrary file reads/writes, and system compromise.

**Incorrect: vulnerable to path traversal**

```python
def unsafe(request):
    filename = request.POST.get('filename')
    f = open(filename, 'r')
    data = f.read()
    f.close()
    return HttpResponse(data)
```

**Correct: static path**

```python
def safe(request):
    filename = "/tmp/data.txt"
    f = open(filename)
    data = f.read()
    f.close()
    return HttpResponse(data)
```

**References:**

**Incorrect: vulnerable to path traversal**

```javascript
const fs = require('fs');

function readUserFile(fileName) {
  fs.readFile(fileName, (err, data) => {
    if (err) throw err;
    console.log(data);
  });
}
```

**Correct: safe with literal path**

```javascript
const fs = require('fs');

function readConfigFile() {
  fs.readFile('config/settings.json', (err, data) => {
    if (err) throw err;
    console.log(data);
  });
}
```

**References:**

**Incorrect: vulnerable to path traversal**

```javascript
const path = require('path');

function getFile(entry) {
  var extractPath = path.join(opts.path, entry.path);
  return extractFile(extractPath);
}
```

**Correct: path sanitized**

```javascript
const path = require('path');

function getFileSafe(req, res) {
  let somePath = req.body.path;
  somePath = somePath.replace(/^(\.\.(\/|\\|$))+/, '');
  return path.join(opts.path, somePath);
}
```

**References:**

**Incorrect: vulnerable to path traversal**

```java
public class FileServlet extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String image = request.getParameter("image");
        File file = new File("static/images/", image);
        if (!file.exists()) {
            response.sendError(404);
        }
    }
}
```

**Correct: sanitized with FilenameUtils**

```java
public class FileServlet extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String image = request.getParameter("image");
        File file = new File("static/images/", FilenameUtils.getName(image));
        if (!file.exists()) {
            response.sendError(404);
        }
    }
}
```

**References:**

**Incorrect: Clean does not prevent traversal**

```go
func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/file", func(w http.ResponseWriter, r *http.Request) {
        filename := filepath.Clean(r.URL.Path)
        filename = filepath.Join(root, strings.Trim(filename, "/"))
        contents, err := ioutil.ReadFile(filename)
        if err != nil {
            w.WriteHeader(http.StatusNotFound)
            return
        }
        w.Write(contents)
    })
}
```

**Correct: prefix with "/" before Clean**

```go
func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/file", func(w http.ResponseWriter, r *http.Request) {
        filename := path.Clean("/" + r.URL.Path)
        filename = filepath.Join(root, strings.Trim(filename, "/"))
        contents, err := ioutil.ReadFile(filename)
        if err != nil {
            w.WriteHeader(http.StatusNotFound)
            return
        }
        w.Write(contents)
    })
}
```

Best Practice: Use filepath.FromSlash(path.Clean("/"+strings.Trim(req.URL.Path, "/"))) or the SecureJoin function from github.com/cyphar/filepath-securejoin.

**References:**

**Incorrect: vulnerable to path traversal/RFI**

```php
<?php
$user_input = $_GET["page"];
include($user_input);
?>
```

**Correct: constant paths**

```php
<?php
include('templates/header.php');
require_once(CONFIG_DIR . '/settings.php');
?>
```

**References:**

**Incorrect: vulnerable to path traversal**

```php
<?php
$data = $_GET["file"];
unlink("/storage/" . $data);
?>
```

**Correct: constant path**

```php
<?php
unlink('/storage/cache/temp.txt');
?>
```

**References:**

---

## 6. Insecure Deserialization

**Impact: CRITICAL**

Deserializing untrusted data can lead to remote code execution, DoS, or authentication bypass. CWE-502.

### 6.1 Prevent Insecure Deserialization

**Impact: CRITICAL (Remote code execution allowing attackers to run arbitrary code on the server)**

Insecure deserialization occurs when untrusted data is used to abuse the logic of an application, inflict denial of service attacks, or execute arbitrary code. Objects can be serialized into strings and later loaded from strings, but deserialization of untrusted data can lead to remote code execution (RCE). Never deserialize data from untrusted sources. Use safer alternatives like JSON for data interchange.

**Incorrect: using pickle with user input**

```python
import pickle
from base64 import b64decode
from flask import Flask, request

app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    user_obj = request.cookies.get('uuid')
    return "Hey there! {}!".format(pickle.loads(b64decode(user_obj)))
```

**Correct: use JSON or load from trusted file**

```python
import pickle
import json

@app.route("/ok")
def ok():
    # Load from trusted local file
    data = pickle.load(open('./config/settings.dat', "rb"))

    # Or use JSON for untrusted data
    user_data = json.loads(request.data)
    return user_data
```

**References:**

**Incorrect: using insecure deserialization libraries**

```typescript
var node_serialize = require("node-serialize")

module.exports.handler = function (req, res) {
    var data = req.files.products.data.toString('utf8')
    node_serialize.unserialize(data)
}
```

**Correct: use JSON.parse for untrusted data**

```javascript
module.exports.handler = function (req, res) {
    var data = req.body.toString('utf8')
    var parsed = JSON.parse(data)
    return parsed
}
```

**References:**

**Incorrect: using ObjectInputStream to deserialize untrusted data**

```java
import java.io.InputStream;
import java.io.ObjectInputStream;

public class Deserializer {
    public Object deserializeObject(InputStream receivedData) throws Exception {
        ObjectInputStream in = new ObjectInputStream(receivedData);
        return in.readObject();
    }
}
```

**Correct: use JSON or implement input validation**

```java
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;

public class SafeDeserializer {
    public MyClass deserialize(InputStream data) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(data, MyClass.class);
    }
}
```

**References:**

**Incorrect: using Marshal.load or YAML.load with user input**

```ruby
def bad_deserialization
    data = params['data']
    obj = Marshal.load(data)

    yaml_data = params['yaml']
    config = YAML.load(yaml_data)
end
```

**Correct: use safe options or trusted data**

```ruby
def ok_deserialization
    # Use YAML.safe_load for untrusted data
    config = YAML.safe_load(params['yaml'])

    # Load from trusted file
    obj = YAML.load(File.read("config.yml"))

    # Use JSON for untrusted data
    data = JSON.parse(params['data'])
end
```

**References:**

**Incorrect: using BinaryFormatter which is inherently insecure**

```csharp
using System.Runtime.Serialization.Formatters.Binary;

public class InsecureDeserialization {
    public void Deserialize(string data) {
        BinaryFormatter formatter = new BinaryFormatter();
        MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes(data));
        object obj = formatter.Deserialize(stream);
    }
}
```

**Correct: use System.Text.Json or Newtonsoft with safe settings**

```csharp
using System.Text.Json;

public class SafeDeserialization {
    public MyClass Deserialize(string json) {
        return JsonSerializer.Deserialize<MyClass>(json);
    }
}
```

**References:**

**Incorrect: unserializing user-controlled data**

```php
<?php
$data = $_GET["data"];
$object = unserialize($data);
```

**Correct: use JSON or hardcoded data**

```php
<?php
// Use json_decode for untrusted data
$object = json_decode($_GET["data"], true);

// Or use unserialize only with hardcoded strings
$object = unserialize('O:1:"a":1:{s:5:"value";s:3:"100";}');
```

**References:**

**References:**

---

## 7. Code Injection

**Impact: CRITICAL**

Code injection (eval, template injection) allows attackers to execute arbitrary code in the application context. CWE-94.

### 7.1 Prevent Code Injection

**Impact: CRITICAL (Remote code execution via eval/exec)**

Code injection vulnerabilities occur when an attacker can insert and execute arbitrary code within your application. This includes direct code evaluation (eval, exec), reflection-based attacks, and dynamic method invocation. These vulnerabilities can lead to complete system compromise, data theft, and remote code execution.

**Incorrect: Python - eval with user input**

```python
def unsafe(request):
    code = request.POST.get('code')
    eval(code)
```

**Correct: Python - static eval with hardcoded strings**

```python
eval("x = 1; x = x + 2")

blah = "import requests; r = requests.get('https://example.com')"
eval(blah)
```

**Incorrect: JavaScript - eval with dynamic content**

```javascript
let dynamic = window.prompt()

eval(dynamic + 'possibly malicious code');

function evalSomething(something) {
    eval(something);
}
```

**Correct: JavaScript - static eval strings**

```javascript
eval('var x = "static strings are okay";');

const constVar = "function staticStrings() { return 'static strings are okay';}";
eval(constVar);
```

**Incorrect: Java - ScriptEngine injection**

```java
public class ScriptEngineSample {

    private static ScriptEngineManager sem = new ScriptEngineManager();
    private static ScriptEngine se = sem.getEngineByExtension("js");

    public static void scripting(String userInput) throws ScriptException {
        Object result = se.eval("test=1;" + userInput);
    }
}
```

**Correct: Java - static ScriptEngine evaluation**

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

**Incorrect: Ruby - dangerous eval**

```ruby
b = params['something']
eval(b)
eval(params['cmd'])
```

**Correct: Ruby - static eval**

```ruby
eval("def zen; 42; end")

class Thing
end
a = %q{def hello() "Hello there!" end}
Thing.module_eval(a)
```

**Incorrect: PHP - dangerous exec functions with user input**

```php
exec($user_input);
passthru($user_input);
$output = shell_exec($user_input);
$output = system($user_input, $retval);

$username = $_COOKIE['username'];
exec("wto -n \"$username\" -g", $ret);
```

**Correct: PHP - static commands with escapeshellarg**

```php
exec('whoami');

$fullpath = $_POST['fullpath'];
$filesize = trim(shell_exec('stat -c %s ' . escapeshellarg($fullpath)));
```

---

## 8. Hardcoded Secrets

**Impact: CRITICAL**

Hardcoded credentials, API keys, and tokens in source code lead to unauthorized access when code is exposed. CWE-798.

### 8.1 Avoid Hardcoded Secrets

**Impact: CRITICAL (Credential exposure and unauthorized access)**

Hardcoded credentials, API keys, tokens, and other secrets in source code pose a critical security risk. When secrets are committed to version control, they can be exposed to unauthorized parties through repository access, leaked in public repositories or through data breaches, difficult to rotate without code changes and redeployment, and discovered by automated secret scanning tools used by attackers. Always use environment variables, secret managers, or secure vaults to provide credentials at runtime.

**Incorrect: Python - hardcoded AWS credentials**

```python
import boto3

client("s3", aws_secret_access_key="jWnyxxxxxxxxxxxxxxxxX7ZQxxxxxxxxxxxxxxxx")

s3 = boto3.resource(
    "s3",
    aws_access_key_id="AKIAxxxxxxxxxxxxxxxx",
    aws_secret_access_key="jWnyxxxxxxxxxxxxxxxxX7ZQxxxxxxxxxxxxxxxx",
    region_name="us-east-1",
)
```

**Correct: Python - AWS credentials from environment**

```python
import boto3
import os

key = os.environ.get("ACCESS_KEY_ID")
secret = os.environ.get("SECRET_ACCESS_KEY")
s3 = boto3.resource(
    "s3",
    aws_access_key_id=key,
    aws_secret_access_key=secret,
    region_name="us-east-1",
)
```

**Incorrect: JavaScript - hardcoded JWT secret**

```javascript
const jsonwt = require('jsonwebtoken')

function signToken() {
  const payload = {foo: 'bar'}
  const token = jsonwt.sign(payload, 'my-secret-key')
  return token
}
```

**Correct: JavaScript - JWT secret from environment**

```javascript
const jsonwt = require('jsonwebtoken')

function signToken() {
  const payload = {foo: 'bar'}
  const secret = process.env.JWT_SECRET
  const token = jsonwt.sign(payload, secret)
  return token
}
```

**Incorrect: JavaScript - hardcoded express-jwt secret**

```javascript
var jwt = require('express-jwt');

app.get('/protected', jwt({ secret: 'shhhhhhared-secret' }), function(req, res) {
    if (!req.user.admin) return res.sendStatus(401);
    res.sendStatus(200);
});
```

**Correct: JavaScript - express-jwt secret from environment**

```javascript
var jwt = require('express-jwt');

app.get('/protected', jwt({ secret: process.env.JWT_SECRET }), function(req, res) {
    if (!req.user.admin) return res.sendStatus(401);
    res.sendStatus(200);
});
```

**Incorrect: Python Flask - hardcoded SECRET_KEY**

```python
import flask
app = flask.Flask(__name__)

app.config["SECRET_KEY"] = '_5#y2L"F4Q8z\n\xec]/'
```

**Correct: Python Flask - SECRET_KEY from environment**

```python
import os
import flask
app = flask.Flask(__name__)

app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
```

**Incorrect: Python - empty password string**

```python
from models import UserProfile

def set_user_password(user_profile: UserProfile) -> None:
    password = ""
    user_profile.set_password(password)
    user_profile.save()
```

**Correct: Python - password from secure source**

```python
from models import UserProfile

def set_user_password(user_profile: UserProfile, password: str) -> None:
    user_profile.set_password(password)
    user_profile.save()
```

**Incorrect: JavaScript - hardcoded Stripe token**

```javascript
const stripe = require('stripe');

const client = stripe('sk_test_20cbqx6v2hpftsbq203r36yqccazez');
```

**Correct: JavaScript - Stripe token from environment**

```javascript
const stripe = require('stripe');

const client = stripe(process.env.STRIPE_SECRET_KEY);
```

**Incorrect: Python - hardcoded GitHub token**

```python
import requests

headers = {"Authorization": "token ghp_emmtytndiqky5a98w0s98w36fakekey"}
response = requests.get("https://api.github.com/user", headers=headers)
```

**Correct: Python - GitHub token from environment**

```python
import os
import requests

headers = {"Authorization": f"token {os.environ['GITHUB_TOKEN']}"}
response = requests.get("https://api.github.com/user", headers=headers)
```

---

## 9. Memory Safety

**Impact: CRITICAL**

Memory safety issues (buffer overflow, use-after-free) can lead to code execution or crashes. CWE-119, CWE-416.

### 9.1 Ensure Memory Safety

**Impact: CRITICAL (Arbitrary code execution and data corruption)**

Memory safety vulnerabilities are among the most critical security issues in software development. They can lead to arbitrary code execution, data corruption, denial of service, and information disclosure. This guide covers common memory safety issues in C/C++ including double-free, use-after-free, and buffer overflow vulnerabilities.

Freeing memory twice can cause memory corruption, crashes, or allow attackers to execute arbitrary code.

**Incorrect:**

```c
int bad_code() {
    char *var = malloc(sizeof(char) * 10);
    free(var);
    free(var);  // Double free vulnerability
    return 0;
}
```

**Correct:**

```c
int safe_code() {
    char *var = malloc(sizeof(char) * 10);
    free(var);
    var = NULL;  // Set to NULL after free
    free(var);   // Safe: freeing NULL is a no-op
    return 0;
}
```

Accessing memory after it has been freed can lead to crashes, data corruption, or code execution.

**Incorrect:**

```c
typedef struct name {
    char *myname;
    void (*func)(char *str);
} NAME;

int bad_code() {
    NAME *var;
    var = (NAME *)malloc(sizeof(struct name));
    free(var);
    var->func("use after free");  // Accessing freed memory
    return 0;
}
```

**Correct:**

```c
typedef struct name {
    char *myname;
    void (*func)(char *str);
} NAME;

int safe_code() {
    NAME *var;
    var = (NAME *)malloc(sizeof(struct name));
    free(var);
    var = NULL;  // Prevents accidental reuse
    // Any access to var now causes immediate crash (easier to debug)
    return 0;
}
```

Writing beyond buffer boundaries can overwrite adjacent memory, leading to crashes or code execution.

**Incorrect:**

```c
void bad_code(char *user_input) {
    char buffer[64];
    strcpy(buffer, user_input);  // No bounds checking
}
```

**Correct:**

```c
void safe_code(char *user_input) {
    char buffer[64];
    strncpy(buffer, user_input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';  // Ensure null termination
}
```

Using user-controlled format strings can allow attackers to read or write arbitrary memory.

**Incorrect:**

```c
void bad_printf(char *user_input) {
    printf(user_input);  // User controls format string
}
```

**Correct:**

```c
void safe_printf(char *user_input) {
    printf("%s", user_input);  // Format string is fixed
}
```

---

## 10. Insecure Cryptography

**Impact: HIGH**

Weak hashing (MD5, SHA1), weak encryption (DES, RC4), or improper key management compromises data confidentiality. CWE-327.

### 10.1 Avoid Insecure Cryptography

**Impact: HIGH (Data decryption and signature forgery)**

Using weak or broken cryptographic algorithms puts sensitive data at risk. Attackers can exploit known vulnerabilities in deprecated algorithms to decrypt data, forge signatures, or predict "random" values.

**Key vulnerabilities:**

**Incorrect: MD5/SHA1 hashing**

```python
import hashlib

hash_val = hashlib.md5(data).hexdigest()
hash_val = hashlib.sha1(data).hexdigest()
```

**Correct: SHA256 hashing**

```python
import hashlib

hash_val = hashlib.sha256(data).hexdigest()
```

**Incorrect: DES cipher**

```python
from Crypto.Cipher import DES

key = b'-8B key-'
cipher = DES.new(key, DES.MODE_CTR, counter=ctr)
```

**Correct: AES cipher**

```python
from Crypto.Cipher import AES

key = b'Sixteen byte key'
cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
```

**Incorrect: MD5 hashing**

```javascript
const crypto = require("crypto");

function hashPassword(pwtext) {
    return crypto.createHash("md5").update(pwtext).digest("hex");
}
```

**Correct: SHA256 hashing**

```javascript
const crypto = require("crypto");

function hashPassword(pwtext) {
    return crypto.createHash("sha256").update(pwtext).digest("hex");
}
```

**Incorrect: MD5/SHA1 hashing**

```java
import java.security.MessageDigest;

MessageDigest md5 = MessageDigest.getInstance("MD5");
md5.update(password.getBytes());
byte[] hash = md5.digest();

MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
```

**Correct: SHA-512 hashing**

```java
import java.security.MessageDigest;

MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
sha512.update(password.getBytes());
byte[] hash = sha512.digest();
```

**Incorrect: DES cipher**

```java
Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
c.init(Cipher.ENCRYPT_MODE, k, iv);
```

**Correct: AES with GCM**

```java
Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
c.init(Cipher.ENCRYPT_MODE, k, iv);
```

**Incorrect: MD5 hashing**

```go
import (
    "crypto/md5"
    "fmt"
)

func hashData(data []byte) {
    h := md5.New()
    h.Write(data)
    fmt.Printf("%x", h.Sum(nil))
}
```

**Correct: SHA256 hashing**

```go
import (
    "crypto/sha256"
    "fmt"
)

func hashData(data []byte) {
    h := sha256.New()
    h.Write(data)
    fmt.Printf("%x", h.Sum(nil))
}
```

**Incorrect: DES cipher**

```go
import "crypto/des"

func encrypt() {
    key := []byte("example key 1234")
    block, _ := des.NewCipher(key[:8])
}
```

**Correct: AES cipher**

```go
import "crypto/aes"

func encrypt() {
    key := []byte("example key 12345678901234567890")
    block, _ := aes.NewCipher(key[:32])
}
```

| Language   | Weak Algorithm | Secure Alternative |
|------------|----------------|-------------------|
| Python     | hashlib.md5, hashlib.sha1 | hashlib.sha256, hashlib.sha512 |
| Python     | DES.new() | AES.new() with EAX/GCM mode |
| JavaScript | createHash("md5") | createHash("sha256") |
| Java       | getInstance("MD5"), getInstance("SHA-1") | getInstance("SHA-512") |
| Java       | getInstance("DES") | getInstance("AES/GCM/NoPadding") |
| Go         | crypto/md5, crypto/sha1 | crypto/sha256, crypto/sha512 |
| Go         | crypto/des | crypto/aes |

---

## 11. Insecure Transport

**Impact: HIGH**

Cleartext transmission, disabled certificate verification, or weak TLS exposes data in transit. CWE-319.

### 11.1 Use Secure Transport

**Impact: HIGH (Exposure of sensitive data through cleartext transmission or improper certificate validation)**

Insecure transport vulnerabilities occur when applications transmit sensitive data over unencrypted connections or when TLS/SSL certificate validation is disabled. This exposes data to man-in-the-middle (MITM) attacks where attackers can intercept, read, and modify communications. Key issues include:

**Incorrect: HTTP requests without TLS**

```javascript
const http = require('http');

http.get('http://nodejs.org/dist/index.json', (res) => {
    const { statusCode } = res;
});
```

**Correct: HTTPS requests with TLS**

```javascript
const https = require('https');

https.get('https://nodejs.org/dist/index.json', (res) => {
    const { statusCode } = res;
});
```

**Incorrect: disabled TLS verification**

```javascript
process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;

var req = https.request({
    host: '192.168.1.1',
    port: 443,
    path: '/',
    method: 'GET',
    rejectUnauthorized: false
});
```

**Correct: TLS verification enabled**

```javascript
var req = https.request({
    host: '192.168.1.1',
    port: 443,
    path: '/',
    method: 'GET',
    rejectUnauthorized: true
});
```

**Incorrect: HTTP requests without TLS**

```go
func bad() {
    resp, err := http.Get("http://example.com/")
}
```

**Correct: HTTPS requests**

```go
func ok() {
    resp, err := http.Get("https://example.com/")
}
```

**Incorrect: disabled TLS verification**

```go
import (
    "crypto/tls"
    "net/http"
)

func bad() {
    client := &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{
                InsecureSkipVerify: true,
            },
        },
    }
}
```

**Correct: TLS verification enabled**

```go
func ok() {
    client := &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{
                InsecureSkipVerify: false,
            },
        },
    }
}
```

**Incorrect: HTTP requests without TLS**

```python
import requests

requests.get("http://example.com")
```

**Correct: HTTPS requests**

```python
import requests

requests.get("https://example.com")
```

**Incorrect: disabled certificate verification**

```python
import requests

r = requests.get("https://example.com", verify=False)
```

**Correct: certificate verification enabled**

```python
import requests

r = requests.get("https://example.com")
```

**Incorrect: HTTP requests without TLS**

```java
HttpClient client = HttpClient.newHttpClient();
HttpRequest request = HttpRequest.newBuilder()
    .uri(URI.create("http://openjdk.java.net/"))
    .build();

client.sendAsync(request, BodyHandlers.ofString())
    .thenApply(HttpResponse::body)
    .thenAccept(System.out::println)
    .join();
```

**Correct: HTTPS requests**

```java
HttpClient client = HttpClient.newHttpClient();
HttpRequest request = HttpRequest.newBuilder()
    .uri(URI.create("https://openjdk.java.net/"))
    .build();

client.sendAsync(request, BodyHandlers.ofString())
    .thenApply(HttpResponse::body)
    .thenAccept(System.out::println)
    .join();
```

**Incorrect: disabled TLS verification via empty X509TrustManager**

```java
new X509TrustManager() {
    public X509Certificate[] getAcceptedIssuers() { return null; }
    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
    public void checkServerTrusted(X509Certificate[] certs, String authType) { }
}
```

**Correct: proper certificate validation**

```java
new X509TrustManager() {
    public X509Certificate[] getAcceptedIssuers() { return null; }
    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
    public void checkServerTrusted(X509Certificate[] certs, String authType) {
        try {
            checkValidity();
        } catch (Exception e) {
            throw new CertificateException("Certificate not valid or trusted.");
        }
    }
}
```

Reference: [https://nodejs.org/api/https.html](https://nodejs.org/api/https.html), [https://golang.org/pkg/crypto/tls/](https://golang.org/pkg/crypto/tls/), [https://docs.python.org/3/library/ssl.html](https://docs.python.org/3/library/ssl.html), [https://docs.oracle.com/en/java/javase/11/docs/api/java.net.http/java/net/http/HttpClient.html](https://docs.oracle.com/en/java/javase/11/docs/api/java.net.http/java/net/http/HttpClient.html)

---

## 12. Server-Side Request Forgery

**Impact: HIGH**

SSRF allows attackers to make requests from the server to internal systems or cloud metadata endpoints. CWE-918.

### 12.1 Prevent Server-Side Request Forgery

**Impact: HIGH (Attackers can make requests from the server to internal systems, cloud metadata endpoints, or external services)**

Server-Side Request Forgery (SSRF) occurs when an attacker can make a server-side application send HTTP requests to an arbitrary domain of the attacker's choosing. This can be used to:

**Incorrect: user input flows into URL host**

```python
from django.http import HttpResponse
import requests

def fetch_user_data(request):
    host = request.POST.get('host')
    user_id = request.POST.get('user_id')
    response = requests.get(f"https://{host}/api/users/{user_id}")
    return HttpResponse(response.content)
```

**Correct: fixed host, user data only in path**

```python
from django.http import HttpResponse
import requests

def fetch_user_data(request):
    user_id = request.POST.get('user_id')
    response = requests.get(f"https://api.example.com/users/{user_id}")
    return HttpResponse(response.content)
```

**Incorrect: user input in URL**

```javascript
const express = require('express');
const axios = require('axios');
const app = express();

app.get('/fetch', async (req, res) => {
    const url = req.query.url;
    const response = await axios.get(url);
    res.send(response.data);
});
```

**Correct: fixed host, user data only in path**

```javascript
const express = require('express');
const axios = require('axios');
const app = express();

app.get('/fetch', async (req, res) => {
    const resourceId = req.query.id;
    const response = await axios.get(`https://api.example.com/resources/${resourceId}`);
    res.send(response.data);
});
```

**Incorrect: user-controlled URL**

```java
import java.net.URL;
import java.net.URLConnection;
import org.springframework.web.bind.annotation.RequestParam;

@RestController
public class FetchController {
    @GetMapping("/fetch")
    public byte[] fetchImage(@RequestParam("url") String imageUrl) throws Exception {
        URL u = new URL(imageUrl);
        URLConnection conn = u.openConnection();
        return conn.getInputStream().readAllBytes();
    }
}
```

**Correct: fixed host, user data in path**

```java
import java.net.URL;
import org.springframework.web.bind.annotation.RequestParam;

@RestController
public class FetchController {
    @GetMapping("/fetch")
    public byte[] fetchImage(@RequestParam("id") String imageId) throws Exception {
        String url = String.format("https://images.example.com/%s", imageId);
        URL u = new URL(url);
        return u.openConnection().getInputStream().readAllBytes();
    }
}
```

**Incorrect: user input in URL host**

```go
package main

import (
    "fmt"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    host := r.URL.Query().Get("host")
    url := fmt.Sprintf("https://%s/api/data", host)
    resp, _ := http.Get(url)
    defer resp.Body.Close()
}
```

**Correct: fixed host, user data in path**

```go
package main

import (
    "fmt"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    resourceId := r.URL.Query().Get("id")
    url := fmt.Sprintf("https://api.example.com/data/%s", resourceId)
    resp, _ := http.Get(url)
    defer resp.Body.Close()
}
```

**Incorrect: user input in URL**

```php
<?php
function fetchData() {
    $url = $_GET['url'];
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
?>
```

**Correct: fixed host, user data in path**

```php
<?php
function fetchData() {
    $resourceId = $_GET['id'];
    $url = 'https://api.example.com/resources/' . $resourceId;
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
?>
```

**Incorrect: user input in HTTP request**

```ruby
require 'net/http'

def fetch_data
  url = params[:url]
  uri = URI(url)
  Net::HTTP.get_response(uri)
end
```

**Correct: fixed host, user data in path**

```ruby
require 'net/http'

def fetch_data
  resource_id = params[:id]
  uri = URI("https://api.example.com/resources/#{resource_id}")
  Net::HTTP.get_response(uri)
end
```

**References:**

---

## 13. JWT Authentication

**Impact: HIGH**

JWT vulnerabilities include the "none" algorithm attack, weak secrets, and missing signature verification. CWE-347.

### 13.1 Secure JWT Authentication

**Impact: HIGH (Authentication bypass and token forgery)**

JSON Web Tokens (JWT) are widely used for authentication and authorization. However, improper implementation can lead to serious security vulnerabilities including authentication bypass and token forgery. The most critical JWT vulnerability is decoding tokens without verifying their signatures, which allows attackers to forge tokens with arbitrary claims, impersonate any user, or escalate privileges.

Related CWEs: CWE-287 (Improper Authentication), CWE-345 (Insufficient Verification of Data Authenticity), CWE-347 (Improper Verification of Cryptographic Signature).

**Incorrect: JavaScript jsonwebtoken - decode without verify**

```javascript
const jwt = require('jsonwebtoken');

function getUserData(token) {
  const decoded = jwt.decode(token, true);
  if (decoded.isAdmin) {
    return getAdminData();
  }
}
```

**Correct: JavaScript jsonwebtoken - verify before decode**

```javascript
const jwt = require('jsonwebtoken');

function getUserData(token, secretKey) {
  jwt.verify(token, secretKey);
  const decoded = jwt.decode(token, true);
  if (decoded.isAdmin) {
    return getAdminData();
  }
}
```

**Incorrect: Python PyJWT - verify_signature disabled**

```python
import jwt

def get_user_claims(token, key):
    decoded = jwt.decode(token, key, options={"verify_signature": False})
    return decoded
```

**Correct: Python PyJWT - verify_signature enabled**

```python
import jwt

def get_user_claims(token, key):
    decoded = jwt.decode(token, key, algorithms=["HS256"])
    return decoded
```

**Incorrect: Java auth0 java-jwt - decode without verify**

```java
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;

public class TokenHandler {
    public DecodedJWT getUserClaims(String token) {
        DecodedJWT jwt = JWT.decode(token);
        return jwt;
    }
}
```

**Correct: Java auth0 java-jwt - verify before use**

```java
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

public class TokenHandler {
    public DecodedJWT getUserClaims(String token, String secret) {
        Algorithm algorithm = Algorithm.HMAC256(secret);
        JWTVerifier verifier = JWT.require(algorithm)
            .withIssuer("auth0")
            .build();
        DecodedJWT jwt = verifier.verify(token);
        return jwt;
    }
}
```

**References:**

---

## 14. Cross-Site Request Forgery

**Impact: HIGH**

CSRF attacks force authenticated users to perform unwanted actions without their knowledge. CWE-352.

### 14.1 Prevent Cross-Site Request Forgery

**Impact: HIGH (Attackers can force authenticated users to perform unwanted actions, potentially modifying data, transferring funds, or changing account settings)**

Cross-Site Request Forgery (CSRF) is an attack that forces authenticated users to execute unwanted actions on a web application. When a user is authenticated, their browser automatically includes session cookies with requests. Attackers can craft malicious pages that trigger requests to vulnerable applications, causing actions to be performed without the user's consent.

**Incorrect: using @csrf_exempt decorator**

```python
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def my_view(request):
    return HttpResponse('Hello world')
```

**Correct: remove csrf_exempt decorator**

```python
from django.http import HttpResponse

def my_view(request):
    return HttpResponse('Hello world')
```

**References:**

**Incorrect: Express app without csurf middleware**

```javascript
var express = require('express')
var bodyParser = require('body-parser')

var app = express()

app.post('/process', bodyParser.urlencoded({ extended: false }), function(req, res) {
    res.send('data is being processed')
})
```

**Correct: include csurf middleware**

```javascript
var csrf = require('csurf')
var express = require('express')

var app = express()
app.use(csrf({ cookie: true }))
```

**References:**

**Incorrect: explicitly disabling CSRF protection**

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .authorizeRequests()
                .antMatchers("/", "/home").permitAll()
                .anyRequest().authenticated();
    }
}
```

**Correct: CSRF protection enabled by default**

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/", "/home").permitAll()
                .anyRequest().authenticated();
    }
}
```

**References:**

**Incorrect: controller without protect_from_forgery**

```ruby
class DangerousController < ActionController::Base
  puts "do more stuff"
end
```

**Correct: controller with protect_from_forgery**

```ruby
class SafeController < ActionController::Base
  protect_from_forgery with: :exception

  puts "do more stuff"
end
```

**References:**

**General References:**

---

## 15. Prototype Pollution

**Impact: HIGH**

Prototype pollution in JavaScript can lead to property injection, denial of service, or code execution. CWE-1321.

### 15.1 Prevent Prototype Pollution

**Impact: HIGH (Attackers can modify object prototypes to inject malicious properties)**

Prototype pollution is a vulnerability that occurs when an attacker can modify the prototype of a base object, such as Object.prototype in JavaScript. This can create attributes that exist on every object or replace critical attributes with malicious ones.

Mitigations: Freeze prototypes with Object.freeze(Object.prototype), use Object.create(null), block __proto__ and constructor keys, or use Map instead of objects.

**Incorrect: JavaScript - dynamic property assignment from user input**

```javascript
app.get('/test/:id', (req, res) => {
    let id = req.params.id;
    let items = req.session.todos[id];
    if (!items) {
        items = req.session.todos[id] = {};
    }
    items[req.query.name] = req.query.text;
    res.end(200);
});
```

**Correct: JavaScript - validate against dangerous keys**

```javascript
app.post('/test/:id', (req, res) => {
    let id = req.params.id;
    if (id !== 'constructor' && id !== '__proto__') {
        let items = req.session.todos[id];
        if (!items) {
            items = req.session.todos[id] = {};
        }
        items[req.query.name] = req.query.text;
    }
    res.end(200);
});
```

**Incorrect: JavaScript - nested property assignment in loop**

```javascript
function setNestedValue(obj, props, value) {
  props = props.split('.');
  var lastProp = props.pop();
  while ((thisProp = props.shift())) {
    if (typeof obj[thisProp] == 'undefined') {
      obj[thisProp] = {};
    }
    obj = obj[thisProp];
  }
  obj[lastProp] = value;
}
```

**Correct: JavaScript - use numeric index or Map**

```javascript
function safeIteration(name) {
  let config = this.config;
  name = name.split('.');
  for (let i = 0; i < name.length; i++) {
    config = config[i];
  }
  return this;
}
```

**Incorrect: JavaScript - Object.assign with user input**

```javascript
function controller(req, res) {
    const defaultData = {foo: true}
    let data = Object.assign(defaultData, req.body)
    doSmthWith(data)
}
```

**Correct: JavaScript - use trusted data sources**

```javascript
function controller(req, res) {
    const defaultData = {foo: {bar: true}}
    let data = Object.assign(defaultData, {foo: getTrustedFoo()})
    doSmthWith(data)
}
```

**References:**

---

## 16. Unsafe Functions

**Impact: HIGH**

Inherently dangerous functions (gets, strcpy, eval) bypass safety checks and should be avoided. CWE-242.

### 16.1 Avoid Unsafe Functions

**Impact: HIGH (Buffer overflows and memory corruption)**

Certain functions in various programming languages are inherently dangerous because they do not perform boundary checks, can lead to buffer overflows, have been deprecated, or bypass type safety mechanisms. Using these functions can result in security vulnerabilities, memory corruption, and arbitrary code execution.

**Incorrect: C - strcat buffer overflow**

```c
int bad_strcpy(src, dst) {
    n = DST_BUFFER_SIZE;
    if ((dst != NULL) && (src != NULL) && (strlen(dst)+strlen(src)+1 <= n))
    {
        // ruleid: insecure-use-strcat-fn
        strcat(dst, src);

        // ruleid: insecure-use-strcat-fn
        strncat(dst, src, 100);
    }
}
```

**Correct: C - use strcat_s with bounds checking**

```c
// Use strcat_s which performs bounds checking
```

**Incorrect: C - strcpy buffer overflow**

```c
int bad_strcpy(src, dst) {
    n = DST_BUFFER_SIZE;
    if ((dst != NULL) && (src != NULL) && (strlen(dst)+strlen(src)+1 <= n))
    {
        // ruleid: insecure-use-string-copy-fn
        strcpy(dst, src);

        // ruleid: insecure-use-string-copy-fn
        strncpy(dst, src, 100);
    }
}
```

**Correct: C - use strcpy_s with bounds checking**

```c
// Use strcpy_s which performs bounds checking
```

**Incorrect: C - strtok modifies buffer**

```c
int bad_code() {
    char str[DST_BUFFER_SIZE];
    fgets(str, DST_BUFFER_SIZE, stdin);
    // ruleid:insecure-use-strtok-fn
    strtok(str, " ");
    printf("%s", str);
    return 0;
}
```

**Correct: C - use strtok_r instead**

```c
int main() {
    char str[DST_BUFFER_SIZE];
    char dest[DST_BUFFER_SIZE];
    fgets(str, DST_BUFFER_SIZE, stdin);
    // ok:insecure-use-strtok-fn
    strtok_r(str, " ", *dest);
    printf("%s", str);
    return 0;
}
```

**Incorrect: C - scanf buffer overflow**

```c
int bad_code() {
    char str[DST_BUFFER_SIZE];
    // ruleid:insecure-use-scanf-fn
    scanf("%s", str);
    printf("%s", str);
    return 0;
}
```

**Correct: C - use fgets instead**

```c
int main() {
    char str[DST_BUFFER_SIZE];
    // ok:insecure-use-scanf-fn
    fgets(str);
    printf("%s", str);
    return 0;
}
```

**Incorrect: C - gets buffer overflow**

```c
int bad_code() {
    char str[DST_BUFFER_SIZE];
    // ruleid:insecure-use-gets-fn
    gets(str);
    printf("%s", str);
    return 0;
}
```

**Correct: C - use fgets or gets_s instead**

```c
int main() {
    char str[DST_BUFFER_SIZE];
    // ok:insecure-use-gets-fn
    fgets(str);
    printf("%s", str);
    return 0;
}
```

**Incorrect: PHP - deprecated mcrypt functions**

```php
<?php

// ruleid: mcrypt-use
mcrypt_ecb(MCRYPT_BLOWFISH, $key, base64_decode($input), MCRYPT_DECRYPT);

// ruleid: mcrypt-use
mcrypt_create_iv($iv_size, MCRYPT_RAND);

// ruleid: mcrypt-use
mdecrypt_generic($td, $c_t);
```

**Correct: PHP - use Sodium or OpenSSL**

```php
<?php

// ok: mcrypt-use
sodium_crypto_secretbox("Hello World!", $nonce, $key);

// ok: mcrypt-use
openssl_encrypt($plaintext, $cipher, $key, $options=0, $iv, $tag);
```

**Incorrect: Python - tempfile.mktemp race condition**

```python
import tempfile as tf

# ruleid: tempfile-insecure
x = tempfile.mktemp()
# ruleid: tempfile-insecure
x = tempfile.mktemp(dir="/tmp")
```

**Correct: Python - use NamedTemporaryFile**

```python
import tempfile

# Use NamedTemporaryFile instead
with tempfile.NamedTemporaryFile() as tmp:
    tmp.write(b"data")
```

**Incorrect: Go - unsafe package bypasses type safety**

```go
package main

import (
	"fmt"
	"unsafe"

	foobarbaz "unsafe"
)

type Fake struct{}

func (Fake) Good() {}
func main() {
	unsafeM := Fake{}
	unsafeM.Good()
	intArray := [...]int{1, 2}
	fmt.Printf("\nintArray: %v\n", intArray)
	intPtr := &intArray[0]
	fmt.Printf("\nintPtr=%p, *intPtr=%d.\n", intPtr, *intPtr)
	// ruleid: use-of-unsafe-block
	addressHolder := uintptr(foobarbaz.Pointer(intPtr)) + unsafe.Sizeof(intArray[0])
	// ruleid: use-of-unsafe-block
	intPtr = (*int)(foobarbaz.Pointer(addressHolder))
	fmt.Printf("\nintPtr=%p, *intPtr=%d.\n\n", intPtr, *intPtr)
}
```

**Correct: Go - avoid unsafe package**

```go
// Avoid using the unsafe package. Use Go's type-safe alternatives for memory operations.
```

**Incorrect: Rust - unsafe block bypasses safety**

```rust
// ruleid: unsafe-usage
let pid = unsafe { libc::getpid() as u32 };
```

**Correct: Rust - use safe alternatives**

```rust
// ok: unsafe-usage
let pid = libc::getpid() as u32;
```

**Incorrect: OCaml - unsafe functions skip bounds checks**

```ocaml
let cb = Array.make 10 2 in
(* ruleid:ocamllint-unsafe *)
Printf.printf "%d\n" (Array.unsafe_get cb 12)
```

**Correct: OCaml - use bounds-checked functions**

```ocaml
let cb = Array.make 10 2 in
(* Use bounds-checked version *)
Printf.printf "%d\n" (Array.get cb 0)
```

---

## 17. Terraform AWS Security

**Impact: HIGH**

AWS infrastructure misconfigurations including public S3 buckets, unencrypted resources, and overly permissive IAM.

### 17.1 Secure AWS Terraform Configurations

**Impact: HIGH (Cloud misconfigurations and data exposure)**

Security best practices for AWS Terraform configurations to prevent common misconfigurations.

**Incorrect:**

```hcl
resource "aws_s3_bucket_object" "fail" {
  bucket  = aws_s3_bucket.bucket.bucket
  key     = "my-object"
  content = "data"
}
```

**Correct:**

```hcl
resource "aws_s3_bucket_object" "pass" {
  bucket     = aws_s3_bucket.bucket.bucket
  key        = "my-object"
  content    = "data"
  kms_key_id = aws_kms_key.example.arn
}
```

**Incorrect: wildcard admin**

```hcl
resource "aws_iam_policy" "fail" {
  policy = <<POLICY
{"Version":"2012-10-17","Statement":[{"Action":"*","Effect":"Allow","Resource":"*"}]}
POLICY
}
```

**Correct: least privilege**

```hcl
resource "aws_iam_policy" "pass" {
  policy = <<POLICY
{"Version":"2012-10-17","Statement":[{"Action":["s3:GetObject*"],"Effect":"Allow","Resource":"arn:aws:s3:::bucket/*"}]}
POLICY
}
```

**Incorrect: wildcard AssumeRole**

```hcl
resource "aws_iam_role" "fail" {
  assume_role_policy = <<POLICY
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}
POLICY
}
```

**Correct: restricted AssumeRole**

```hcl
resource "aws_iam_role" "pass" {
  assume_role_policy = <<POLICY
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}]}
POLICY
}
```

**Incorrect: EBS**

```hcl
resource "aws_ebs_volume" "fail" {
  availability_zone = "us-west-2a"
  encrypted         = false
}
```

**Correct: EBS**

```hcl
resource "aws_ebs_volume" "pass" {
  availability_zone = "us-west-2a"
  encrypted         = true
}
```

**Incorrect: RDS no backup**

```hcl
resource "aws_db_instance" "fail" { backup_retention_period = 0 }
```

**Correct: RDS with backup**

```hcl
resource "aws_db_instance" "pass" { backup_retention_period = 35 }
```

**Incorrect: DynamoDB**

```hcl
resource "aws_dynamodb_table" "fail" {
  name = "Table"; hash_key = "Id"
  attribute { name = "Id"; type = "S" }
}
```

**Correct: DynamoDB with CMK**

```hcl
resource "aws_dynamodb_table" "pass" {
  name = "Table"; hash_key = "Id"
  attribute { name = "Id"; type = "S" }
  server_side_encryption { enabled = true; kms_key_arn = "arn:aws:kms:..." }
}
```

**Incorrect: SQS/SNS**

```hcl
resource "aws_sqs_queue" "fail" { name = "queue" }
resource "aws_sns_topic" "fail" {}
```

**Correct: SQS/SNS encrypted**

```hcl
resource "aws_sqs_queue" "pass" { name = "queue"; sqs_managed_sse_enabled = true }
resource "aws_sns_topic" "pass" { kms_master_key_id = "alias/aws/sns" }
```

**Incorrect: public SSH**

```hcl
resource "aws_security_group_rule" "fail" {
  type = "ingress"; protocol = "tcp"; from_port = 22; to_port = 22
  cidr_blocks = ["0.0.0.0/0"]
}
```

**Correct: restricted CIDR**

```hcl
resource "aws_security_group_rule" "pass" {
  type = "ingress"; protocol = "tcp"; from_port = 22; to_port = 22
  cidr_blocks = ["10.0.0.0/8"]
}
```

**Incorrect: public IP**

```hcl
resource "aws_instance" "fail" {
  ami = "ami-12345"; instance_type = "t3.micro"
  associate_public_ip_address = true
}
```

**Correct: no public IP**

```hcl
resource "aws_instance" "pass" {
  ami = "ami-12345"; instance_type = "t3.micro"
  associate_public_ip_address = false
}
```

**Incorrect: KMS no rotation**

```hcl
resource "aws_kms_key" "fail" { enable_key_rotation = false }
```

**Correct: KMS with rotation**

```hcl
resource "aws_kms_key" "pass" { enable_key_rotation = true }
```

**Incorrect: CloudTrail**

```hcl
resource "aws_cloudtrail" "fail" { name = "trail"; s3_bucket_name = "bucket" }
```

**Correct: CloudTrail encrypted**

```hcl
resource "aws_cloudtrail" "pass" {
  name = "trail"; s3_bucket_name = "bucket"; kms_key_id = aws_kms_key.key.arn
}
```

**Incorrect: hardcoded**

```hcl
provider "aws" {
  region = "us-west-2"; access_key = "AKIAEXAMPLE"; secret_key = "secret"
}
```

**Correct: external credentials**

```hcl
provider "aws" {
  region = "us-west-2"; shared_credentials_file = "~/.aws/creds"; profile = "myprofile"
}
```

---

## 18. Terraform Azure Security

**Impact: HIGH**

Azure infrastructure misconfigurations including public endpoints, missing encryption, and insecure network settings.

### 18.1 Secure Azure Terraform Configurations

**Impact: HIGH (Cloud misconfigurations and data exposure)**

Security best practices for Azure infrastructure via Terraform. Misconfigurations can lead to data breaches and unauthorized access.

**Incorrect:**

```hcl
resource "azurerm_storage_account" "bad" {
  name                      = "storageaccountname"
  resource_group_name       = azurerm_resource_group.example.name
  location                  = azurerm_resource_group.example.location
  min_tls_version           = "TLS1_0"
  enable_https_traffic_only = false
}

resource "azurerm_storage_container" "bad" {
  name                  = "vhds"
  storage_account_name  = azurerm_storage_account.example.name
  container_access_type = "blob"
}
```

**Correct:**

```hcl
resource "azurerm_storage_account" "good" {
  name                      = "storageaccountname"
  resource_group_name       = azurerm_resource_group.example.name
  location                  = azurerm_resource_group.example.location
  min_tls_version           = "TLS1_2"
  enable_https_traffic_only = true
  network_rules {
    default_action             = "Deny"
    ip_rules                   = ["100.0.0.1"]
    virtual_network_subnet_ids = [azurerm_subnet.example.id]
    bypass                     = ["Metrics", "AzureServices"]
  }
}

resource "azurerm_storage_container" "good" {
  name                  = "vhds"
  storage_account_name  = azurerm_storage_account.example.name
  container_access_type = "private"
}
```

**Incorrect:**

```hcl
resource "azurerm_app_service" "bad" {
  name                     = "example-app-service"
  location                 = azurerm_resource_group.example.location
  resource_group_name      = azurerm_resource_group.example.name
  app_service_plan_id      = azurerm_app_service_plan.example.id
  https_only               = false
  remote_debugging_enabled = true
  site_config {
    min_tls_version = "1.0"
    cors { allowed_origins = ["*"] }
  }
  auth_settings { enabled = false }
}
```

**Correct:**

```hcl
resource "azurerm_app_service" "good" {
  name                     = "example-app-service"
  location                 = azurerm_resource_group.example.location
  resource_group_name      = azurerm_resource_group.example.name
  app_service_plan_id      = azurerm_app_service_plan.example.id
  https_only               = true
  remote_debugging_enabled = false
  site_config {
    min_tls_version = "1.2"
    cors { allowed_origins = ["https://example.com"] }
  }
  auth_settings { enabled = true }
}
```

**Incorrect:**

```hcl
resource "azurerm_key_vault" "bad" {
  name                     = "examplekeyvault"
  location                 = azurerm_resource_group.example.location
  purge_protection_enabled = false
  network_acls { bypass = "AzureServices"; default_action = "Allow" }
}

resource "azurerm_key_vault_key" "bad" {
  name         = "mykey"
  key_vault_id = azurerm_key_vault.example.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey"]
}
```

**Correct:**

```hcl
resource "azurerm_key_vault" "good" {
  name                       = "examplekeyvault"
  location                   = azurerm_resource_group.example.location
  soft_delete_retention_days = 7
  purge_protection_enabled   = true
  network_acls { bypass = "AzureServices"; default_action = "Deny" }
}

resource "azurerm_key_vault_key" "good" {
  name            = "mykey"
  key_vault_id    = azurerm_key_vault.example.id
  key_type        = "RSA"
  key_size        = 2048
  expiration_date = "2025-12-31T00:00:00Z"
  key_opts        = ["decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey"]
}
```

**Incorrect:**

```hcl
resource "azurerm_mssql_server" "bad" {
  name                          = "mssqlserver"
  resource_group_name           = azurerm_resource_group.example.name
  location                      = azurerm_resource_group.example.location
  version                       = "12.0"
  minimum_tls_version           = "1.0"
  public_network_access_enabled = true
}

resource "azurerm_mysql_firewall_rule" "bad" {
  name             = "office"
  server_name      = azurerm_mysql_server.example.name
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}
```

**Correct:**

```hcl
resource "azurerm_mssql_server" "good" {
  name                          = "mssqlserver"
  resource_group_name           = azurerm_resource_group.example.name
  location                      = azurerm_resource_group.example.location
  version                       = "12.0"
  minimum_tls_version           = "1.2"
  public_network_access_enabled = false
  azuread_administrator {
    login_username = "AzureAD Admin"
    object_id      = "00000000-0000-0000-0000-000000000000"
  }
}

resource "azurerm_mysql_firewall_rule" "good" {
  name             = "office"
  server_name      = azurerm_mysql_server.example.name
  start_ip_address = "40.112.8.12"
  end_ip_address   = "40.112.8.17"
}
```

**Incorrect:**

```hcl
resource "azurerm_kubernetes_cluster" "bad" {
  name                            = "example-aks1"
  location                        = azurerm_resource_group.example.location
  resource_group_name             = azurerm_resource_group.example.name
  dns_prefix                      = "exampleaks1"
  private_cluster_enabled         = false
  api_server_authorized_ip_ranges = []
  default_node_pool { name = "default"; node_count = 1; vm_size = "Standard_D2_v2" }
  identity { type = "SystemAssigned" }
}
```

**Correct:**

```hcl
resource "azurerm_kubernetes_cluster" "good" {
  name                            = "example-aks1"
  location                        = azurerm_resource_group.example.location
  resource_group_name             = azurerm_resource_group.example.name
  dns_prefix                      = "exampleaks1"
  private_cluster_enabled         = true
  disk_encryption_set_id          = azurerm_disk_encryption_set.example.id
  api_server_authorized_ip_ranges = ["192.168.0.0/16"]
  default_node_pool { name = "default"; node_count = 1; vm_size = "Standard_D2_v2" }
  identity { type = "SystemAssigned" }
}
```

**Incorrect:**

```hcl
resource "azurerm_linux_virtual_machine_scale_set" "bad" {
  name                            = "example-vmss"
  resource_group_name             = azurerm_resource_group.example.name
  location                        = azurerm_resource_group.example.location
  sku                             = "Standard_F2"
  admin_username                  = "adminuser"
  admin_password                  = "P@55w0rd1234!"
  encryption_at_host_enabled      = false
  disable_password_authentication = false
}
```

**Correct:**

```hcl
resource "azurerm_linux_virtual_machine_scale_set" "good" {
  name                            = "example-vmss"
  resource_group_name             = azurerm_resource_group.example.name
  location                        = azurerm_resource_group.example.location
  sku                             = "Standard_F2"
  admin_username                  = "adminuser"
  encryption_at_host_enabled      = true
  disable_password_authentication = true
  admin_ssh_key { username = "adminuser"; public_key = tls_private_key.new.public_key_pem }
}
```

Always disable public network access and use virtual networks where possible.

**Incorrect:**

```hcl
resource "azurerm_cosmosdb_account" "bad" {
  name                          = "tfex-cosmos-db"
  location                      = azurerm_resource_group.example.location
  resource_group_name           = azurerm_resource_group.example.name
  offer_type                    = "Standard"
  kind                          = "GlobalDocumentDB"
  public_network_access_enabled = true
}

resource "azurerm_container_group" "bad" {
  name                = "example-continst"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  ip_address_type     = "public"
  os_type             = "Linux"
  container { name = "hello-world"; image = "microsoft/aci-helloworld:latest"; cpu = "0.5"; memory = "1.5" }
}
```

**Correct:**

```hcl
resource "azurerm_cosmosdb_account" "good" {
  name                          = "tfex-cosmos-db"
  location                      = azurerm_resource_group.example.location
  resource_group_name           = azurerm_resource_group.example.name
  offer_type                    = "Standard"
  kind                          = "GlobalDocumentDB"
  public_network_access_enabled = false
  key_vault_key_id              = azurerm_key_vault_key.example.versionless_id
}

resource "azurerm_container_group" "good" {
  name                = "example-continst"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  ip_address_type     = "private"
  os_type             = "Linux"
  network_profile_id  = azurerm_network_profile.example.id
  container { name = "hello-world"; image = "microsoft/aci-helloworld:latest"; cpu = "0.5"; memory = "1.5" }
}
```

**Incorrect:**

```hcl
resource "azurerm_role_definition" "bad" {
  name  = "my-custom-role"
  scope = data.azurerm_subscription.primary.id
  permissions { actions = ["*"]; not_actions = [] }
  assignable_scopes = [data.azurerm_subscription.primary.id]
}
```

**Correct:**

```hcl
resource "azurerm_role_definition" "good" {
  name  = "my-custom-role"
  scope = data.azurerm_subscription.primary.id
  permissions {
    actions = [
      "Microsoft.Authorization/*/read",
      "Microsoft.Insights/alertRules/*",
      "Microsoft.Resources/deployments/write",
      "Microsoft.Support/*"
    ]
    not_actions = []
  }
  assignable_scopes = [data.azurerm_subscription.primary.id]
}
```

---

## 19. Terraform GCP Security

**Impact: HIGH**

GCP infrastructure misconfigurations including public resources, disabled logging, and insecure IAM bindings.

### 19.1 Secure GCP Terraform Configurations

**Impact: HIGH (Cloud misconfigurations and data exposure)**

Impact: HIGH

Secure configuration patterns for Google Cloud Platform (GCP) resources using Terraform.

**Incorrect:**

```hcl
resource "google_storage_bucket" "insecure" {
  name     = "example"
  location = "EU"
  uniform_bucket_level_access = false
}
resource "google_storage_bucket_iam_member" "public" {
  bucket = google_storage_bucket.default.name
  role   = "roles/storage.admin"
  member = "allUsers"
}
```

**Correct:**

```hcl
resource "google_storage_bucket" "secure" {
  name     = "example"
  location = "EU"
  uniform_bucket_level_access = true
  versioning { enabled = true }
  logging { log_bucket = "my-logging-bucket" }
}
resource "google_storage_bucket_iam_member" "restricted" {
  bucket = google_storage_bucket.default.name
  role   = "roles/storage.admin"
  member = "user:jane@example.com"
}
```

**Incorrect:**

```hcl
resource "google_compute_instance" "insecure" {
  name = "test"; machine_type = "n1-standard-1"; zone = "us-central1-a"
  can_ip_forward = true; boot_disk {}
  metadata = { serial-port-enable = true, enable-oslogin = false }
  network_interface { network = "default"; access_config {} }
}
resource "google_compute_firewall" "open" {
  name = "allow-all"; network = "google_compute_network.vpc.name"
  allow { protocol = "tcp"; ports = [22, 3389] }
  source_ranges = ["0.0.0.0/0"]
}
```

**Correct:**

```hcl
resource "google_compute_instance" "secure" {
  name = "test"; machine_type = "n1-standard-1"; zone = "us-central1-a"
  can_ip_forward = false
  boot_disk { kms_key_self_link = google_kms_crypto_key.key.id }
  metadata = { enable-oslogin = true }
  network_interface { network = "default" }
  shielded_instance_config { enable_vtpm = true; enable_integrity_monitoring = true }
}
resource "google_compute_firewall" "restricted" {
  name = "allow-ssh"; network = "google_compute_network.vpc.name"
  allow { protocol = "tcp"; ports = ["22"] }
  source_ranges = ["172.1.2.3/32"]; target_tags = ["ssh"]
}
```

**Incorrect:**

```hcl
resource "google_container_cluster" "insecure" {
  name = "my-cluster"; location = "us-central1-a"; initial_node_count = 3
  enable_legacy_abac = true; logging_service = "none"
  master_auth { username = "admin"; password = "password123" }
}
```

**Correct:**

```hcl
resource "google_container_cluster" "secure" {
  name = "my-cluster"; location = "us-central1-a"; initial_node_count = 3
  enable_legacy_abac = false; enable_shielded_nodes = true; enable_binary_authorization = true
  private_cluster_config { enable_private_nodes = true; master_ipv4_cidr_block = "10.0.0.0/28" }
  master_authorized_networks_config { cidr_blocks { cidr_block = "10.0.0.0/8" } }
  master_auth { client_certificate_config { issue_client_certificate = false } }
  network_policy { enabled = true }
}
resource "google_container_node_pool" "secure" {
  name = "my-pool"; cluster = "my-cluster"
  management { auto_repair = true; auto_upgrade = true }
}
```

**Incorrect:**

```hcl
resource "google_sql_database_instance" "insecure" {
  database_version = "MYSQL_8_0"; name = "instance"
  settings {
    tier = "db-f1-micro"
    ip_configuration { ipv4_enabled = true; authorized_networks { value = "0.0.0.0/0" } }
  }
}
```

**Correct:**

```hcl
resource "google_sql_database_instance" "secure" {
  database_version = "MYSQL_8_0"; name = "instance"
  settings {
    tier = "db-f1-micro"
    ip_configuration { ipv4_enabled = false; require_ssl = true; private_network = google_compute_network.net.id }
  }
}
```

**Incorrect:**

```hcl
resource "google_project_iam_member" "dangerous" {
  project = "your-project-id"; role = "roles/iam.serviceAccountTokenCreator"
  member  = "serviceAccount:test-compute@developer.gserviceaccount.com"
}
resource "google_compute_subnetwork" "no_logs" {
  name = "example"; ip_cidr_range = "10.0.0.0/16"; network = "google_compute_network.vpc.id"
}
resource "google_project" "default_network" {
  name = "My Project"; project_id = "your-project-id"; org_id = "1234567"
}
```

**Correct:**

```hcl
resource "google_project_iam_member" "safe" {
  project = "your-project-id"; role = "roles/viewer"; member = "user:jane@example.com"
}
resource "google_compute_subnetwork" "with_logs" {
  name = "example"; ip_cidr_range = "10.0.0.0/16"; network = "google_compute_network.vpc.self_link"
  log_config { aggregation_interval = "INTERVAL_10_MIN"; flow_sampling = 0.5 }
}
resource "google_project" "no_default_network" {
  name = "My Project"; project_id = "your-project-id"; org_id = "1234567"; auto_create_network = false
}
```

**Incorrect:**

```hcl
resource "google_kms_crypto_key" "unprotected" {
  name = "key"; key_ring = google_kms_key_ring.keyring.id; rotation_period = "15552000s"
}
resource "google_redis_instance" "insecure" { name = "my-instance"; memory_size_gb = 1; auth_enabled = false }
resource "google_bigquery_dataset" "unencrypted" { dataset_id = "example"; location = "EU" }
resource "google_pubsub_topic" "unencrypted" { name = "example-topic" }
```

**Correct:**

```hcl
resource "google_kms_crypto_key" "protected" {
  name = "key"; key_ring = google_kms_key_ring.keyring.id; rotation_period = "15552000s"
  lifecycle { prevent_destroy = true }
}
resource "google_redis_instance" "secure" {
  name = "my-instance"; memory_size_gb = 1; auth_enabled = true; transit_encryption_mode = "SERVER_AUTHENTICATION"
}
resource "google_bigquery_dataset" "encrypted" {
  dataset_id = "example"; location = "EU"
  default_encryption_configuration { kms_key_name = google_kms_crypto_key.example.name }
}
resource "google_pubsub_topic" "encrypted" { name = "topic"; kms_key_name = google_kms_crypto_key.key.id }
```

**Incorrect:**

```hcl
resource "google_cloud_run_service_iam_member" "public" {
  location = google_cloud_run_service.default.location; service = google_cloud_run_service.default.name
  role = "roles/run.invoker"; member = "allUsers"
}
resource "google_cloudbuild_worker_pool" "public" { name = "pool"; location = "eu-west1"; worker_config { no_external_ip = false } }
resource "google_dataproc_cluster" "public" { name = "cluster"; region = "us-central1"; cluster_config { gce_cluster_config { internal_ip_only = false } } }
resource "google_notebooks_instance" "public" {
  name = "instance"; location = "us-west1-a"; machine_type = "e2-medium"
  vm_image { project = "deeplearning-platform-release"; image_family = "tf-latest-cpu" }; no_public_ip = false
}
```

**Correct:**

```hcl
resource "google_cloud_run_service_iam_member" "restricted" {
  location = google_cloud_run_service.default.location; service = google_cloud_run_service.default.name
  role = "roles/run.invoker"; member = "user:jane@example.com"
}
resource "google_cloudbuild_worker_pool" "private" { name = "pool"; location = "eu-west1"; worker_config { no_external_ip = true } }
resource "google_dataproc_cluster" "private" { name = "cluster"; region = "us-central1"; cluster_config { gce_cluster_config { internal_ip_only = true } } }
resource "google_notebooks_instance" "private" {
  name = "instance"; location = "us-west1-a"; machine_type = "e2-medium"
  vm_image { project = "deeplearning-platform-release"; image_family = "tf-latest-cpu" }; no_public_ip = true
}
```

**Incorrect:**

```hcl
resource "google_compute_ssl_policy" "weak" { name = "weak"; min_tls_version = "TLS_1_0" }
resource "google_dns_managed_zone" "weak" {
  name = "zone"; dns_name = "example.com."
  dnssec_config { state = "on"; default_key_specs { algorithm = "rsasha1"; key_length = 2048; key_type = "keySigning" } }
}
```

**Correct:**

```hcl
resource "google_compute_ssl_policy" "strong" { name = "strong"; min_tls_version = "TLS_1_2"; profile = "MODERN" }
resource "google_dns_managed_zone" "strong" {
  name = "zone"; dns_name = "example.com."
  dnssec_config { state = "on"; default_key_specs { algorithm = "rsasha256"; key_length = 2048; key_type = "keySigning" } }
}
```

---

## 20. Kubernetes Security

**Impact: HIGH**

Kubernetes misconfigurations including privileged containers, host namespace access, and excessive RBAC permissions.

### 20.1 Secure Kubernetes Configurations

**Impact: HIGH (Container escapes and cluster compromise)**

This guide provides security best practices for Kubernetes YAML configurations. Following these patterns helps prevent common security misconfigurations that could expose your containers and cluster to attacks.

Key Security Principles:

Running containers in privileged mode grants full access to the host, bypassing security boundaries.

**Incorrect:**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: nginx
      image: nginx
      securityContext:
        privileged: true
```

**Correct:**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: redis
      image: redis
      securityContext:
        privileged: false
```

Containers should never run as root to limit the impact of container escapes.

**Incorrect:**

```yaml
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: false
  containers:
    - name: redis
      image: redis
```

**Correct:**

```yaml
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
  containers:
    - name: nginx
      image: nginx
```

Prevent processes from gaining more privileges than their parent process.

**Incorrect:**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: redis
      image: redis
      securityContext:
        allowPrivilegeEscalation: true
```

**Correct:**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: haproxy
      image: haproxy
      securityContext:
        allowPrivilegeEscalation: false
```

Sharing the host PID namespace allows containers to see and interact with all processes on the host.

**Incorrect:**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: view-pid
spec:
  hostPID: true
  containers:
    - name: nginx
      image: nginx
```

**Correct:**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  containers:
    - name: nginx
      image: nginx
```

Sharing the host network namespace exposes the host network stack to the container.

**Incorrect:**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: view-network
spec:
  hostNetwork: true
  containers:
    - name: nginx
      image: nginx
```

**Correct:**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  containers:
    - name: nginx
      image: nginx
```

Sharing the host IPC namespace allows containers to access shared memory on the host.

**Incorrect:**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: view-ipc
spec:
  hostIPC: true
  containers:
    - name: nginx
      image: nginx
```

**Correct:**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  containers:
    - name: nginx
      image: nginx
```

Mounting the Docker socket gives containers full control over the Docker daemon.

**Incorrect:**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    - image: gcr.io/google_containers/test-webserver
      name: test-container
      volumeMounts:
        - mountPath: /var/run/docker.sock
          name: docker-sock-volume
  volumes:
    - name: docker-sock-volume
      hostPath:
        type: File
        path: /var/run/docker.sock
```

**Correct:**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    - image: gcr.io/google_containers/test-webserver
      name: test-container
      volumeMounts:
        - mountPath: /data
          name: data-volume
  volumes:
    - name: data-volume
      emptyDir: {}
```

Never store secrets directly in configuration files. Use external secrets management.

**Incorrect:**

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: mysecret
type: Opaque
data:
  USERNAME: Y2FsZWJraW5uZXk=
  PASSWORD: UzNjcmV0UGEkJHcwcmQ=
```

**Correct: use Sealed Secrets or external secrets management**

```yaml
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: mysecret
spec:
  encryptedData:
    password: AgBy8hCi8...encrypted...
```

---

## 21. Docker Security

**Impact: HIGH**

Docker misconfigurations including running as root, privileged mode, and exposed Docker socket.

### 21.1 Secure Docker Configurations

**Impact: HIGH (Container escapes and privilege escalation)**

This guide provides security best practices for Dockerfiles and docker-compose configurations. Following these patterns helps prevent container escapes, privilege escalation, and other security vulnerabilities in containerized environments.

The last user in the container should not be 'root'. If an attacker gains control of the container, they will have root access.

**Incorrect:**

```dockerfile
FROM busybox
RUN apt-get update && apt-get install -y some-package
USER appuser
USER root
```

**Correct:**

```dockerfile
FROM busybox
USER root
RUN apt-get update && apt-get install -y some-package
USER appuser
```

Images should be tagged with an explicit version to produce deterministic container builds.

**Incorrect:**

```dockerfile
FROM debian
```

**Correct:**

```dockerfile
FROM debian:bookworm
```

The 'latest' tag may change the base container without warning, producing non-deterministic builds.

**Incorrect:**

```dockerfile
FROM debian:latest
```

**Correct:**

```dockerfile
FROM debian:bookworm
```

Running containers in privileged mode grants the container the equivalent of root capabilities on the host machine. This can lead to container escapes, privilege escalation, and other security concerns.

**Incorrect:**

```yaml
version: "3.9"
services:
  worker:
    image: my-worker-image:1.0
    privileged: true
```

**Correct:**

```yaml
version: "3.9"
services:
  worker:
    image: my-worker-image:1.0
    privileged: false
```

Exposing the host's Docker socket to containers via a volume is equivalent to giving unrestricted root access to your host. Never expose the Docker socket unless absolutely necessary.

**Incorrect:**

```yaml
version: "3.9"
services:
  worker:
    image: my-worker-image:1.0
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
```

**Correct:**

```yaml
version: "3.9"
services:
  worker:
    image: my-worker-image:1.0
    volumes:
      - /tmp/data:/tmp/data
```

If unverified user data can reach the run or create method, it can result in running arbitrary containers.

**Incorrect:**

```python
import docker
client = docker.from_env()

def run_container(user_input):
    client.containers.run(user_input, 'echo hello world')
```

**Correct:**

```python
import docker
client = docker.from_env()

def run_container():
    client.containers.run("alpine", 'echo hello world')
```

---

## 22. GitHub Actions Security

**Impact: HIGH**

GitHub Actions vulnerabilities including script injection, unsafe checkout of PR code, and unpinned actions.

### 22.1 Secure GitHub Actions

**Impact: HIGH (Prevents code injection, secrets theft, and supply chain attacks in CI/CD pipelines)**

GitHub Actions workflows can be vulnerable to several security issues including script injection, secrets exposure, and supply chain attacks. Attackers who exploit these vulnerabilities can steal repository secrets, inject malicious code, or compromise the entire CI/CD pipeline.

Using variable interpolation ${{...}} with github context data in a run: step could allow an attacker to inject their own code into the runner. This would allow them to steal secrets and code.

When using pull_request_target, the Action runs in the context of the target repository with access to all repository secrets. Checking out the incoming PR code while having access to secrets is dangerous because you may inadvertently execute arbitrary code from the incoming PR.

Similar to pull_request_target, when using workflow_run, the Action runs in the context of the target repository with access to all repository secrets. Checking out incoming PR code with this trigger is dangerous.

An action sourced from a third-party repository on GitHub is not pinned to a full length commit SHA. Pinning an action to a full length commit SHA is currently the only way to use an action as an immutable release.

**Incorrect: vulnerable to script injection via PR title**

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Check PR title
        run: |
          title="${{ github.event.pull_request.title }}"
          echo "$title"
```

**Correct: use environment variable**

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Check PR title
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: |
          echo "$PR_TITLE"
```

Fix: Use an intermediate environment variable with env: to store the data and use the environment variable in the run: script. Be sure to use double-quotes around the environment variable.

**Incorrect: checking out PR code with pull_request_target**

```yaml
on:
  pull_request_target:

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install && npm build
```

**Correct: no checkout of PR code**

```yaml
on:
  pull_request_target:

jobs:
  safe-job:
    runs-on: ubuntu-latest
    steps:
      - name: echo
        run: echo "Hello, world"
```

**Incorrect: checking out PR code with workflow_run**

```yaml
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
        with:
          ref: ${{ github.event.workflow_run.head.sha }}
      - run: npm install
```

**Correct: no checkout of PR code**

```yaml
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]

jobs:
  safe-job:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Safe operation"
```

**Incorrect: using tag reference**

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: fakerepo/comment-on-pr@v1
        with:
          message: "Thank you!"
```

**Correct: pinned to full commit SHA**

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: fakerepo/comment-on-pr@5fd3084fc36e372ff1fff382a39b10d03659f355
        with:
          message: "Thank you!"
```

Note: GitHub-owned actions (actions/*, github/*) and local actions (./.github/actions/*) don't require SHA pinning.

**References:**

Reference: [https://docs.github.com/en/actions/learn-github-actions/security-hardening-for-github-actions#understanding-the-risk-of-script-injections](https://docs.github.com/en/actions/learn-github-actions/security-hardening-for-github-actions#understanding-the-risk-of-script-injections), [https://securitylab.github.com/research/github-actions-preventing-pwn-requests/](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/), [https://www.legitsecurity.com/blog/github-privilege-escalation-vulnerability](https://www.legitsecurity.com/blog/github-privilege-escalation-vulnerability), [https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions)

---

## 23. Regular Expression DoS

**Impact: MEDIUM**

ReDoS attacks exploit inefficient regex patterns to cause CPU exhaustion and denial of service. CWE-1333.

### 23.1 Prevent Regular Expression DoS

**Impact: MEDIUM (Service disruption through CPU exhaustion via malicious regex patterns)**

Regular Expression Denial of Service (ReDoS) occurs when attackers exploit inefficient regular expression patterns to cause excessive CPU consumption. Certain regex patterns with nested quantifiers or overlapping alternatives can experience "catastrophic backtracking" when matched against malicious input, causing the regex engine to take exponential time to evaluate.

Common vulnerable patterns include:

**Incorrect: vulnerable ReDoS pattern**

```javascript
const re = new RegExp("([a-z]+)+$", "i");

var emailRegex = /^\w+([-_+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$/;
emailRegex.test(userInput);
```

**Correct: safe regex patterns**

```javascript
// Use atomic patterns without nested quantifiers
const safeRegex = /^[a-z]+$/i;

// Or use a library with ReDoS protection
import { RE2 } from 're2';
const re = new RE2("([a-z]+)+$");
```

**Incorrect: non-literal RegExp with user input**

```javascript
function searchHandler(userPattern) {
  const reg = new RegExp("\\w+" + userPattern);
  return reg.exec(data);
}
```

**Correct: hardcoded regex patterns**

```javascript
function searchHandler(userInput) {
  const reg = new RegExp("\\w+");
  return reg.exec(userInput);
}
```

**Incorrect: incomplete string sanitization**

```javascript
function escapeQuotes(s) {
  return s.replace("'", "''");  // Only replaces first occurrence
}
```

**Correct: use regex with global flag**

```javascript
function escapeQuotes(s) {
  return s.replace(/'/g, "''");  // Replaces all occurrences
}
```

**References:**

**Incorrect: inefficient regex pattern**

```python
import re

redos_pattern = r"^(a+)+$"
data = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaX"

pattern = re.compile(redos_pattern)
pattern.match(data)  # Catastrophic backtracking
```

**Correct: safe regex patterns**

```python
import re

safe_pattern = r"^a+$"
data = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaX"

pattern = re.compile(safe_pattern)
pattern.match(data)  # Fast failure, no backtracking
```

**Mitigation strategies:**

```python
# Use regex timeout (Python 3.11+)
import re
re.match(pattern, data, timeout=1.0)

# Or use google-re2 library for linear-time matching
import re2
re2.match(r"^(a+)+$", data)
```

**References:**

**References:**

---

## 24. Race Conditions

**Impact: MEDIUM**

TOCTOU race conditions and insecure temporary file creation can lead to privilege escalation. CWE-367.

### 24.1 Prevent Race Conditions

**Impact: MEDIUM (Time-of-check Time-of-use (TOCTOU) vulnerabilities, insecure temporary files, data corruption)**

Race conditions occur when the behavior of software depends on the timing or sequence of events that execute in an unpredictable order. Time-of-check Time-of-use (TOCTOU) vulnerabilities are a specific type of race condition where a resource's state is checked at one point in time but used at a later point, allowing an attacker to modify the resource between the check and use.

Common race condition patterns include:

Using Filename.temp_file might lead to race conditions since the file could be altered or replaced by a symlink before being opened.

**Incorrect: vulnerable to race condition**

```ocaml
(* ruleid:ocamllint-tempfile *)
let ofile = Filename.temp_file "test" "" in
Printf.printf "%s\n" ofile
```

**Correct: use safer alternatives**

```ocaml
(* Use open_temp_file which returns both the filename and an open channel *)
let (filename, oc) = Filename.open_temp_file "test" "" in
Printf.fprintf oc "data\n";
close_out oc
```

**References:**

**Incorrect: vulnerable to race condition**

```python
import tempfile as tf

# ruleid: tempfile-insecure
x = tempfile.mktemp()
# ruleid: tempfile-insecure
x = tempfile.mktemp(dir="/tmp")
```

**Correct: use secure alternatives**

```python
import tempfile

# Use NamedTemporaryFile which atomically creates and opens the file
with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
    f.write("data")
    filename = f.name

# Or use mkstemp which returns both file descriptor and name
fd, path = tempfile.mkstemp()
try:
    with os.fdopen(fd, 'w') as f:
        f.write("data")
finally:
    os.unlink(path)
```

**References:**

**Incorrect: hardcoded tmp path**

```python
def test1():
    # ruleid:hardcoded-tmp-path
    f = open("/tmp/blah.txt", 'w')
    f.write("hello world")
    f.close()

def test2():
    # ruleid:hardcoded-tmp-path
    f = open("/tmp/blah/blahblah/blah.txt", 'r')
    data = f.read()
    f.close()

def test4():
    # ruleid:hardcoded-tmp-path
    with open("/tmp/blah.txt", 'r') as fin:
        data = fin.read()
```

**Correct: use tempfile module or relative paths**

```python
def test3():
    # ok:hardcoded-tmp-path
    f = open("./tmp/blah.txt", 'w')
    f.write("hello world")
    f.close()

def test3a():
    # ok:hardcoded-tmp-path
    f = open("/var/log/something/else/tmp/blah.txt", 'w')
    f.write("hello world")
    f.close()

def test5():
    # ok:hardcoded-tmp-path
    with open("./tmp/blah.txt", 'w') as fout:
        fout.write("hello world")
```

**References:**

**Incorrect: hardcoded tmp path**

```go
package samples

import (
	"fmt"
	"io/ioutil"
)

func main() {
	// ruleid:bad-tmp-file-creation
	err := ioutil.WriteFile("/tmp/demo2", []byte("This is some data"), 0644)
	if err != nil {
		fmt.Println("Error while writing!")
	}
}
```

**Correct: use TempFile for atomic creation**

```go
import "os"

func secureTemp() error {
    // Atomically creates a file with a random suffix
    f, err := os.CreateTemp("", "prefix-*.txt")
    if err != nil {
        return err
    }
    defer f.Close()

    _, err = f.WriteString("secure data")
    return err
}
```

Best Practice: Use os.CreateTemp (Go 1.16+) or ioutil.TempFile which atomically creates a new file with a unique name.

**References:**

**References:**

---

## 25. Code Correctness

**Impact: MEDIUM**

Common coding mistakes including exception handling errors, null checks, type errors, and logic bugs.

### 25.1 Code Correctness

**Impact: MEDIUM (Runtime errors and unexpected behavior)**

Common coding mistakes that cause runtime errors, unexpected behavior, or logic issues.

Python only instantiates default arguments once. Mutating them affects all future calls.

**INCORRECT:**

```python
def append_func(default=[]):
    default.append(5)
```

**CORRECT:**

```python
def append_func(default=None):
    if default is None:
        default = []
    default.append(5)
```

**INCORRECT:**

```python
items = [1, 2, 3, 4]
for i in items:
    items.pop(0)
```

**CORRECT:**

```python
for i in list(items):  # Iterate over a copy
    items.pop(0)
```

Using break, continue, or return in finally suppresses exceptions.

**INCORRECT:**

```python
try:
    raise ValueError()
finally:
    break  # Suppresses the exception!
```

**INCORRECT:**

```python
raise "error"
```

**CORRECT:**

```python
raise Exception("error")
```

Missing commas cause implicit string concatenation.

**INCORRECT:**

```python
bad = ["a" "b" "c"]  # Results in ["abc"]
```

**CORRECT:**

```python
good = ["a", "b", "c"]
```

**INCORRECT:**

```javascript
return `value is {x}`  // Missing $
```

**CORRECT:**

```javascript
return `value is ${x}`
```

Loop variables are shared across iterations.

**INCORRECT:**

```go
for _, val := range values {
    funcs = append(funcs, func() {
        fmt.Println(&val)  // Same pointer for all!
    })
}
```

**CORRECT:**

```go
for _, val := range values {
    val := val  // Create new variable
    funcs = append(funcs, func() {
        fmt.Println(&val)
    })
}
```

**INCORRECT:**

```go
bigValue, _ := strconv.Atoi("2147483648")
value := int16(bigValue)  // Overflow!
```

CORRECT: Use strconv.ParseInt with correct bit size.

**INCORRECT:**

```java
if (a == "hello") return 1;
```

**CORRECT:**

```java
if ("hello".equals(a)) return 1;
```

**INCORRECT:**

```java
if (myBoolean = true) {  // Assignment, not comparison!
```

**CORRECT:**

```java
if (myBoolean) {
```

The ato*() functions cause undefined behavior on overflow.

**INCORRECT:**

```c
int i = atoi(buf);
```

**CORRECT:**

```c
long l = strtol(buf, NULL, 10);
```

Unquoted variables split on whitespace.

**INCORRECT:**

```bash
exec $foo
```

**CORRECT:**

```bash
exec "$foo"
```

**INCORRECT:**

```scala
if (list.indexOf(item) > 0)  // Misses first element!
```

**CORRECT:**

```scala
if (list.indexOf(item) >= 0)
```

Atoms are never garbage collected. Use String.to_existing_atom instead of String.to_atom.

Use = not == for value comparison, <> not != for inequality.

---

## 26. Best Practices

**Impact: LOW**

Code style, API usage patterns, deprecated patterns, and general coding recommendations.

### 26.1 Code Best Practices

**Impact: LOW (Code quality and maintainability issues)**

This document outlines coding best practices across multiple languages. Following these patterns helps improve code quality, maintainability, and prevents common mistakes.

**Incorrect: Python**

```python
def func1():
    fd = open('foo')
    x = 123
```

**Correct: Python - using context manager**

```python
def func2():
    with open('bar', encoding='utf-8') as fd:
        data = fd.read()
```

open() uses device locale encodings by default. Always specify encoding in text mode.

**Incorrect:**

```python
fd = open('foo', mode="w")
```

**Correct:**

```python
fd = open('foo', encoding='utf-8', mode="w")
```

Requests without a timeout will hang indefinitely if no response is received.

**Incorrect: Python**

```python
import requests
r = requests.get(url)
```

**Correct: Python**

```python
r = requests.get(url, timeout=30)
```

Debug statements like alert(), confirm(), prompt(), and debugger should not be in production code.

**Incorrect: JavaScript**

```javascript
var name = prompt('what is your name');
alert('your name is ' + name);
debugger;
```

Lazy loading inside functions complicates bundling and blocks requests synchronously in Node.js.

**Incorrect: JavaScript**

```javascript
function smth() {
  const mod = require('module-name')
  return mod();
}
```

**Correct: JavaScript**

```javascript
const mod = require('module-name')
function smth() {
  return mod();
}
```

File creation in shared tmp directories without proper APIs can lead to security vulnerabilities.

**Incorrect: Python**

```python
with open('/tmp/myfile.txt', 'w') as f:
    f.write(data)
```

**Correct: Python**

```python
import tempfile
with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
    f.write(data)
```

Always set HttpOnly and Secure flags on security-sensitive cookies.

**Incorrect: JavaScript/Express**

```javascript
res.cookie('session', value);
```

**Correct: JavaScript/Express**

```javascript
res.cookie('session', value, { httpOnly: true, secure: true });
```

Never redirect to user-provided URLs without validation to prevent open redirect vulnerabilities.

**Incorrect: JavaScript**

```javascript
res.redirect(req.query.returnUrl);
```

**Correct: JavaScript**

```javascript
const allowedHosts = ['example.com'];
const url = new URL(req.query.returnUrl, 'https://example.com');
if (allowedHosts.includes(url.hostname)) {
  res.redirect(url.href);
}
```

Use actively maintained alternatives instead of deprecated libraries.

**Incorrect: JavaScript - Moment.js is deprecated**

```javascript
import moment from 'moment';
```

**Correct: JavaScript - use dayjs**

```javascript
import dayjs from 'dayjs';
```

---

## 27. Performance

**Impact: LOW**

Performance anti-patterns including inefficient loops, unnecessary database queries, and memory waste.

### 27.1 Performance Best Practices

**Impact: LOW (Unnecessary overhead and inefficiency)**

This document covers performance optimizations to write efficient code. These rules identify patterns that cause unnecessary computational overhead, extra database queries, or memory inefficiency.

Use ITEM.user_id rather than ITEM.user.id to prevent running an extra query. Accessing .user.id causes Django to fetch the entire related User object just to get the ID, when the foreign key ID is already available on the model.

**INCORRECT - Extra query to fetch related object:**

```python
def get_user_id(item):
    return item.user.id
```

**CORRECT - Use the foreign key directly:**

```python
def get_user_id(item):
    return item.user_id
```

Using QUERY.count() instead of len(QUERY.all()) sends less data to the client since the count is performed server-side. The len(all()) approach fetches all records into memory just to count them.

**INCORRECT - Fetches all records into memory:**

```python
total = len(persons.all())
```

**CORRECT - Count performed server-side:**

```python
total = persons.count()
```

Rather than adding one element at a time, use batch loading to improve performance. Each individual db.session.add() in a loop can trigger separate database operations.

**INCORRECT - Adding one at a time in a loop:**

```python
for song in songs:
    db.session.add(song)
```

**CORRECT - Batch add all at once:**

```python
db.session.add_all(songs)
```

By declaring a styled component inside the render method, you dynamically create a new component on every render. This forces React to discard and re-calculate that part of the DOM subtree on each render, leading to performance bottlenecks.

**INCORRECT - Styled component declared inside function:**

```tsx
import styled from "styled-components";

function FunctionalComponent() {
  const StyledDiv = styled.div`
    color: blue;
  `
  return <StyledDiv />
}
```

**CORRECT - Styled component declared at module level:**

```tsx
import styled from "styled-components";

const StyledDiv = styled.div`
  color: blue;
`

function FunctionalComponent() {
  return <StyledDiv />
}
```

Check array length efficiently without traversing the entire collection.

**INCORRECT - Inefficient length check:**

```javascript
if (items.length === 0) { /* empty */ }
```

**CORRECT - Direct comparison when possible:**

```javascript
if (!items.length) { /* empty */ }
```

For operations that require iterating, prefer built-in methods that short-circuit:

**INCORRECT - Full iteration to find one item:**

```javascript
const found = items.filter(x => x.id === targetId)[0];
```

**CORRECT - Short-circuit on first match:**

```javascript
const found = items.find(x => x.id === targetId);
```

---

## 28. Maintainability

**Impact: LOW**

Code organization, deprecated API usage, naming conventions, and long-term code health.

### 28.1 Code Maintainability

**Impact: LOW (Technical debt and code confusion)**

Rules that identify code patterns leading to confusion, technical debt, or unexpected behavior. Focus areas: useless code, deprecated APIs, and code organization.

**Incorrect: Python - duplicate if condition**

```python
if a:
    print('1')
elif a:
    print('2')
```

**Correct: Python - distinct conditions**

```python
if a:
    print('1')
elif b:
    print('2')
```

**Incorrect: Python - identical if/else branches**

```python
if a:
    print('1')
else:
    print('1')
```

**Correct: Python - different branches or simplified**

```python
print('1')
```

**Incorrect: Python - unused inner function**

```python
def A():
    def B():
        print('never used')
    return None
```

**Correct: Python - inner function called or returned**

```python
def A():
    def B():
        print('used')
    return B()
```

**Incorrect: Python - function reference without call**

```python
if example.is_positive:
    do_something()
```

**Correct: Python - function called with parentheses**

```python
if example.is_positive():
    do_something()
```

**Incorrect: Django - duplicate URL paths**

```python
urlpatterns = [
    path('path/to/view', views.example_view),
    path('path/to/view', views.other_view),
]
```

**Correct: Django - unique URL paths**

```python
urlpatterns = [
    path('path/to/view1', views.example_view),
    path('path/to/view2', views.other_view),
]
```

**Incorrect: Flask - deprecated APIs**

```python
from flask import json_available
blueprint = request.module
```

**Correct: Flask - modern alternatives**

```python
from flask import Flask, request
app = Flask(__name__)
```

---

