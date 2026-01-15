---
title: Prevent Server-Side Request Forgery
impact: HIGH
impactDescription: Attackers can make requests from the server to internal systems, cloud metadata endpoints, or external services
tags: security, ssrf, cwe-918
---

## Prevent Server-Side Request Forgery (SSRF)

Server-Side Request Forgery (SSRF) occurs when an attacker can make a server-side application send HTTP requests to an arbitrary domain of the attacker's choosing. This can be used to:

- Access internal services and APIs that are not exposed to the internet
- Read cloud metadata endpoints (e.g., AWS EC2 metadata at 169.254.169.254)
- Scan internal networks and ports
- Bypass firewalls and access controls
- Exfiltrate sensitive data

### Language: Python

**Incorrect (Django - user data flows into URL host):**
```python
from django.http import HttpResponse
import requests

def ex1(request):
  env = request.POST.get('env')
  user_name = request.POST.get('user_name')
  # ruleid: tainted-url-host
  user_age = requests.get("https://%s/%s/age" % (env, user_name))
  return HttpResponse(user_age)

def ex2(request):
  env = request.POST.get('env')
  user_name = request.POST.get('user_name')
  # ruleid: tainted-url-host
  user_age = requests.get("https://{}/{}/age".format(env, user_name))
  return HttpResponse(user_age)

def ex3(request):
  env = request.POST.get('env')
  user_name = request.POST.get('user_name')
  # ruleid: tainted-url-host
  user_age = requests.get(f"https://{env}/{user_name}/age")
  return HttpResponse(user_age)
```

**Correct (Django - fixed host with user data in path only):**
```python
from django.http import HttpResponse
import requests

def ok1(request):
  env = request.POST.get('env')
  user_name = request.POST.get('user_name')
  # ok: tainted-url-host
  user_age = requests.get("https://example.com/%s/%s/age" % (env, user_name))
  return HttpResponse(user_age)

def ok2(request):
  env = request.POST.get('env')
  user_name = request.POST.get('user_name')
  # ok: tainted-url-host
  user_age = requests.get("https://example.com/%s/%s/age".format(env, user_name))
  return HttpResponse(user_age)
```

**Incorrect (Django - SSRF via requests library):**
```python
from requests import get
from django.shortcuts import render

def send_to_redis(request):
    # ruleid: ssrf-injection-requests
    bucket = request.GET.get("bucket")
    inner_response = get("http://my.redis.foo/{}".format(bucket), data=3)
    return render({"response_code": inner_response.status_code})

def send_to_redis_fstring(request):
    # ruleid: ssrf-injection-requests
    bucket = request.GET.get("bucket")
    inner_response = get(f"http://my.redis.foo/{bucket}", data=3)
    return render({"response_code": inner_response.status_code})
```

**Incorrect (Django - SSRF via urllib):**
```python
from urllib.request import urlopen
from django.shortcuts import render

def send_to_redis(request):
    # ruleid: ssrf-injection-urllib
    bucket = request.GET.get("bucket")
    inner_response = urlopen("http://my.redis.foo/{}".format(bucket), data=3)
    return render({"response_code": inner_response.status_code})
```

**Incorrect (Flask - user data flows into URL host):**
```python
import flask
import requests

app = flask.Flask(__name__)

@app.route("/route_param/<route_param>")
def route_param(route_param):
    print("blah")
    # ruleid: tainted-url-host
    url = "https://%s/path" % route_param
    requests.get(url)
    return True

@app.route("/get_param_inline", methods=["GET"])
def get_param_inline():
    # ruleid: tainted-url-host
    return "<a href='https://%s/path'>Click me!</a>" % flask.request.args.get("param")

@app.route("/get_param_inline_concat", methods=["GET"])
def get_param_inline_concat():
    # ruleid: tainted-url-host
    return "<a href='http://" + flask.request.args.get("param") + "'>Click me!</a>"
```

**Correct (Flask - fixed host, user data only in path):**
```python
import flask
import requests

app = flask.Flask(__name__)

@app.route("/route_param_ok/<route_param>")
def route_param_ok(route_param):
    print("blah")
    # ok: tainted-url-host
    return "<a href='https://example.com'>Click me!</a>"

@app.route("/get_param_inline_concat_ok_in_path", methods=["GET"])
def get_param_inline_concat_ok_in_path():
    # ok: tainted-url-host
    return "<a href='http://example.com/" + flask.request.args.get("param") + "'>Click me!</a>"

@app.route("/route_param/<route_param>")
def doesnt_use_the_route_param(route_param):
    not_the_route_param = "hello.com"
    # ok: tainted-url-host
    url = "https://%s/path" % not_the_route_param
    requests.get(url)
    return True
```

**Incorrect (Flask - SSRF via requests):**
```python
import flask
import requests

app = flask.Flask(__name__)

@app.route("/route_param/<route_param>")
def route_param(route_param):
    print("blah")
    # ruleid: ssrf-requests
    return requests.get(route_param)

@app.route("/get_param", methods=["GET"])
def get_param():
    param = flask.request.args.get("param")
    # ruleid: ssrf-requests
    requests.post(param, timeout=10)

@app.route("/get_param_concat", methods=["GET"])
def get_param_concat():
    param = flask.request.args.get("param")
    # ruleid: ssrf-requests
    requests.get(param + "/id")
```

**Correct (Flask - safe requests usage):**
```python
import flask
import requests

app = flask.Flask(__name__)

@app.route("/route_param_ok/<route_param>")
def route_param_ok(route_param):
    print("blah")
    # ok: ssrf-requests
    return requests.get("this is safe")

@app.route("/get_param_ok", methods=["GET"])
def get_param_ok():
    param = flask.request.args.get("param")
    # ok: ssrf-requests
    requests.post("this is safe", timeout=10)

@app.route("/ok")
def ok():
    requests.get("https://www.google.com")
```

**Incorrect (Flask - host header injection):**
```python
from flask import Flask, request
from flask_mail import Mail, Message

app = Flask(__name__)
mail = Mail(app)

@app.route("/reset_password", methods=["POST"])
def reset_password():
    email = request.form.get("email")
    if not email:
        return "Invalid email", 400
    # ruleid: host-header-injection-python
    reset_link = "https://"+request.host+"reset/"+request.headers.get('reset_token')
    msg = Message('Password reset request', recipients=[email])
    msg.body = "Please click on the link to reset your password: " + reset_link
    mail.send(msg)
    return "Password reset email sent!"
```

**Correct (Flask - avoid using request.host):**
```python
from flask import Flask, request
from flask_mail import Mail, Message

app = Flask(__name__)
mail = Mail(app)

@app.route("/reset_password", methods=["POST"])
def reset_password():
    email = request.form.get("email")
    if not email:
        return "Invalid email", 400
    # ok: host-header-injection-python
    reset_link = "https://"+request.foo+"reset/"+request.headers.get('reset_token')
    msg = Message('Password reset request', recipients=[email])
    msg.body = "Please click on the link to reset your password: " + reset_link
    mail.send(msg)
    return "Password reset email sent!"
```

---

### Language: JavaScript / Node.js

**Incorrect (Express - SSRF via request library):**
```typescript
import { Request, Response, NextFunction } from 'express'

const request = require('request')

module.exports = function badNormal () {
  return (req: Request, res: Response, next: NextFunction) => {
    const url = "//"+req.body.imageUrl
    const url1 = req.body['imageUrl'] + 123
    // ruleid: express-ssrf
    request.get(url)
    // ruleid: express-ssrf
    request.get(url1+123)

    // ruleid: express-ssrf
    request.get(req.body.url)
    // ruleid: express-ssrf
    request.get(`${req.query.url}/fooo`)
    // ruleid: express-ssrf
    request.get("//"+req.query.url+config_value.url)

    const a = req.body.url
    // ruleid: express-ssrf
    request.get(a)
  }
}
```

**Correct (Express - user data only in path, not host):**
```typescript
import { Request, Response, NextFunction } from 'express'

const request = require('request')

module.exports = function goodNormal () {
  return (req: Request, res: Response, next: NextFunction) => {
    // ok: express-ssrf
    request.get(`https://reddit.com/${req.query.url}/fooo`)
    // ok: express-ssrf
    request.get("https://google.com/"+req.query.url)
    // ok: express-ssrf
    request.get(config_value.foo+req.query.url)
    // ok: express-ssrf
    request.get(config_value.foo+req.body.shouldalsonotcatch)
  }
}
```

**Incorrect (Puppeteer - goto injection):**
```javascript
const puppeteer = require('puppeteer');

const testFunc = async (userInput) => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();

  // ruleid:puppeteer-goto-injection
  await page.goto(unverifiedInput());

  const newUrl = userInput;
  // ruleid:puppeteer-goto-injection
  await page.goto(newUrl);

  await page.screenshot({path: 'example.png'});
  await browser.close();
};
```

**Correct (Puppeteer - hardcoded URL):**
```javascript
const puppeteer = require('puppeteer');

const testFunc = async (userInput) => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  let url = 'https://hardcoded.url.com'
  // ok
  await page.goto('https://example.com');

  // ok
  await page.goto(url);

  await page.screenshot({path: 'example.png'});
  await browser.close();
};
```

**Incorrect (Express + Puppeteer - combined SSRF):**
```javascript
const express = require('express')
const app = express()
const puppeteer = require('puppeteer')

app.get('/', async (req, res) => {
    const browser = await puppeteer.launch()
    const page = await browser.newPage()
    const url = `https://${req.query.name}`
    // ruleid: express-puppeteer-injection
    await page.goto(url)

    await page.screenshot({path: 'example.png'})
    await browser.close()
    res.send('Hello World!')
})

app.post('/test', async (req, res) => {
    const browser = await puppeteer.launch()
    const page = await browser.newPage()
    // ruleid: express-puppeteer-injection
    await page.setContent(`${req.body.foo}`)

    await page.screenshot({path: 'example.png'})
    await browser.close()
    res.send('Hello World!')
})

const controller = async (req, res) => {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const body = req.body.foo;
    // ruleid: express-puppeteer-injection
    await page.setContent('<html>' + body + '</html>');

    await page.screenshot({path: 'example.png'});
    await browser.close();
    res.send('Hello World!');
}
```

**Correct (Express + Puppeteer - safe usage):**
```javascript
const express = require('express')
const app = express()
const puppeteer = require('puppeteer')

app.post('/ok-test', async (req, res) => {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    // ok: express-puppeteer-injection
    await page.goto('https://example.com');

    await page.screenshot({path: 'example.png'});
    await browser.close();
    res.send('Hello World!');
})

const controller = async (req, res) => {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    // ok: express-puppeteer-injection
    const body = '<div>123</div>';
    await page.setContent('<html>' + body + '</html>');

    await page.screenshot({path: 'example.png'});
    await browser.close();
    res.send('Hello World!');
}
```

**Incorrect (Phantom.js - page open injection):**
```javascript
const phantom = require('phantom');

(async function() {
  const instance = await phantom.create();
  const page = await instance.createPage();
  await page.on('onResourceRequested', function(requestData) {
    console.info('Requesting', requestData.url);
  });

  // ruleid: phantom-injection
  const status = await page.open(input());

  const content = await page.property('content');
  console.log(content);

  await instance.exit();
})();

(async function(userInput) {
  const instance = await phantom.create();
  const page = await instance.createPage();

  // ruleid: phantom-injection
  const status = await page.property('content', input());

  // ruleid: phantom-injection
  await page.setContent(userInput);

  // ruleid: phantom-injection
  await page.evaluateJavaScript(userInput);

  await instance.exit();
})();
```

**Correct (Phantom.js - hardcoded URLs):**
```javascript
const phantom = require('phantom');

(async function() {
  const instance = await phantom.create();
  const page = await instance.createPage();

  // ok: phantom-injection
  const status = await page.open('https://stackoverflow.com/');

  // ok: phantom-injection
  var html = '<html>123</html>'
  const status = await page.property('content', html);

  // ok: phantom-injection
  var url = 'https://stackoverflow.com/'
  const status = await page.openUrl(url, {}, {});

  await instance.exit();
})();
```

**Incorrect (wkhtmltopdf - injection):**
```javascript
const wkhtmltopdf = require('wkhtmltopdf')

// ruleid: wkhtmltopdf-injection
wkhtmltopdf(input(), { output: 'vuln.pdf' })

function test(userInput) {
  // ruleid: wkhtmltopdf-injection
  return wkhtmltopdf(userInput, { output: 'vuln.pdf' })
}
```

**Correct (wkhtmltopdf - hardcoded content):**
```javascript
const wkhtmltopdf = require('wkhtmltopdf')

// ok: wkhtmltopdf-injection
wkhtmltopdf('<html><html/>', { output: 'vuln.pdf' })

function okTest(userInput) {
   var html = '<html><html/>';
   // ok: wkhtmltopdf-injection
   return wkhtmltopdf(html, { output: 'vuln.pdf' })
}
```

**Incorrect (wkhtmltoimage - injection):**
```javascript
var wkhtmltoimage = require('wkhtmltoimage')

// ruleid: wkhtmltoimage-injection
wkhtmltoimage.generate(input(), { output: 'vuln.jpg' })

function test(userInput) {
    // ruleid: wkhtmltoimage-injection
    wkhtmltoimage.generate(userInput, { output: 'vuln.jpg' })
}
```

**Correct (wkhtmltoimage - hardcoded content):**
```javascript
var wkhtmltoimage = require('wkhtmltoimage')

const html = '<html></html>'
// ok: wkhtmltoimage-injection
wkhtmltoimage.generate(html, { output: 'vuln.jpg' })
```

**Incorrect (Apollo + Axios - SSRF):**
```javascript
module.exports = {
    Query: {
        requestStatus(parent, args, context, info)
        {
            url = args.url
            const axios = require('axios');

            async function getStatus(url) {
                try {
                  // ruleid: apollo-axios-ssrf
                  const response = await axios.request(url);
                  console.log(response);
                  var s = response.status;
                } catch (error) {
                  console.error(error);
                  var s = error.code;
                }
                return s;
              }
            return getStatus(url);
        }
    }
};
```

---

### Language: Go

**Incorrect (tainted URL host via fmt.Sprintf):**
```go
package main

import (
	"fmt"
	"net/http"
)

func handlerIndexFmt(w http.ResponseWriter, r *http.Request) {
	client := &http.Client{}

	if r.Method == "POST" && r.URL.Path == "/api" {
		url := fmt.Sprintf("https://%v/api", r.URL.Query().Get("proxy"))

		// ruleid: tainted-url-host
		resp, err := client.Post(url, "application/json", r.Body)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()
	}
}

func handlerBadFmt(w http.ResponseWriter, r *http.Request) {
	urls, ok := r.URL.Query()["url"]
	if !ok {
		http.Error(w, "url missing", 500)
		return
	}

	url := fmt.Sprintf("//%s/path", urls[0])

	// ruleid: tainted-url-host
	resp, err := http.Get(url)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	client := &http.Client{}

	// ruleid: tainted-url-host
	req2, err := http.NewRequest("GET", url, nil)
	_, err2 := client.Do(req2)
}
```

**Correct (fixed host, user data in path only):**
```go
package main

import (
	"fmt"
	"net/http"
)

func handlerOkFmt(w http.ResponseWriter, r *http.Request) {
	client := &http.Client{}

	if r.Method == "POST" && r.URL.Path == "/api" {
		url := fmt.Printf("https://example.com/%v", r.URL.Query().Get("proxy"))

		// ok: tainted-url-host
		resp, err := client.Post(url, "application/json", r.Body)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()
	}
}

func handlerOk(w http.ResponseWriter, r *http.Request) {
	// ok: tainted-url-host
	_, err3 := http.Get("https://semgrep.dev")
	if err3 != nil {
		http.Error(w, err3.Error(), 500)
		return
	}
}
```

**Incorrect (tainted URL host via string concatenation):**
```go
package main

import (
	"net/http"
)

func handlerIndexAdd(w http.ResponseWriter, r *http.Request) {
	client := &http.Client{}

	if r.Method == "POST" && r.URL.Path == "/api" {
		url := "https://" + r.URL.Query().Get("proxy") + "/api"

		// ruleid: tainted-url-host
		resp, err := client.Post(url, "application/json", r.Body)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()
	}
}

func handlerBadAdd(w http.ResponseWriter, r *http.Request) {
	urls, ok := r.URL.Query()["url"]
	if !ok {
		http.Error(w, "url missing", 500)
		return
	}

	url := urls[0]

	// ruleid: tainted-url-host
	resp, err := http.Get(url)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	client := &http.Client{}

	// ruleid: tainted-url-host
	req2, err := http.NewRequest("GET", r.URL.Path, nil)
	_, err2 := client.Do(req2)
}
```

**Correct (user data only in path portion):**
```go
package main

import (
	"net/http"
)

func handlerOkAdd(w http.ResponseWriter, r *http.Request) {
	client := &http.Client{}

	if r.Method == "POST" && r.URL.Path == "/api" {
		// ok: tainted-url-host
		resp, err := client.Post("https://example.com/"+r.URL.Query().Get("proxy"), "application/json", r.Body)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()
	} else {
		proxy := r.URL.Query()["proxy"]
		url := "https://example.com/" + proxy
		// ok: tainted-url-host
		resp, err := client.Post(url, "application/json", r.Body)
	}
}
```

---

### Language: Java

**Incorrect (Spring - tainted URL host):**
```java
package org.sasanlabs.service.vulnerability.ssrf;

import java.net.URL;
import java.net.URLConnection;
import org.springframework.web.bind.annotation.RequestParam;

@VulnerableAppRestController(descriptionLabel = "SSRF_VULNERABILITY", value = "SSRFVulnerability")
public class SSRFVulnerability {

    @VulnerableAppRequestMapping(value = LevelConstants.LEVEL_1, htmlTemplate = "LEVEL_1/SSRF")
    public ResponseEntity<GenericVulnerabilityResponseBean<byte[]>> getVulnerablePayloadLevel1(
            @RequestParam("imageurl") String urlImage) {
        try {
            // ruleid: tainted-url-host
            URL u = new URL(urlImage);
            URLConnection urlConnection = u.openConnection();
            byte[] bytes;
            try (InputStream in = urlConnection.getInputStream()) {
                bytes = StreamUtils.copyToByteArray(urlConnection.getInputStream());
            }
            return new ResponseEntity<>(
                    new GenericVulnerabilityResponseBean<>(bytes, true), HttpStatus.OK);
        } catch (Exception e) {
            LOGGER.error("Error fetching URL {}", urlImage, e);
        }
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }
}
```

**Correct (Java - hardcoded host, user data in path):**
```java
@RestController
@RequestMapping("/user03")
public class User03Controller {

    @Autowired
    private RestTemplate restTemplate;

    @GetMapping("/get")
    public UserDTO get(@RequestParam("id") Integer id) {
        // ok: tainted-url-host
        String url = String.format("http://%s/user/get?id=%d", "demo-provider", id);
        return restTemplate.getForObject(url, UserDTO.class);
    }

    @PostMapping("/add")
    public Integer add(UserAddDTO addDTO) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        String body = JSON.toJSONString(addDTO);
        HttpEntity<String> entity = new HttpEntity<>(body, headers);
        // ok: tainted-url-host
        String url = String.format("http://%s/user/add", "demo-provider");
        return restTemplate.postForObject(url, entity, Integer.class);
    }
}
```

---

### Language: C#

**Incorrect (WebRequest with user-controlled URL):**
```csharp
using System.Net.WebRequest;
using System.Uri;

namespace Ssrf
{
    public class Ssrf
    {
        // ruleid: ssrf
        public void WebRequest(string host)
        {
            try
            {
                WebRequest webRequest = WebRequest.Create(host);
            }
            catch (Exception e)
            {
                System.Diagnostics.Debug.WriteLine(e);
            }
        }

        // ruleid: ssrf
        public void WebRequestWithStringConcatenation(string host)
        {
            String baseUrl = "constant" + host;
            WebRequest webRequest = WebRequest.Create(baseUrl);
        }

        // ruleid: ssrf
        public void WebRequestWithUri(string host)
        {
            Uri uri = new Uri(host);
            WebRequest webRequest = WebRequest.Create(uri);
        }
    }
}
```

**Correct (WebRequest with hardcoded URL):**
```csharp
using System.Net.WebRequest;
using System.Uri;

namespace Ssrf
{
    public class Ssrf
    {
        // ok: ssrf
        public void WebRequest(string host)
        {
            try
            {
                WebRequest webRequest = WebRequest.Create("constant");
            }
            catch (Exception e)
            {
                System.Diagnostics.Debug.WriteLine(e);
            }
        }

        // ok: ssrf
        public void WebRequestWithStringConcatenation(string host)
        {
            String baseUrl = "constant";
            WebRequest webRequest = WebRequest.Create(baseUrl);
        }

        // ok: ssrf
        public void WebRequestWithUri(string host)
        {
            Uri uri = new Uri("constant");
            WebRequest webRequest = WebRequest.Create(uri);
        }
    }
}
```

**Incorrect (HttpClient with user-controlled URL):**
```csharp
using System.Net.Http;

namespace ServerSideRequestForgery
{
    public class Ssrf
    {
        // ruleid: ssrf
        public void HttpClientAsync(string host)
        {
            HttpClient client = new HttpClient();
            try
            {
                HttpResponseMessage response = client.GetAsync(host).Result;
            }
            catch (Exception e)
            {
                System.Diagnostics.Debug.WriteLine(e);
            }
        }

        // ruleid: ssrf
        public void HttpClientAsyncWithUri(string host)
        {
            Uri uri = new Uri(host);
            HttpClient client = new HttpClient();
            try
            {
                HttpResponseMessage response = client.GetAsync(uri).Result;
            }
            catch (Exception e)
            {
                System.Diagnostics.Debug.WriteLine(e);
            }
        }
    }
}
```

**Correct (HttpClient with hardcoded URL):**
```csharp
using System.Net.Http;

namespace ServerSideRequestForgery
{
    public class Ssrf
    {
        // ok: ssrf
        public void HttpClientAsync(string host)
        {
            HttpClient client = new HttpClient();
            try
            {
                HttpResponseMessage response = client.GetAsync("constant").Result;
            }
            catch (Exception e)
            {
                System.Diagnostics.Debug.WriteLine(e);
            }
        }

        // ok: ssrf
        public void HttpClientAsyncWithUri(string host)
        {
            Uri uri = new Uri("constant");
            HttpClient client = new HttpClient();
            try
            {
                HttpResponseMessage response = client.GetAsync(uri).Result;
            }
            catch (Exception e)
            {
                System.Diagnostics.Debug.WriteLine(e);
            }
        }
    }
}
```

**Incorrect (WebClient with user-controlled URL):**
```csharp
using System.Net;

namespace ServerSideRequestForgery
{
    public class Ssrf
    {
        // ruleid: ssrf
        public string WebClient(string host)
        {
            string result = "";
            try
            {
                WebClient client = new WebClient();
                Stream data = client.OpenRead(host);
                StreamReader reader = new StreamReader(data);
                result = reader.ReadToEnd();
            }
            catch (Exception e)
            {
                System.Diagnostics.Debug.WriteLine(e);
            }
            return result;
        }

        // ruleid: ssrf
        public string WebClientDownloadString(string host)
        {
            string result = "";
            try
            {
                WebClient client = new WebClient();
                Stream data = client.DownloadString(host);
                StreamReader reader = new StreamReader(data);
                result = reader.ReadToEnd();
            }
            catch (Exception e)
            {
                System.Diagnostics.Debug.WriteLine(e);
            }
            return result;
        }
    }
}
```

**Correct (WebClient with hardcoded URL):**
```csharp
using System.Net;

namespace ServerSideRequestForgery
{
    public class Ssrf
    {
        // ok: ssrf
        public string WebClient(string host)
        {
            string result = "";
            try
            {
                WebClient client = new WebClient();
                Stream data = client.OpenRead("constant");
                StreamReader reader = new StreamReader(data);
                result = reader.ReadToEnd();
            }
            catch (Exception e)
            {
                System.Diagnostics.Debug.WriteLine(e);
            }
            return result;
        }

        // ok: ssrf
        public string WebClientDownloadString(string host)
        {
            string result = "";
            try
            {
                WebClient client = new WebClient();
                Stream data = client.DownloadString("constant");
                StreamReader reader = new StreamReader(data);
                result = reader.ReadToEnd();
            }
            catch (Exception e)
            {
                System.Diagnostics.Debug.WriteLine(e);
            }
            return result;
        }
    }
}
```

**Incorrect (RestClient with user-controlled URL):**
```csharp
using RestSharp;

namespace ServerSideRequestForgery
{
    public class Ssrf
    {
        // ruleid: ssrf
        public void RestClientGet(string host)
        {
            try
            {
                RestClient client = new RestClient(host);
                var request = new RestRequest("/");
                var response = client.Get(request);
                result = response.Content;
            }
            catch (Exception e)
            {
                System.Diagnostics.Debug.WriteLine(e);
            }
        }
    }
}
```

**Correct (RestClient with hardcoded URL):**
```csharp
using RestSharp;

namespace ServerSideRequestForgery
{
    public class Ssrf
    {
        // ok: ssrf
        public void RestClientGet(string host)
        {
            try
            {
                RestClient client = new RestClient("constant");
                var request = new RestRequest("/");
                var response = client.Get(request);
                result = response.Content;
            }
            catch (Exception e)
            {
                System.Diagnostics.Debug.WriteLine(e);
            }
        }
    }
}
```

---

### Language: Scala

**Incorrect (Play WSClient - SSRF):**
```scala
package controllers

import javax.inject._
import play.api.libs.ws._
import scala.concurrent.Future

object Smth {
  def call1(wsClient: WSClient, url: String): Future[Unit] = {
    // ruleid: webservice-ssrf
    wsClient.url(url).get().map { response =>
      val statusText: String = response.statusText
      println(s"Got a response $statusText")
    }
  }
}

@Singleton
class HomeController @Inject()(
  ws: WSClient,
  val controllerComponents: ControllerComponents,
  implicit val ec: ExecutionContext
) extends BaseController {

  def req1(url: String) = Action.async { implicit request: Request[AnyContent] =>
    // ruleid: webservice-ssrf
    val futureResponse = ws.url(url).get()
    futureResponse.map { response =>
      Ok(s"it works: ${response.statusText}")
    }
  }
}
```

**Correct (Play WSClient - hardcoded URL):**
```scala
package controllers

import javax.inject._
import play.api.libs.ws._
import scala.concurrent.Future

object Smth {
  def call2(wsClient: WSClient): Future[Unit] = {
    // ok: webservice-ssrf
    wsClient.url("https://www.google.com").get().map { response =>
      val statusText: String = response.statusText
      println(s"Got a response $statusText")
    }
  }
}

@Singleton
class HomeController @Inject()(
  ws: WSClient,
  val controllerComponents: ControllerComponents,
  implicit val ec: ExecutionContext
) extends BaseController {

  def req2(url: String) = Action.async { implicit request: Request[AnyContent] =>
    // ok: webservice-ssrf
    val futureResponse = ws.url("https://www.google.com").get()
    futureResponse.map { response =>
      Ok(s"it works: ${url}")
    }
  }
}
```

**Incorrect (Scala IO Source - SSRF):**
```scala
package controllers

import scala.io.{Codec, Source}

object Smth {
  def call1(request_url: String) = {
    // ruleid: io-source-ssrf
    val html = Source.fromURI(request_url)
    val data = html.mkString
    data
  }
}

object FooBar {
  def call1(request_url: String, codec: Codec) = {
    // ruleid: io-source-ssrf
    val res = Source.fromURL(request_url)(codec).mkString
    res
  }
}
```

**Correct (Scala IO Source - hardcoded URL):**
```scala
package controllers

import scala.io.{Codec, Source}

object Smth {
  def call2() = {
    // ok: io-source-ssrf
    val html = Source.fromURI("https://www.google.com")
    val data = html.mkString
    data
  }
}

object FooBar {
  def call2() = {
    // ok: io-source-ssrf
    val res = Source.fromURL("https://www.google.com")(codec).mkString
    res
  }
}
```

**Incorrect (Dispatch HTTP - SSRF):**
```scala
package controllers

import dispatch._
import Defaults._

object Smth {
  def call1(request_url: String): Future[Unit] = {
    // ruleid: dispatch-ssrf
    val req = url(request_url)
    val data = Http.default(req OK as.String)
    data
  }
}

object FooBar {
  def call1(request_url: String): Future[Unit] = {
    // ruleid: dispatch-ssrf
    val request = url(request_url).POST.setHeader("Content-Type", "application/json")
    val res = Http(request OK as.String)
    res
  }
}
```

**Correct (Dispatch HTTP - hardcoded URL):**
```scala
package controllers

import dispatch._
import Defaults._

object Smth {
  def call2(): Future[Unit] = {
    // ok: dispatch-ssrf
    val req = url("https://www.google.com")
    val data = Http.default(req OK as.String)
    data
  }
}

object FooBar {
  def call2(): Future[Unit] = {
    // ok: dispatch-ssrf
    val request = url("https://www.google.com").POST.setHeader("Content-Type", "application/json")
    val res = Http(request OK as.String)
    res
  }
}
```

**Incorrect (Scalaj HTTP - SSRF):**
```scala
package controllers

import scalaj.http.{Http, Token}

object Smth {
  def call1(url: String): Future[Unit] = {
    // ruleid: scalaj-http-ssrf
    val response: HttpResponse[String] = Http(url).param("q","monkeys").asString
    response.body
  }
}

object FooBar {
  def call1(url: String): Future[Unit] = {
    // ruleid: scalaj-http-ssrf
    val request = Http(url).postForm(Seq("name" -> "jon", "age" -> "29"))
    request.asString
  }
}
```

**Correct (Scalaj HTTP - hardcoded URL):**
```scala
package controllers

import scalaj.http.{Http, Token}

object Smth {
  def call2(): Future[Unit] = {
    // ok: scalaj-http-ssrf
    val response: HttpResponse[String] = Http("https://www.google.com").param("q","monkeys").asString
    response.body
  }
}

object FooBar {
  def call2(): Future[Unit] = {
    // ok: scalaj-http-ssrf
    val request = Http("https://www.google.com").postForm(Seq("name" -> "jon", "age" -> "29"))
    request.asString
  }
}
```

---

### Language: PHP

**Incorrect (curl with user input):**
```php
<?php
    function test1(){
        //ruleid: php-ssrf
        $ch = curl_init($_GET['r']);
    }

    function test2(){
        //ruleid: php-ssrf
        $url = $_GET['r'];
        $ch = curl_init($url);
    }

    function test3(){
        $ch = curl_init();
        //ruleid: php-ssrf
        curl_setopt($ch, CURLOPT_URL, $_POST['image_url']);
    }

    function test4(){
        $ch = curl_init();
        //ruleid: php-ssrf
        $url = $_GET['r'];
        curl_setopt($ch, CURLOPT_URL, $url);
    }
?>
```

**Incorrect (fopen/file_get_contents with user input):**
```php
<?php
    function test5(){
        //ruleid: php-ssrf
        $url = $_GET['r'];
        $file = fopen($url, 'rb');
    }

    function test6(){
        //ruleid: php-ssrf
        $file = fopen($_POST['r'], 'rb');
    }

    function test7(){
        //ruleid: php-ssrf
        $url = $_POST['r'];
        $file = file_get_contents($url);
    }

    function test8(){
        //ruleid: php-ssrf
        $file = file_get_contents($_POST['r']);
    }
?>
```

**Correct (hardcoded URLs):**
```php
<?php
    function test9(){
        //ok: php-ssrf
        $file = file_get_contents("index.php");
    }

    function test10(){
        //ok: php-ssrf
        $url = $_POST['r'];
        $file = fopen("/tmp/test.txt", 'rb');
    }
?>
```

**Incorrect (tainted URL host):**
```php
<?php

function test1() {
    // ruleid: tainted-url-host
    $url = 'https://'.$_GET['url'].'/foobar';
    $info = make_request($url);
    return $info;
}

function test2() {
    $part = $_POST['url'];
    // ruleid: tainted-url-host
    $url = "https://$part/foobar";
    $info = make_request($url);
    return $info;
}

function test3() {
    // ruleid: tainted-url-host
    $url = "https://{$_REQUEST['url']}/foobar";
    $info = make_request($url);
    return $info;
}

function test4() {
    // ruleid: tainted-url-host
    $url = sprintf('https://%s/%s/', $_COOKIE['foo'], $bar);
    $info = make_request($url);
    return $info;
}
```

**Correct (fixed host, user data in path only):**
```php
<?php

function test1() {
    // ok: tainted-url-host
    $url = 'https://www.google.com/'.$_GET['url'].'/foobar';
    $info = make_request($url);
    return $info;
}

function test3() {
    // ok: tainted-url-host
    $url = "https://www.google.com/{$_REQUEST['url']}/foobar";
    $info = make_request($url);
    return $info;
}
```

**Incorrect (tainted filename leading to SSRF):**
```php
<?php

$tainted = $_GET["tainted"];
// ruleid: tainted-filename
hash_file('sha1', $tainted);

// ruleid: tainted-filename
file($tainted);

// ruleid: tainted-filename
file(dirname($tainted));
```

**Correct (sanitized filename):**
```php
<?php

$tainted = $_GET["tainted"];

// ok: tainted-filename
hash_file($tainted, 'file.txt');

// Sanitized
// ok: tainted-filename
file(basename($tainted));
```

---

### Language: Ruby

**Incorrect (Rails - tainted HTTP request):**
```ruby
require 'net/http'

def foo
  url = params[:url]
  # ruleid: avoid-tainted-http-request
  Net::HTTP.get(url, "/index.html")

  # ruleid: avoid-tainted-http-request
  Net::HTTP.get_response(params[:url])

  uri = URI(params[:url])
  # ruleid: avoid-tainted-http-request
  Net::HTTP.post(uri)

  # ruleid: avoid-tainted-http-request
  Net::HTTP.post_form(URI(params[:url]))

  uri = URI(params[:server])
  # ruleid: avoid-tainted-http-request
  req = Net::HTTP::Get.new uri

  # ruleid: avoid-tainted-http-request
  Net::HTTP.start(uri.host, uri.port) do |http|
    # ruleid: avoid-tainted-http-request
    req = Net::HTTP::Get.new uri
    resp = http.request request
  end

  # ruleid: avoid-tainted-http-request
  Net::HTTP::Get.new(params[:url])

  # ruleid: avoid-tainted-http-request
  Net::HTTP::Post.new(URI(params[:url]))
end
```

**Correct (Ruby - hardcoded URLs):**
```ruby
require 'net/http'

def foo
  # ok: avoid-tainted-http-request
  Net::HTTP.get("example.com", "/index.html")

  uri = URI("example.com/index.html")
  # ok: avoid-tainted-http-request
  Net::HTTP::Get.new(uri)
end
```

---

### Language: Terraform / Infrastructure as Code

**Incorrect (AWS EC2 IMDSv1 optional - allows SSRF to metadata):**
```hcl
resource "aws_instance" "test-instance-bad-http-tokens-optional" {
  ami = "ami-0d5eff06f840b45e9"

  metadata_options {
    http_endpoint = "enabled"
    # ruleid: ec2-imdsv1-optional
    http_tokens = "optional"
  }
}

# ruleid: ec2-imdsv1-optional
resource "aws_instance" "test-instance-bad-no-metadata-options" {
  ami = "ami-0d5eff06f840b45e9"
}

# ruleid: ec2-imdsv1-optional
resource "aws_instance" "test-instance-bad-v3-http-tokens-default-optional" {
  ami = "ami-0d5eff06f840b45e9"
  metadata_options {
    http_endpoint = "enabled"
  }
}
```

**Correct (AWS EC2 IMDSv2 required - mitigates SSRF to metadata):**
```hcl
# ok: ec2-imdsv1-optional
resource "aws_instance" "test-instance-good" {
  ami = "ami-0d5eff06f840b45e9"
  metadata_options {
    http_endpoint = "enabled"
    http_tokens = "required"
  }
}
```

---

**References:**
- CWE-918: Server-Side Request Forgery (SSRF)
- [OWASP Top 10 A10:2021 - Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP SSRF Attacks](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [AWS EC2 Instance Metadata and SSRF](https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service)
- [CWE-918 Definition](https://cwe.mitre.org/data/definitions/918.html)
