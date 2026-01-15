---
title: Use Secure Transport
impact: HIGH
impactDescription: Exposure of sensitive data through cleartext transmission or improper certificate validation
tags: security, insecure-transport, tls, ssl, cwe-295, cwe-319, cwe-311
---

## Use Secure Transport

Insecure transport vulnerabilities occur when applications transmit sensitive data over unencrypted connections or when TLS/SSL certificate validation is disabled. This exposes data to man-in-the-middle (MITM) attacks where attackers can intercept, read, and modify communications. Key issues include:

- **Cleartext transmission**: Using HTTP instead of HTTPS, FTP instead of SFTP, or Telnet instead of SSH
- **Disabled certificate verification**: Accepting any SSL certificate without validation
- **Weak TLS versions**: Using deprecated protocols like SSLv2, SSLv3, or TLS 1.0/1.1
- **Missing secure cookie flags**: Cookies transmitted over insecure channels

---

### Language: JavaScript/Node.js

**Incorrect (HTTP requests without TLS):**
```javascript
const http = require('http');

function bad_http() {
    // ruleid: http-request
    http.get('http://nodejs.org/dist/index.json', (res) => {
    const { statusCode } = res;})

    // ruleid: http-request
    const options = {
        port: 80,
        hostname: 'www.google.com',
        path: '/upload'
    }

    const req = http.request(options, (res) => {
    console.log(`STATUS: ${res.statusCode}`);})

    // ruleid: http-request
    const options = new URL('http://abc:xyz@example.com');

    const req = http.request(options, (res) => {
    });
}
```

**Correct (HTTPS requests with TLS):**
```javascript
const https = require('https');

function ok_http() {
    // ok: http-request
    https.get('https://nodejs.org/dist/index.json', (res) => {
    const { statusCode } = res;})

    // ok: http-request
    const options = {
        port: 443,
        hostname: 'www.google.com',
        path: '/upload',
        protocol: 'https'
    }

    const req = https.request(options, (res) => {
    console.log(`STATUS: ${res.statusCode}`);})
}
```

**Incorrect (disabled TLS verification):**
```javascript
function bad_tls1() {
    // ruleid: bypass-tls-verification
    process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;
}

function bad_tls2() {
    // ruleid: bypass-tls-verification
    var req = https.request({
      host: '192.168.1.1',
      port: 443,
      path: '/',
      method: 'GET',
      rejectUnauthorized: false,
      requestCert: true,
      agent: false
    });

    // ruleid: bypass-tls-verification
    var client = new RpcClient({
      user: 'user',
      pass: 'pass',
      host: 'localhost',
      port: 8332,
      rejectUnauthorized: false,
      disableAgent: true
    });
}

// ruleid: bypass-tls-verification
require('request').defaults({method: 'GET', rejectUnauthorized: false, requestCert: true})
```

**Correct (TLS verification enabled):**
```javascript
function ok_tls1() {
    // ok: bypass-tls-verification
    var req = https.request({
      host: '192.168.1.1',
      port: 443,
      path: '/',
      method: 'GET',
      rejectUnauthorized: true,
      requestCert: true,
      agent: false
    });
}

function ok_tls2() {
    // ok: bypass-tls-verification
    var req = https.request({
      host: '192.168.1.1',
      port: 443,
      path: '/',
      method: 'GET',
      requestCert: true,
      agent: false
    });
}
```

**Incorrect (weak TLS versions allowed):**
```javascript
const https = require('https');

function bad1() {
    const consts = require('crypto');
    // ruleid: disallow-old-tls-versions1
    https.createServer({
        secureOptions: consts.SSL_OP_NO_TLSv1 | consts.SSL_OP_NO_SSLv3
    }, app).listen(443);
}

function bad2() {
    const consts = require('crypto');
    // ruleid: disallow-old-tls-versions1
    https.createServer({
        secureOptions: consts.SSL_OP_NO_TLSv1
    }, app).listen(443);
}
```

**Correct (all weak TLS versions disabled):**
```javascript
const https = require('https');

function ok1() {
    const constants = require('crypto');
    // ok: disallow-old-tls-versions1
    https.createServer({
        secureOptions: constants.SSL_OP_NO_TLSv1 | constants.SSL_OP_NO_SSLv3 | constants.SSL_OP_NO_SSLv2
    }, app).listen(443);
}
```

Reference: [Node.js HTTPS Documentation](https://nodejs.org/api/https.html)

---

### Language: TypeScript/React

**Incorrect (unencrypted HTTP requests):**
```typescript
import axios from 'axios';

// ruleid: react-insecure-request
fetch('http://www.example.com', 'GET', {})

let addr = "http://www.example.com"
// ruleid: react-insecure-request
fetch(addr, 'POST', {})

// ruleid: react-insecure-request
axios.get('http://www.example.com');

// ruleid: react-insecure-request
const options = {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  data: qs.stringify(data),
  url: 'http://www.example.com',
};
axios(options);

// ruleid: react-insecure-request
axios({ method: 'POST', url: 'http://www.example.com' });
```

**Correct (HTTPS requests):**
```typescript
import axios from 'axios';

// ok: react-insecure-request
fetch('https://www.example.com', 'GET', {})

// ok: react-insecure-request
axios.get('https://www.example.com');

// ok: react-insecure-request
const options = {
  method: 'POST',
  url: 'https://www.example.com',
};
axios(options);
```

Reference: [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures)

---

### Language: Go

**Incorrect (HTTP requests without TLS):**
```go
func bad1() {
    // ruleid: http-request
    resp, err := http.Get("http://example.com/")
    // ruleid: http-request
    resp, err := http.Post("http://example.com/", val, val)
    // ruleid: http-request
    resp, err := http.Head("http://example.com/")
    // ruleid: http-request
    resp, err := http.PostForm("http://example.com/", form)
}

func bad2() {
    client := &http.Client{
        CheckRedirect: redirectPolicyFunc,
    }

    // ruleid: http-request
    resp, err := client.Get("http://example.com")
}
```

**Correct (HTTPS requests):**
```go
func ok1() {
    // ok: http-request
    resp, err := http.Get("https://example.com/")
    // ok: http-request
    resp, err := http.Post("https://example.com/", val, val)
    // ok: http-request
    resp, err := http.Head("https://example.com/")
    // ok: http-request
    resp, err := http.PostForm("https://example.com/", form)
    // ok: http-request - localhost is acceptable
    resp, err := http.PostForm("http://127.0.0.1/", form)
    // ok: http-request
    resp, err := http.Head("http://localhost/path/to/x")
}
```

**Incorrect (disabled TLS verification):**
```go
package main

import (
    "crypto/tls"
    "net/http"
)

func bad1() {
    client := &http.Client{
        Transport: &http.Transport{
            // ruleid: bypass-tls-verification
            TLSClientConfig: &tls.Config{
                InsecureSkipVerify: true,
            },
        },
    }
}

func bad2() {
    tr := &http.Transport{
        // ruleid: bypass-tls-verification
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    client := &http.Client{Transport: tr}
}

func bad3() {
    // ruleid: bypass-tls-verification
    http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
}

func bad4() {
    // ruleid: bypass-tls-verification
    mTLSConfig := &tls.Config {}
    mTLSConfig.PreferServerCipherSuites = true
    mTLSConfig.InsecureSkipVerify = true
}
```

**Correct (TLS verification enabled):**
```go
func ok1() {
    client := &http.Client{
        Transport: &http.Transport{
            // ok: bypass-tls-verification
            TLSClientConfig: &tls.Config{
                InsecureSkipVerify: false,
            },
        },
    }
}

func ok2() {
    tr := &http.Transport{
        // ok: bypass-tls-verification
        TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
    }
    client := &http.Client{Transport: tr}
}
```

**Incorrect (weak TLS versions):**
```go
func bad1() {
    client := &http.Client{
        Transport: &http.Transport{
            // ruleid: disallow-old-tls-versions
            TLSClientConfig: &tls.Config{
                MinVersion: tls.VersionSSL30,
            },
        },
    }
}

func bad2() {
    // ruleid: disallow-old-tls-versions
    mTLSConfig := &tls.Config {}
    mTLSConfig.MinVersion = tls.VersionTLS11
}
```

**Correct (modern TLS versions only):**
```go
func ok1() {
    client := &http.Client{
        Transport: &http.Transport{
            // ok: disallow-old-tls-versions
            TLSClientConfig: &tls.Config{
                MinVersion: tls.VersionTLS12,
            },
        },
    }
}

func ok2() {
    // ok: disallow-old-tls-versions
    mTLSConfig := &tls.Config {}
    mTLSConfig.MinVersion = tls.VersionTLS13
}
```

**Incorrect (HTTP server without TLS):**
```go
package main

import (
    "net/http"
)

func main() {
    http.HandleFunc("/index", Handler)
    // ruleid: use-tls
    http.ListenAndServe(":80", nil)
}
```

**Correct (HTTPS server with TLS):**
```go
func main() {
    http.HandleFunc("/index", Handler)
    // ok: use-tls
    http.ListenAndServeTLS(":443", "cert.pem", "key.pem", nil)
}
```

**Incorrect (insecure gRPC connection):**
```go
package insecuregrpc

import (
    "google.golang.org/grpc"
)

func unsafe() {
    // ruleid: grpc-client-insecure-connection
    conn, err := grpc.Dial(address, grpc.WithInsecure())
    if err != nil {
        log.Fatalf("did not connect: %v", err)
    }
    defer conn.Close()
}
```

**Correct (secure gRPC connection):**
```go
func safe() {
    // ok: grpc-client-insecure-connection
    conn, err := grpc.Dial(address, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
    if err != nil {
        log.Fatalf("did not connect: %v", err)
    }
    defer conn.Close()
}
```

Reference: [Go TLS Documentation](https://golang.org/pkg/crypto/tls/)

---

### Language: Python

**Incorrect (HTTP requests without TLS):**
```python
import requests

def test1():
    # ruleid: request-with-http
    requests.get("http://example.com")

def test2():
    url = "http://example.com"
    # ruleid: request-with-http
    requests.post(url)

def test3(url = "http://example.com"):
    # ruleid: request-with-http
    requests.delete(url)

def test4(url = "http://example.com"):
    # ruleid: request-with-http
    requests.request("HEAD", url, timeout=30)
```

**Correct (HTTPS requests):**
```python
import requests

def test1_ok():
    # ok: request-with-http
    requests.get("https://example.com")

def test2_ok():
    # ok: request-with-http
    url = "https://example.com"
    requests.post(url)

def test_localhost_ok(url = "http://localhost/blah"):
    # ok: request-with-http - localhost is acceptable
    requests.Request("HEAD", url, timeout=30)
```

**Incorrect (disabled certificate verification):**
```python
import requests as req
import requests

some_url = "https://example.com"

# ruleid: disabled-cert-validation
r = req.get(some_url, stream=True, verify=False)
# ruleid: disabled-cert-validation
r = requests.post(some_url, stream=True, verify=False)
# ruleid: disabled-cert-validation
r = requests.post(some_url, verify=False, stream=True)
```

**Correct (certificate verification enabled):**
```python
import requests as req
import requests

some_url = "https://example.com"

# ok: disabled-cert-validation
r = req.get(some_url, stream=True)
# ok: disabled-cert-validation
r = requests.post(some_url, stream=True)
```

**Incorrect (unverified SSL context):**
```python
import ssl
import httplib.client

# ruleid: unverified-ssl-context
context = ssl._create_unverified_context()
conn = httplib.client.HTTPSConnection("123.123.21.21", context=context)

# ruleid: unverified-ssl-context
conn = httplib.client.HTTPSConnection("123.123.21.21", context=ssl._create_unverified_context())

# ruleid: unverified-ssl-context
ssl._create_default_https_context = ssl._create_unverified_context
urllib2.urlopen("https://google.com").read()
```

**Correct (verified SSL context):**
```python
import ssl
import httplib.client

# ok: unverified-ssl-context
context = ssl.create_default_context()
conn = httplib.client.HTTPSConnection("123.123.21.21", context=context)
```

Reference: [Python SSL Documentation](https://docs.python.org/3/library/ssl.html)

---

### Language: Java

**Incorrect (HTTP requests without TLS):**
```java
class Bad {
    public void sendbad1() {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
            // ruleid: httpclient-http-request
            .uri(URI.create("http://openjdk.java.net/"))
            .build();

        client.sendAsync(request, BodyHandlers.ofString())
            .thenApply(HttpResponse::body)
            .thenAccept(System.out::println)
            .join();
    }

    public void sendbad2() {
        String uri = "http://openjdk.java.net/";
        HttpClient client = HttpClient.newBuilder().build();
        HttpRequest request = HttpRequest.newBuilder()
                // ruleid: httpclient-http-request
                .uri(URI.create(uri))
                .POST(BodyPublishers.ofString(data))
                .build();

        HttpResponse<?> response = client.send(request, BodyHandlers.discarding());
    }
}
```

**Correct (HTTPS requests):**
```java
class Ok {
    public void sendok1() {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
            // ok: httpclient-http-request
            .uri(URI.create("https://openjdk.java.net/"))
            .build();

        client.sendAsync(request, BodyHandlers.ofString())
            .thenApply(HttpResponse::body)
            .thenAccept(System.out::println)
            .join();
    }

    public void sendok2() {
        String uri = "https://openjdk.java.net/";
        HttpClient client = HttpClient.newBuilder().build();
        HttpRequest request = HttpRequest.newBuilder()
                // ok: httpclient-http-request
                .uri(URI.create(uri))
                .POST(BodyPublishers.ofString(data))
                .build();

        HttpResponse<?> response = client.send(request, BodyHandlers.discarding());
    }
}
```

**Incorrect (disabled TLS verification via empty X509TrustManager):**
```java
public class Bad {
    public void bad_bypass() {
        // ruleid: bypass-tls-verification
        new X509TrustManager() {
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            public void checkClientTrusted(X509Certificate[] certs, String authType) {  }

            public void checkServerTrusted(X509Certificate[] certs, String authType) {  }
        }
    }
}
```

**Correct (proper certificate validation):**
```java
public class Ok {
    public void ok_bypass() {
        // ok: bypass-tls-verification
        new X509TrustManager() {
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            public void checkClientTrusted(X509Certificate[] certs, String authType) { }

            public void checkServerTrusted(X509Certificate[] certs, String authType) {
                try {
                    checkValidity();
                } catch (Exception e) {
                    throw new CertificateException("Certificate not valid or trusted.");
                }
             }
        }
    }
}
```

**Incorrect (weak TLS versions):**
```java
class Bad {
    public void bad_disable_old_tls1() {
        // ruleid: disallow-old-tls-versions1
        SSLConnectionSocketFactory sf = new SSLConnectionSocketFactory(
                sslContext,
                new String[] {"TLSv1", "TLSv1.1", "TLSv1.2"},
                null,
                SSLConnectionSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER);
    }

    public void bad_disable_old_tls2() {
        // ruleid: disallow-old-tls-versions1
        SSLConnectionSocketFactory sf = new SSLConnectionSocketFactory(
                sslContext,
                new String[] {"TLSv1", "TLSv1.1", "SSLv3"},
                null,
                SSLConnectionSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER);
    }
}
```

**Correct (modern TLS versions only):**
```java
class Ok {
    public void ok_disable_old_tls1() {
        // ok: disallow-old-tls-versions1
        SSLConnectionSocketFactory sf = new SSLConnectionSocketFactory(
                sslContext,
                new String[] {"TLSv1.2"},
                null,
                SSLConnectionSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER);
    }

    public void ok_disable_old_tls2() {
        // ok: disallow-old-tls-versions1
        SSLConnectionSocketFactory sf = new SSLConnectionSocketFactory(
                sslContext,
                new String[] {"TLSv1.2", "TLSv1.3"},
                null,
                SSLConnectionSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER);
    }
}
```

Reference: [Java HTTPS Documentation](https://docs.oracle.com/en/java/javase/11/docs/api/java.net.http/java/net/http/HttpClient.html)

---

### Language: Ruby

**Incorrect (HTTP requests without TLS):**
```ruby
require 'net/http'

def bad1
    # ruleid: net-http-request
    uri = URI('http://example.com/index.html?count=10')
    Net::HTTP.get(uri) # => String
end

def bad2
    # ruleid: net-http-request
    uri = URI('http://www.example.com/search.cgi')
    res = Net::HTTP.post_form(uri, 'q' => 'ruby', 'max' => '50')
    puts res.body
end

def bad3
    # ruleid: net-http-request
    uri = URI('http://example.com/some_path?query=string')

    Net::HTTP.start(uri.host, uri.port) do |http|
    request = Net::HTTP::Get.new uri

    response = http.request request # Net::HTTPResponse object
    end
end
```

**Correct (HTTPS requests):**
```ruby
require 'net/http'

def ok1
    # ok: net-http-request
    uri = URI('https://example.com/index.html?count=10')
    Net::HTTP.get(uri) # => String
end

def ok2
    # ok: net-http-request
    uri = URI('https://www.example.com/search.cgi')
    res = Net::HTTP.post_form(uri, 'q' => 'ruby', 'max' => '50')
    puts res.body
end

def ok3
    # ok: net-http-request
    uri = URI('https://example.com/some_path?query=string')

    Net::HTTP.start(uri.host, uri.port) do |http|
    request = Net::HTTP::Get.new uri

    response = http.request request # Net::HTTPResponse object
    end
end
```

**Incorrect (disabled SSL verification):**
```ruby
require "net/https"
require "uri"

uri = URI.parse("https://ssl-site.com/")
http = Net::HTTP.new(uri.host, uri.port)
http.use_ssl = true
# ruleid: ssl-mode-no-verify
http.verify_mode = OpenSSL::SSL::VERIFY_NONE

request = Net::HTTP::Get.new(uri.request_uri)
response = http.request(request)
```

**Correct (SSL verification enabled):**
```ruby
require "net/https"
require "uri"

uri = URI.parse("https://ssl-site.com/")
http = Net::HTTP.new(uri.host, uri.port)
http.use_ssl = true
# ok: ssl-mode-no-verify
http.verify_mode = OpenSSL::SSL::VERIFY_PEER

request = Net::HTTP::Get.new(uri.request_uri)
response = http.request(request)
```

Reference: [Ruby OpenSSL Documentation](https://ruby-doc.org/stdlib/libdoc/openssl/rdoc/OpenSSL.html)

---

### Language: PHP

**Incorrect (disabled SSL verification):**
```php
<?php

$ch = curl_init();

curl_setopt($ch, CURLOPT_URL, "http://www.example.com/");
curl_setopt($ch, CURLOPT_HEADER, 0);

// ruleid: curl-ssl-verifypeer-off
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
```

**Correct (SSL verification enabled):**
```php
<?php

$ch = curl_init();

curl_setopt($ch, CURLOPT_URL, "https://www.example.com/");
curl_setopt($ch, CURLOPT_HEADER, 0);

// ok: curl-ssl-verifypeer-off
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
```

Reference: [PHP cURL SSL Options](https://www.php.net/manual/en/function.curl-setopt.php)

---

### Language: Kotlin

**Incorrect (unencrypted sockets):**
```kotlin
package testcode.crypto

import java.net.Socket
import java.net.ServerSocket

public class UnencryptedSocket {

    fun plainSocket(): Void {
        // ruleid: unencrypted-socket
        val soc: Socket = Socket("www.google.com", 80)
        doGetRequest(soc)
    }

    fun otherConstructors(): Void {
        // ruleid: unencrypted-socket
        val soc1: Socket = Socket("www.google.com", 80, true)
        doGetRequest(soc1)
        val address: ByteArray = byteArrayOfInts(127, 0, 0, 1)
        // ruleid: unencrypted-socket
        val soc2: Socket = Socket("www.google.com", 80, InetAddress.getByAddress(address), 13337)
        doGetRequest(soc2)
    }
}

public class UnencryptedServerSocket {

    fun plainServerSocket(): Void {
        // ruleid: unencrypted-socket
        val ssoc: ServerSocket = ServerSocket(1234)
        ssoc.close()
    }

    fun otherConstructors(): Void {
        // ruleid: unencrypted-socket
        val ssoc1: ServerSocket = ServerSocket()
        ssoc1.close()
        // ruleid: unencrypted-socket
        val ssoc2: ServerSocket = ServerSocket(1234, 10)
        ssoc2.close()
    }
}
```

**Correct (SSL sockets):**
```kotlin
package testcode.crypto

import javax.net.ssl.SSLServerSocketFactory
import javax.net.ssl.SSLSocketFactory

public class UnencryptedSocket {

    fun sslSocket(): Void {
        // ok: unencrypted-socket
        val soc: Socket = SSLSocketFactory.getDefault().createSocket("www.google.com", 443)
        doGetRequest(soc)
    }
}

public class UnencryptedServerSocket {

    fun sslServerSocket(): Void {
        // ok: unencrypted-socket
        val ssoc: ServerSocket = SSLServerSocketFactory.getDefault().createServerSocket(1234)
        ssoc.close()
    }
}
```

Reference: [Kotlin SSL Documentation](https://kotlinlang.org/api/latest/jvm/stdlib/)

---

### Language: Rust

**Incorrect (accepting invalid certificates):**
```rust
use reqwest::header;

// ruleid: reqwest-accept-invalid
let client = reqwest::Client::builder()
    .danger_accept_invalid_hostnames(true)
    .build();

// ruleid: reqwest-accept-invalid
let client = reqwest::Client::builder()
    .danger_accept_invalid_certs(true)
    .build();

// ruleid: reqwest-accept-invalid
let client = reqwest::Client::builder()
    .user_agent("USER AGENT")
    .cookie_store(true)
    .danger_accept_invalid_hostnames(true)
    .build();

// ruleid: reqwest-accept-invalid
let client = reqwest::Client::builder()
    .user_agent("USER AGENT")
    .cookie_store(true)
    .danger_accept_invalid_certs(true)
    .build();
```

**Correct (certificate validation enabled):**
```rust
use reqwest::header;

// ok: reqwest-accept-invalid
let client = reqwest::Client::builder()
    .user_agent("USER AGENT")
    .build();
```

Reference: [Reqwest TLS Documentation](https://docs.rs/reqwest/latest/reqwest/struct.ClientBuilder.html)

---

### Language: C#

**Incorrect (validating certificates by subject name):**
```csharp
using System.IdentityModel.Tokens;

namespace System.IdentityModel.Samples
{
    public class TrustedIssuerNameRegistry : IssuerNameRegistry
    {
        public override string GetIssuerName(SecurityToken securityToken)
        {
            X509SecurityToken x509Token = securityToken as X509SecurityToken;
            if (x509Token != null)
            {
                // ruleid: X509-subject-name-validation
                if (String.Equals(x509Token.Certificate.SubjectName.Name, "CN=localhost"))
                {
                    return x509Token.Certificate.SubjectName.Name;
                }

                // ruleid: X509-subject-name-validation
                if (x509Token.Certificate.SubjectName.Name == "CN=localhost")
                {
                    return x509Token.Certificate.SubjectName.Name;
                }
            }
        }
    }
}
```

**Correct (use proper certificate validation):**
```csharp
using System.Security.Cryptography.X509Certificates;

public bool ValidateCertificate(X509Certificate2 certificate)
{
    // ok: X509-subject-name-validation
    // Use X509Certificate2.Verify() method instead of comparing subject names
    return certificate.Verify();
}
```

Reference: [Microsoft X509Certificate2 Documentation](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate2)

---

## Summary of CWEs

- **CWE-295**: Improper Certificate Validation
- **CWE-311**: Missing Encryption of Sensitive Data
- **CWE-319**: Cleartext Transmission of Sensitive Information
- **CWE-523**: Unprotected Transport of Credentials
- **CWE-614**: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute

## References

- [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures)
- [OWASP Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
