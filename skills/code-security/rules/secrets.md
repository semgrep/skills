---
title: Avoid Hardcoded Secrets
impact: CRITICAL
---

## Avoid Hardcoded Secrets

Hardcoded credentials, API keys, tokens, and other secrets in source code pose a critical security risk. When secrets are committed to version control, they can be exposed to unauthorized parties through repository access, leaked in public repositories or through data breaches, difficult to rotate without code changes and redeployment, and discovered by automated secret scanning tools used by attackers. Always use environment variables, secret managers, or secure vaults to provide credentials at runtime.

**Incorrect (Python - hardcoded AWS credentials with boto3):**

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

**Correct (Python - AWS credentials from environment variables):**

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

**Incorrect (Go - hardcoded AWS access token pattern):**

```go
// ruleid: aws-access-token
AWS_api_token = "AKIALALEMEL33243OLIB"
```

**Correct (Go - AWS token from environment):**

```go
// ok: aws-access-token
AWS_api_token = os.Getenv("AWS_ACCESS_KEY_ID")
```

**Incorrect (JavaScript - hardcoded JWT secret with jsonwebtoken):**

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

**Correct (JavaScript - JWT secret from config or environment):**

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

**Incorrect (JavaScript - hardcoded express-jwt secret):**

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

**Correct (JavaScript - express-jwt secret from environment or config):**

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

**Incorrect (TypeScript - hardcoded express-session secret):**

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

**Correct (TypeScript - express-session secret from config):**

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

**Incorrect (Go - hardcoded jwt-go key):**

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

**Correct (Go - JWT key from environment):**

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

**Incorrect (Java - hardcoded java-jwt secret):**

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

**Correct (Java - JWT secret from parameter):**

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

**Incorrect (Go - hardcoded GitHub personal access token):**

```go
// ruleid: github-pat
github_api_token = "ghp_emmtytndiqky5a98w0s98w36vfhiz6f7ed4c"
```

**Correct (Go - GitHub token from environment):**

```go
// ok: github-pat
github_api_token = os.Getenv("GITHUB_TOKEN")
```

**Incorrect (Go - hardcoded Stripe access token):**

```go
// ruleid: stripe-access-token
stripeToken := "sk_test_20cbqx6v2hpftsbq203r36yqccazez"
```

**Correct (Go - Stripe token from environment):**

```go
// ok: stripe-access-token
stripeToken := os.Getenv("STRIPE_SECRET_KEY")
```

**Incorrect (Go - hardcoded private key):**

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

**Correct (Go - private key from file or environment):**

```go
// ok: private-key - load from file or environment
privateKey, err := ioutil.ReadFile(os.Getenv("PRIVATE_KEY_PATH"))
if err != nil {
    log.Fatal(err)
}
```

**Incorrect (Ruby - hardcoded secrets):**

```ruby
# ruleid: check-secrets
PASSWORD = "superdupersecret"
http_basic_authenticate_with :name => "superduperadmin", :password => PASSWORD, :only => :create
```

**Correct (Ruby - secrets from secure store):**

```ruby
# ok: check-secrets
secret = get_from_store('somepass')
# ok: check-secrets
rest_auth_site_key = ""
```

**Incorrect (Ruby - hardcoded HTTP auth password in controller):**

```ruby
class DangerousController < ApplicationController
  # ruleid:hardcoded-http-auth-in-controller
  http_basic_authenticate_with :name => "dhh", :password => "secret", :except => :index

  puts "do more stuff"

end
```

**Correct (Ruby - HTTP auth password from variable):**

```ruby
# ok:hardcoded-http-auth-in-controller
class OkController < ApplicationController

  http_basic_authenticate_with :name => "dhh", :password => not_a_string, :except => :index

  puts "do more stuff"

end
```

**Incorrect (Python Flask - hardcoded SECRET_KEY):**

```python
import os
import flask
app = flask.Flask(__name__)

# ruleid: avoid_hardcoded_config_SECRET_KEY
app.config.update(SECRET_KEY="aaaa")
# ruleid: avoid_hardcoded_config_SECRET_KEY
app.config["SECRET_KEY"] = '_5#y2L"F4Q8z\n\xec]/'
```

**Correct (Python Flask - SECRET_KEY from environment):**

```python
import os
import flask
app = flask.Flask(__name__)

# ok: avoid_hardcoded_config_SECRET_KEY
app.config.update(SECRET_KEY=os.getenv("SECRET_KEY"))
# ok: avoid_hardcoded_config_SECRET_KEY
app.config.update(SECRET_KEY=os.environ["SECRET_KEY"])
```

**Incorrect (Python Django - empty password string):**

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

**Correct (Python Django - non-empty password):**

```python
from models import UserProfile

def test_email_auth_backend_empty_password(user_profile: UserProfile) -> None:
    user_profile = example_user('hamlet')
    # ok: password-empty-string
    password = "testpassword"
    user_profile.set_password(password)
    user_profile.save()
```

**Incorrect (Python JWT - exposed credentials in token payload):**

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

**Correct (Python JWT - no credentials in token payload):**

```python
import jwt

def ok(secret_key):
    # ok: jwt-python-exposed-credentials
    encoded = jwt.encode({'some': 'payload'}, secret_key, algorithm='HS256')
    return encoded
```

**Incorrect (Terraform - IAM credentials exposure):**

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

**Correct (Terraform - IAM policy without credentials exposure):**

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
