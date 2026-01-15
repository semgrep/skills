---
title: Secure JWT Authentication
impact: HIGH
---

## Secure JWT Authentication

JSON Web Tokens (JWT) are widely used for authentication and authorization. However, improper implementation can lead to serious security vulnerabilities including authentication bypass and token forgery. The most critical JWT vulnerability is decoding tokens without verifying their signatures, which allows attackers to forge tokens with arbitrary claims, impersonate any user, or escalate privileges. Other vulnerabilities include accepting the "none" algorithm, using weak secrets, and accepting unsigned tokens. Related CWEs: CWE-287 (Improper Authentication), CWE-345 (Insufficient Verification of Data Authenticity), CWE-347 (Improper Verification of Cryptographic Signature).

**Incorrect (JavaScript jsonwebtoken - decode without verify):**

```javascript
const jwt = require('jsonwebtoken');

function notOk(token) {
  // ruleid: jwt-decode-without-verify
  if (jwt.decode(token, true).param === true) {
    console.log('token is valid');
  }
}
```

**Correct (JavaScript jsonwebtoken - verify before decode):**

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

**Incorrect (JavaScript jwt-simple - verification disabled):**

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

**Correct (JavaScript jwt-simple - verification enabled):**

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

**Incorrect (Python PyJWT - verify_signature disabled):**

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

**Correct (Python PyJWT - verify_signature enabled):**

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

**Incorrect (Java auth0 java-jwt - decode without verify):**

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

**Correct (Java auth0 java-jwt - verify before use):**

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

**Incorrect (Go jwt-go - ParseUnverified):**

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

**Correct (Go jwt-go - ParseWithClaims):**

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

**Incorrect (Ruby ruby-jwt - verification disabled):**

```ruby
require 'jwt'

def bad1(hmac_secret)
    # ruleid: ruby-jwt-decode-without-verify
    decoded_token = JWT.decode token, hmac_secret, false, { algorithm: 'HS256' }
    puts decoded_token
end
```

**Correct (Ruby ruby-jwt - verification enabled):**

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

**Incorrect (C# TokenValidationParameters - unsigned tokens accepted):**

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

**Correct (C# TokenValidationParameters - signed tokens required):**

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

References:
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
- https://semgrep.dev/blog/2020/hardcoded-secrets-unverified-tokens-and-other-common-jwt-mistakes/
- https://cwe.mitre.org/data/definitions/287
- https://cwe.mitre.org/data/definitions/345
- https://cwe.mitre.org/data/definitions/347
- https://www.npmjs.com/package/jwt-simple
- https://github.com/we45/Vulnerable-Flask-App/blob/752ee16087c0bfb79073f68802d907569a1f0df7/app/app.py#L96
