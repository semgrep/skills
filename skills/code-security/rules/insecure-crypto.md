---
title: Avoid Insecure Cryptography
impact: HIGH
---

## Avoid Insecure Cryptography

Using weak or broken cryptographic algorithms puts sensitive data at risk. Attackers can exploit known vulnerabilities in deprecated algorithms to decrypt data, forge signatures, or predict "random" values. Weak algorithms include MD5 and SHA1 for hashing (collision attacks are practical), DES/RC4/Blowfish for encryption (deprecated due to small key or block sizes), RSA keys below 2048 bits, ECB mode (reveals patterns), and non-cryptographic random number generators. CWE-327: Use of a Broken or Risky Cryptographic Algorithm. CWE-328: Use of Weak Hash. CWE-326: Inadequate Encryption Strength.

**Incorrect (Python - MD5 hashing):**

```python
import hashlib

# Using MD5 for hashing
hashlib.md5(1)
hashlib.md5(1).hexdigest()
abc = str.replace(hashlib.md5("1"), "###")
print(hashlib.md5("1"))
foo = hashlib.md5(data, usedforsecurity=True)
```

**Incorrect (Python - SHA1 hashing):**

```python
import hashlib

# Using SHA1 for hashing
hashlib.sha1(1)
```

**Incorrect (Python - SHA1 with cryptography library):**

```python
from cryptography.hazmat.primitives import hashes

hashes.SHA1()
```

**Correct (Python - SHA256 hashing):**

```python
import hashlib

# Using secure hash algorithm
hashlib.sha256(1)

# With cryptography library
from cryptography.hazmat.primitives import hashes
hashes.SHA256()
hashes.SHA3_256()
```

**Incorrect (Python - DES cipher):**

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

**Incorrect (Python - RC4/ARC4 cipher):**

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

**Correct (Python - AES cipher):**

```python
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = b'Sixteen byte key'
cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

# With cryptography library
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
```

**Incorrect (Python - ECB mode):**

```python
from cryptography.hazmat.primitives.ciphers.modes import ECB

mode = ECB(iv)
```

**Correct (Python - CBC mode):**

```python
from cryptography.hazmat.primitives.ciphers.modes import CBC

mode = CBC(iv)
```

**Incorrect (Python - weak RSA key size):**

```python
from cryptography.hazmat.primitives.asymmetric import rsa

rsa.generate_private_key(public_exponent=65537,
                         key_size=1024,
                         backend=backends.default_backend())
```

**Correct (Python - strong RSA key size):**

```python
from cryptography.hazmat.primitives.asymmetric import rsa

rsa.generate_private_key(public_exponent=65537,
                         key_size=2048,
                         backend=backends.default_backend())
```

**Incorrect (Python - JWT none algorithm):**

```python
import jwt

encoded = jwt.encode({'some': 'payload'}, None, algorithm='none')
jwt.decode(encoded, None, algorithms=['none'])
```

**Correct (Python - JWT with proper algorithm):**

```python
import jwt

encoded = jwt.encode({'some': 'payload'}, secret_key, algorithm='HS256')
```

**Incorrect (Java - MD5 hashing):**

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

**Incorrect (Java - SHA1 hashing):**

```java
import java.security.MessageDigest;
import org.apache.commons.codec.digest.DigestUtils;

MessageDigest sha1Digest = MessageDigest.getInstance("SHA-1");
sha1Digest.update(password.getBytes());

byte[] hashValue = DigestUtils.getSha1Digest().digest(password.getBytes());

java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA1", "SUN");
```

**Correct (Java - SHA-512 hashing):**

```java
import java.security.MessageDigest;

MessageDigest sha512Digest = MessageDigest.getInstance("SHA-512");
sha512Digest.update(password.getBytes());
byte[] hashValue = sha512Digest.digest();
```

**Incorrect (Java - DES cipher):**

```java
Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
c.init(Cipher.ENCRYPT_MODE, k, iv);

Cipher c = Cipher.getInstance("DES");
```

**Incorrect (Java - RC4 cipher):**

```java
Cipher.getInstance("RC4");
useCipher(Cipher.getInstance("RC4"));
```

**Correct (Java - AES with GCM):**

```java
Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
c.init(Cipher.ENCRYPT_MODE, k, iv);

Cipher.getInstance("AES/CBC/PKCS7PADDING");
```

**Incorrect (Java - ECB mode):**

```java
Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
c.init(Cipher.ENCRYPT_MODE, k, iv);
byte[] cipherText = c.doFinal(plainText);
```

**Correct (Java - GCM mode):**

```java
Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
c.init(Cipher.ENCRYPT_MODE, k, iv);
byte[] cipherText = c.doFinal(plainText);
```

**Incorrect (Java - weak RSA key size):**

```java
import java.security.KeyPairGenerator;

KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
keyGen.initialize(512);
```

**Correct (Java - strong RSA key size):**

```java
import java.security.KeyPairGenerator;

KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
keyGen.initialize(2048);
```

**Incorrect (Java - weak random number generator):**

```java
float rand = new java.util.Random().nextFloat();
new java.util.Random().nextInt();
double value = java.lang.Math.random();
```

**Correct (Java - secure random):**

```java
double value2 = java.security.SecureRandom();
```

**Incorrect (Java - weak SSL context):**

```java
SSLContext ctx = SSLContext.getInstance("SSL");
SSLContext ctx = SSLContext.getInstance("TLS");
SSLContext ctx = SSLContext.getInstance("TLSv1");
SSLContext ctx = SSLContext.getInstance("SSLv3");
SSLContext ctx = SSLContext.getInstance("TLSv1.1");
```

**Correct (Java - secure TLS version):**

```java
SSLContext ctx = SSLContext.getInstance("TLSv1.2");
SSLContext ctx = SSLContext.getInstance("TLSv1.3");
```

**Incorrect (JavaScript - weak pseudo-random bytes):**

```javascript
// Using pseudoRandomBytes which is not cryptographically secure
crypto.pseudoRandomBytes
```

**Correct (JavaScript - secure random bytes):**

```javascript
// Using cryptographically secure random bytes
crypto.randomBytes
```

**Incorrect (JavaScript - MD5 for password hashing):**

```javascript
const crypto = require("crypto");

function ex1(user, pwtext) {
    digest = crypto.createHash("md5").update(pwtext).digest("hex");
    user.setPassword(digest);
}
```

**Correct (JavaScript - SHA256 for password hashing):**

```javascript
const crypto = require("crypto");

function ok1(user, pwtext) {
    digest = crypto.createHash("sha256").update(pwtext).digest("hex");
    user.setPassword(digest);
}
```

**Incorrect (JavaScript - JWT none algorithm):**

```javascript
const jose = require("jose");
const { JWK, JWT } = jose;
const token = JWT.verify('token-here', JWK.None);
```

**Correct (JavaScript - JWT with proper key):**

```javascript
const jose = require("jose");
const { JWK, JWT } = jose;
const token = JWT.verify('token-here', secretKey);
```

**Incorrect (Go - MD5 hashing):**

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

**Incorrect (Go - SHA1 hashing):**

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

**Incorrect (Go - DES cipher):**

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

**Incorrect (Go - RC4 cipher):**

```go
import "crypto/rc4"

func test_rc4() {
    key := []byte{1, 2, 3, 4, 5, 6, 7}
    c, err := rc4.NewCipher(key)
    dst := make([]byte, len(src))
    c.XORKeyStream(dst, src)
}
```

**Incorrect (Go - weak RSA key size):**

```go
import (
    "crypto/rand"
    "crypto/rsa"
)

pvk, err := rsa.GenerateKey(rand.Reader, 1024)
```

**Correct (Go - strong RSA key size):**

```go
import (
    "crypto/rand"
    "crypto/rsa"
)

pvk, err := rsa.GenerateKey(rand.Reader, 2048)
```

**Incorrect (Go - weak random number generator):**

```go
import mrand "math/rand"
import mrand "math/rand/v2"
```

**Correct (Go - secure random):**

```go
import "crypto/rand"

good, _ := rand.Read(nil)
```

**Incorrect (Ruby - MD5 hashing):**

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

**Incorrect (Ruby - SHA1 hashing):**

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

**Correct (Ruby - SHA256 hashing):**

```ruby
require 'digest'

digest = OpenSSL::Digest::SHA256.new
digest = OpenSSL::Digest::SHA256.hexdigest 'abc'
OpenSSL::HMAC.hexdigest("SHA256", key, data)

user.set_password Digest::SHA256.hexdigest pwtext
```

**Incorrect (Ruby - MD5 for password hashing):**

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

**Correct (Ruby - SHA256 for password hashing):**

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

**Incorrect (Ruby - weak RSA key size):**

```ruby
class Test
    $key = 512
    @key2 = 512

    OpenSSL::PKey::RSA.new(@key2)
    OpenSSL::PKey::RSA.new 512
    key = OpenSSL::PKey::RSA.new($key)
end
```

**Correct (Ruby - strong RSA key size):**

```ruby
class Test
    $pass1 = 2048
    @pass2 = 2048

    key = OpenSSL::PKey::RSA.new($pass1)
    key = OpenSSL::PKey::RSA.new(@pass2)
    key = OpenSSL::PKey::RSA.new(2048)
end
```

**Incorrect (Kotlin - MD5 hashing):**

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

**Incorrect (Kotlin - SHA1 hashing):**

```kotlin
import java.security.MessageDigest
import org.apache.commons.codec.digest.DigestUtils

var sha1Digest: MessageDigest = MessageDigest.getInstance("SHA1")
var sha1Digest: MessageDigest = MessageDigest.getInstance("SHA-1")
val hashValue: Array<Byte> = DigestUtils.getSha1Digest().digest(password.getBytes())
```

**Correct (Kotlin - SHA256 hashing):**

```kotlin
import java.security.MessageDigest

val sha256Digest: MessageDigest = MessageDigest.getInstance("SHA256")
sha256Digest.update(password.getBytes())
val hashValue: ByteArray = sha256Digest.digest()
```

**Incorrect (Kotlin - ECB mode):**

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

**Correct (Kotlin - GCM mode):**

```kotlin
class ECBCipher {
  public fun noEcbCipher(): Void {
    var c = Cipher.getInstance("AES/GCM/NoPadding")
    c.init(Cipher.ENCRYPT_MODE, k, iv)
    val cipherText = c.doFinal(plainText)
  }
}
```

**Incorrect (Kotlin - weak RSA key size):**

```kotlin
import java.security.KeyPairGenerator

fun rsaWeak(): Void {
    val keyGen: KeyPairGenerator = KeyPairGenerator.getInstance("RSA")
    keyGen.initialize(512)
}
```

**Correct (Kotlin - strong RSA key size):**

```kotlin
import java.security.KeyPairGenerator

fun rsaOK(): Void {
    val keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
}
```

**Incorrect (C# - DES or RC2 cipher):**

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

**Correct (C# - AES cipher):**

```csharp
using System.Security.Cryptography;

public void CreateAes1() {
    var key = Aes.Create();
}

public void CreateAes2() {
    var key = Aes.Create("ImplementationName");
}
```

**Incorrect (C# - ECB mode):**

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

**Correct (C# - CBC mode):**

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

**Incorrect (C# - weak RNG for key generation):**

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

**Correct (C# - secure RNG for key generation):**

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

**Incorrect (PHP - weak crypto functions):**

```php
<?php

$hashed_password = crypt('mypassword');
$hashed_password = md5('mypassword');
$hashed_password = md5_file('filename.txt');
$hashed_password = sha1('mypassword');
$hashed_password = sha1_file('filename.txt');
$hashed_password = str_rot13('totally secure');
```

**Correct (PHP - secure hashing):**

```php
<?php

$hashed_password = sodium_crypto_generichash('mypassword');
```

**Incorrect (PHP - MD5 for password hashing):**

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

**Correct (PHP - SHA256 for password hashing):**

```php
<?php

function okTest1($value) {
    $pass = hash('sha256', $value);
    $user->setPassword($pass);
}
```

**Incorrect (Swift - insecure random number generators):**

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

**Correct (Swift - SecCopyRandomBytes):**

```swift
import Security

var randomBytes = [UInt8](repeating: 0, count: 16)
let status = SecRandomCopyBytes(kSecRandomDefault, randomBytes.count, &randomBytes)
```

**Incorrect (Scala - insecure random number generator):**

```scala
class Test {
  def bad1() {
    import scala.util.Random

    val result = Seq.fill(16)(Random.nextInt)
    return result.map("%02x" format _).mkString
  }
}
```

**Correct (Scala - SecureRandom):**

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

**Incorrect (Scala - RSA without OAEP padding):**

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

**Correct (Scala - RSA with OAEP padding):**

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

**Incorrect (Rust - insecure hash algorithms):**

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

**Correct (Rust - SHA256 hashing):**

```rust
use sha2::{Sha256};

let mut hasher = Sha256::new();
```
