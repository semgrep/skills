---
title: Prevent XML External Entity (XXE) Injection
impact: CRITICAL
impactDescription: File disclosure, SSRF, denial of service
tags: security, xxe, cwe-611
---

## Prevent XML External Entity (XXE) Injection

XXE occurs when XML input containing a reference to an external entity is processed by a weakly configured XML parser. Attackers can access local files, perform SSRF, or cause DoS.

---

### Language: Java

#### XMLInputFactory - External Entities Enabled

**Incorrect (vulnerable to XXE):**
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

**Correct (XXE disabled):**
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

#### XMLInputFactory - Possible XXE (External Entities Not Explicitly Disabled)

**Incorrect (vulnerable to XXE):**
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

**Correct (XXE disabled):**
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

#### DocumentBuilderFactory - Disallow DOCTYPE Declaration Missing

**Incorrect (vulnerable to XXE):**
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

**Correct (XXE disabled):**
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

#### DocumentBuilderFactory - Disallow DOCTYPE Declaration False

**Incorrect (vulnerable to XXE):**
```java
class BadDocumentBuilderFactory{
    public void BadXMLInputFactory() throws  ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        //ruleid:documentbuilderfactory-disallow-doctype-decl-false
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
    }
}
```

**Correct (XXE disabled):**
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

#### DocumentBuilderFactory/SAXParserFactory - External General Entities Enabled

**Incorrect (vulnerable to XXE):**
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

**Correct (XXE disabled):**
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

#### DocumentBuilderFactory/SAXParserFactory - External Parameter Entities Enabled

**Incorrect (vulnerable to XXE):**
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

**Correct (XXE disabled):**
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

#### SAXParserFactory - Disallow DOCTYPE Declaration Missing

**Incorrect (vulnerable to XXE):**
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

**Correct (XXE disabled):**
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

#### TransformerFactory - DTDs Not Disabled

**Incorrect (vulnerable to XXE):**
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

**Correct (XXE disabled):**
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

#### XMLDecoder - Unsafe Deserialization

**Incorrect (vulnerable to XXE):**
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

**Correct (safe usage):**
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

### Language: JavaScript/TypeScript

#### xml2json - XXE via User Input

**Incorrect (vulnerable to XXE):**
```javascript
function test1(body) {
    // ruleid: xml2json-xxe
    const xml2json = require('xml2json')
    const result = xml2json.toJson(body, { object: true, arrayNotation: true })
    return result
}
```

**Correct (safe usage):**
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

#### node-expat - XXE via User Input

**Incorrect (vulnerable to XXE):**
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

**Correct (safe usage):**
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

#### sax - Custom DTD Entity Handling

**Incorrect (vulnerable to XXE):**
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

**Correct (safe usage):**
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

#### Express with xml2json - XXE via Request Data

**Incorrect (vulnerable to XXE):**
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

**Correct (safe usage):**
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

#### Express with node-expat - XXE via Request Data

**Incorrect (vulnerable to XXE):**
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

**Correct (safe usage):**
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

#### libxmljs/libxmljs2 - noent Option Enabled

**Incorrect (vulnerable to XXE):**
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

**Correct (XXE disabled):**
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

#### libxml parseXml with noent in VM Context

**Incorrect (vulnerable to XXE):**
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

**Correct (XXE disabled):**
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

#### Express xml2json - XXE via Request Events

**Incorrect (vulnerable to XXE):**
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

**Correct (safe usage):**
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

### Language: Python

#### Native xml Library Usage

**Incorrect (vulnerable to XXE):**
```python
def bad():
    # ruleid: use-defused-xml
    import xml
    # ruleid: use-defused-xml
    from xml.etree import ElementTree
    tree = ElementTree.parse('country_data.xml')
    root = tree.getroot()
```

**Correct (safe usage):**
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

#### xml.etree.ElementTree.parse with User Input

**Incorrect (vulnerable to XXE):**
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

**Correct (safe usage):**
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

#### Twilio TwiML Injection

**Incorrect (vulnerable to XML injection):**
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

**Correct (safe usage):**
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

### Language: Ruby (Rails)

#### LibXML Backend

**Incorrect (vulnerable to XXE):**
```ruby
require 'xml'
require 'libxml'

# ruleid: libxml-backend
ActiveSupport::XmlMini.backend = 'LibXML'
```

**Correct (safe usage):**
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

#### XML External Entities Explicitly Enabled

**Incorrect (vulnerable to XXE):**
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

**Correct (XXE disabled):**
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

### Language: C#/.NET

#### XmlDocument with Unsafe XmlResolver

**Incorrect (vulnerable to XXE):**
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

**Correct (XXE disabled):**
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

#### XmlReaderSettings with DtdProcessing.Parse

**Incorrect (vulnerable to XXE):**
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

**Correct (XXE disabled):**
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

#### XmlTextReader Unsafe Defaults

**Incorrect (vulnerable to XXE):**
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

**Correct (XXE disabled):**
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

### Language: Scala

#### XMLInputFactory - DTD Enabled

**Incorrect (vulnerable to XXE):**
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

**Correct (XXE disabled):**
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

#### SAXReader/SAXParserFactory - DTD Enabled

**Incorrect (vulnerable to XXE):**
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

**Correct (XXE disabled):**
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

#### DocumentBuilderFactory - DTD Enabled

**Incorrect (vulnerable to XXE):**
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

**Correct (XXE disabled):**
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

### Language: Go

#### libxml2 - External Entities Enabled

**Incorrect (vulnerable to XXE):**
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

**Correct (XXE disabled):**
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
