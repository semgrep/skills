---
title: Prevent Cross-Site Request Forgery
impact: HIGH
impactDescription: Attackers can force authenticated users to perform unwanted actions, potentially modifying data, transferring funds, or changing account settings
tags: security, csrf, cwe-352, owasp-a01
---

## Prevent Cross-Site Request Forgery

Cross-Site Request Forgery (CSRF) is an attack that forces authenticated users to execute unwanted actions on a web application. When a user is authenticated, their browser automatically includes session cookies with requests. Attackers can craft malicious pages that trigger requests to vulnerable applications, causing actions to be performed without the user's consent. CSRF attacks can result in unauthorized fund transfers, email address changes, password changes, or any other state-changing operation.

---

### Language: Ruby / Rails

#### Skip Forgery Protection

**Incorrect (disables CSRF protection entirely):**
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

**Correct (CSRF protection enabled by default):**
```ruby
class ApplicationController2 < ActionController::Base
    # ok: rails-skip-forgery-protection
  end
```

**References:**
- [Rails ActionController RequestForgeryProtection](https://api.rubyonrails.org/classes/ActionController/RequestForgeryProtection/ClassMethods.html#method-i-skip_forgery_protection)

---

#### Missing CSRF Protection

**Incorrect (controller without protect_from_forgery):**
```ruby
# ruleid:missing-csrf-protection
class DangerousController < ActionController::Base

  puts "do more stuff"

end
```

**Correct (controller with protect_from_forgery):**
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

### Language: JavaScript / Express

#### CSRF Before Method Override

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

#### Missing CSRF Middleware in Express

**Incorrect (Express app without csurf middleware):**
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

**Correct (include csurf or csrf middleware):**
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

### Language: C# / ASP.NET MVC

#### Missing Anti-Forgery Token Validation

**Incorrect (state-changing methods without ValidateAntiForgeryToken):**
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

**Correct (add ValidateAntiForgeryToken or strict Content-Type checking):**
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

### Language: Java / Spring

#### Unrestricted Request Mapping

**Incorrect (RequestMapping without specifying HTTP method):**
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

**Correct (specify HTTP method in RequestMapping):**
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

#### Spring CSRF Disabled

**Incorrect (explicitly disabling CSRF protection):**
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

**Correct (CSRF protection enabled by default):**
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

### Language: Python / Django

#### CSRF Exempt Decorator

**Incorrect (using @csrf_exempt decorator):**
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

**Correct (remove csrf_exempt decorator):**
```python
from django.http import HttpResponse

# ok: no-csrf-exempt
def my_view(request):
    return HttpResponse('Hello world')
```

**References:**
- [OWASP Top 10 A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control)

---

### Language: Python / Pyramid

#### CSRF Check Disabled Globally

**Incorrect (disabling CSRF checks globally):**
```python
from pyramid.csrf import CookieCSRFStoragePolicy


def includeme_bad(config):
    config.set_csrf_storage_policy(CookieCSRFStoragePolicy())
    # ruleid: pyramid-csrf-check-disabled-globally
    config.set_default_csrf_options(require_csrf=False)
```

**Correct (enable CSRF checks):**
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

#### CSRF Check Disabled Per View

**Incorrect (disabling CSRF for specific view):**
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

**Correct (enable CSRF for view):**
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

#### CSRF Origin Check Disabled

**Incorrect (disabling origin check for CSRF token):**
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

**Correct (enable origin check):**
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

#### CSRF Origin Check Disabled Globally

**Incorrect (disabling origin check globally):**
```python
from pyramid.csrf import CookieCSRFStoragePolicy


def includeme_bad(config):
    config.set_csrf_storage_policy(CookieCSRFStoragePolicy())
    # ruleid: pyramid-csrf-origin-check-disabled-globally
    config.set_default_csrf_options(check_origin=False)
```

**Correct (enable origin check globally):**
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

### Language: Python / Flask

#### Flask-WTF CSRF Disabled

**Incorrect (disabling WTF_CSRF_ENABLED):**
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

**Correct (enable CSRF or only disable for testing):**
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

### Language: PHP / Symfony

#### Symfony CSRF Protection Disabled

**Incorrect (disabling csrf_protection in forms or configuration):**
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

**Correct (enable CSRF protection):**
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

### Language: PHP / WordPress

#### WordPress CSRF Audit - Useless Check

**Incorrect (check_ajax_referer with false third argument):**
```php
<?php

// ruleid: wp-csrf-audit
check_ajax_referer( 'wpforms-admin', 'nonce', false );
```

**Correct (check_ajax_referer with die enabled):**
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

### Language: Go / Gorilla WebSocket

#### WebSocket Missing Origin Check

**Incorrect (WebSocket upgrade without CheckOrigin):**
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

**Correct (WebSocket upgrade with CheckOrigin):**
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
