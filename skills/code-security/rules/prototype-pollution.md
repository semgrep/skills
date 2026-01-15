---
title: Prevent Prototype Pollution
impact: HIGH
impactDescription: Attackers can modify object prototypes to inject malicious properties, leading to privilege escalation, denial of service, or remote code execution
tags: security, prototype-pollution, mass-assignment, cwe-915
---

## Prevent Prototype Pollution

Prototype pollution is a vulnerability that occurs when an attacker can modify the prototype of a base object, such as `Object.prototype` in JavaScript. By adding or modifying attributes of an object prototype, it is possible to create attributes that exist on every object, or replace critical attributes with malicious ones (such as `hasOwnProperty`, `toString`, or `valueOf`).

This vulnerability class also includes mass assignment attacks in other languages, where attackers can set arbitrary attributes on models by manipulating request parameters.

**Possible mitigations:**
- Freeze the object prototype using `Object.freeze(Object.prototype)`
- Use objects without prototypes via `Object.create(null)`
- Block modifications to attributes that resolve to object prototype (`__proto__`, `constructor`)
- Use `Map` instead of plain objects for key-value storage
- In web frameworks, use strong parameter allowlisting to control which attributes can be set

---

### Language: JavaScript / TypeScript

**Incorrect (vulnerable to prototype pollution via dynamic assignment):**
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

**Correct (validate against dangerous keys):**
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

**Correct (use static keys):**
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

**Incorrect (prototype pollution in loops):**
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

**Correct (use numeric index in loops):**
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

**Incorrect (mass assignment via Object.assign in Express):**
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

**Correct (use safe data sources in Object.assign):**
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

### Language: Ruby (Rails)

**Incorrect (permitting dangerous attributes):**
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

**Correct (permit only safe attributes):**
```ruby
#ok: check-permit-attributes-high
params.permit(:some_safe_property)

#ok: check-permit-attributes-medium
params.permit(:some_safe_property)
```

**Incorrect (dangerous attr_accessible and permit usage):**
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

**Correct (safe attr_accessible and permit usage):**
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

**Incorrect (create_with bypasses strong parameters):**
```ruby
def bad_create_with
    # ruleid: create-with
    user.blog_posts.create_with(params[:blog_post]).create
end
```

**Correct (use permit with create_with):**
```ruby
def create
    # ok: create-with
    user.blog_posts.create(params[:blog_post])
    # ok: create-with
    user.blog_posts.create_with(params[:blog_post].permit(:title, :body, :etc)).create
end
```

**Incorrect (mass assignment without attr_accessible):**
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

**Correct (use attr_accessible before mass assignment):**
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

**Incorrect (disabling mass assignment protection):**
```ruby
# ruleid:mass-assignment-protection-disabled
User.new(params[:user], :without_protection => true)
```

**Correct (do not disable protection):**
```ruby
# ok:mass-assignment-protection-disabled
User.new(params[:user])
```

**Incorrect (model without attr_accessible):**
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

**Correct (model with attr_accessible):**
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

### Language: Python (Django)

**Incorrect (mass assignment using **request):**
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

**Correct (explicitly assign each field):**
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

### Language: PHP (Laravel)

**Incorrect (empty $guarded allows mass assignment):**
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

**Correct (use $fillable to explicitly allowlist attributes):**
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

### Language: C# (.NET)

**Incorrect (model binding without [Bind] attribute):**
```csharp
using Microsoft.AspNetCore.Mvc;

public IActionResult Create(UserModel model)
{
    context.SaveChanges();
    // ruleid: mass-assignment
    return View("Index", model);
}
```

**Correct (use [Bind] attribute to allowlist properties):**
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
