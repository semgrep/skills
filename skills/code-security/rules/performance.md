---
title: Performance Best Practices
impact: LOW
---

# Performance Best Practices

This document covers performance optimizations and best practices to write efficient code. These rules identify patterns that cause unnecessary computational overhead, extra database queries, memory inefficiency, or render bottlenecks.

## Table of Contents

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

## Python

### Django

#### Access Foreign Keys Directly

You should use `ITEM.user_id` rather than `ITEM.user.id` to prevent running an extra query. Accessing `.user.id` causes Django to fetch the entire related User object just to get the ID, when the foreign key ID is already available on the model.

Reference: [Django Documentation - Use foreign key values directly](https://docs.djangoproject.com/en/5.0/topics/db/optimization/#use-foreign-key-values-directly)

**INCORRECT** - Extra query to fetch related object:
```python
from django.http import HttpResponse
from models import User


def other():
    # ruleid: access-foreign-keys
    print(User.user.id)
```

**CORRECT** - Use request.user.id which is already loaded:
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

### SQLAlchemy

#### Use count() Instead of len(all())

Using `QUERY.count()` instead of `len(QUERY.all())` sends less data to the client since the SQLAlchemy method is performed server-side. The `len(all())` approach fetches all records into memory just to count them.

**INCORRECT** - Fetches all records into memory:
```python
# ruleid:len-all-count
len(persons.all())
```

**CORRECT** - Count performed server-side:
```python
# ok:len-all-count
persons.count()
```

#### Batch Database Operations

Rather than adding one element at a time, consider batch loading to improve performance. Each individual `db.session.add()` in a loop can trigger separate database operations.

**INCORRECT** - Adding one at a time in a loop:
```python
# ruleid:batch-import
for song in songs:
    db.session.add(song)
```

**CORRECT** - Batch add all at once:
```python
# ok:batch-import
db.session.add_all(songs)
```

---

## Ruby

### Rails

#### Add Indexes for Foreign Keys

Foreign key columns (columns ending in `_id`) should have database indexes to improve query performance. Without an index, queries filtering or joining on foreign keys require full table scans.

Reference: [Why Your Database Needs Indexes](https://archive.is/i7SLO)

**INCORRECT** - Foreign key column without index:
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

**CORRECT** - Add index immediately after adding foreign key column:
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

## C

#### Use strcmp for String Comparison

Using `==` on `char*` performs pointer comparison, not string content comparison. Use `strcmp` instead to compare the actual string values.

**INCORRECT** - Pointer comparison instead of string comparison:
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

**CORRECT** - Use strcmp for string content comparison:
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

## C#

#### Use Structured Logging

String interpolation in log messages obscures the distinction between variables and the log message. Use structured logging instead, where the variables are passed as additional arguments and the interpolation is performed by the logging library. This reduces the possibility of log injection and makes it easier to search through logs.

CWE: CWE-117: Improper Output Neutralization for Logs

References:
- [NLog - How to use structured logging](https://github.com/NLog/NLog/wiki/How-to-use-structured-logging)
- [Benefits of Structured Logging vs Basic Logging](https://softwareengineering.stackexchange.com/questions/312197/benefits-of-structured-logging-vs-basic-logging)

**INCORRECT** - String interpolation in log messages:
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

**CORRECT** - Pass variables as structured arguments:
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

## TypeScript/JavaScript

### React

#### Define Styled Components at Module Level

By declaring a styled component inside the render method of a React component, you are dynamically creating a new component on every render. This means that React will have to discard and re-calculate that part of the DOM subtree on each subsequent render, instead of just calculating the difference of what changed between them. This leads to performance bottlenecks and unpredictable behavior.

Reference: [styled-components FAQ - Why should I avoid declaring styled-components in the render method](https://styled-components.com/docs/faqs#why-should-i-avoid-declaring-styled-components-in-the-render-method)

**INCORRECT** - Styled component declared inside function/class:
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

**CORRECT** - Styled component declared at module level:
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

## OCaml

#### Use Empty List Check Instead of List.length

Checking `List.length xs = 0` or `List.length xs > 0` is inefficient. `List.length` traverses the entire list to count elements. For checking if a list is empty or non-empty, compare directly against `[]`.

**INCORRECT** - Using List.length for empty check:
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

**CORRECT** - Compare directly against empty list:
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
