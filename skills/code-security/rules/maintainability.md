---
title: Code Maintainability
impact: LOW
---

# Code Maintainability

This document covers maintainability rules that help identify code patterns that may lead to confusion, technical debt, or unexpected behavior. These rules focus on code organization, deprecated APIs, dead code, and shadow AI/LLM usage detection.

## Shadow AI / LLM Usage Detection

These rules help organizations track and govern the use of AI and LLM services in their codebase. Detecting "shadow AI" usage is important for compliance, security auditing, and understanding AI dependencies.

### Go

#### detect-openai

**Severity:** INFO
**Message:** Possibly found usage of AI: OpenAI

Detects usage of OpenAI APIs in Go code.

**References:**
- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code (usage detected):**

```go
package gpt

// ruleid: detect-openai
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	gogpt "github.com/sashabaranov/go-openai"
)

var ErrTooManyRequests = errors.New("too many requests")

type Config struct {
	Keys    []string
	Timeout time.Duration
}

type Client struct {
	id int
	*gogpt.Client
}
```

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

#### detect-gemini

**Severity:** INFO
**Message:** Possibly found usage of AI: Gemini

Detects usage of Google Gemini APIs in Go code.

**References:**
- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code (usage detected):**

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

### Python

#### detect-anthropic

**Severity:** INFO
**Message:** Possibly found usage of AI: Anthropic

Detects usage of Anthropic Claude APIs in Python code.

**References:**
- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code (usage detected):**

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

#### detect-openai

**Severity:** INFO
**Message:** Possibly found usage of AI: OpenAI

Detects usage of OpenAI APIs in Python code.

**References:**
- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code (usage detected):**

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

#### detect-gemini

**Severity:** INFO
**Message:** Possibly found usage of AI: Gemini

Detects usage of Google Gemini APIs in Python code.

**References:**
- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code (usage detected):**

```python
# ruleid: detect-gemini
import google.generativeai as genai
import os

genai.configure(api_key=os.environ["API_KEY"])

model = genai.GenerativeModel('gemini-1.5-flash')
```

---

#### detect-mistral

**Severity:** INFO
**Message:** Possibly found usage of AI: Mistral

Detects usage of Mistral APIs in Python code.

**References:**
- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code (usage detected):**

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

#### detect-langchain

**Severity:** INFO
**Message:** Possibly found usage of AI tooling: LangChain

Detects usage of LangChain framework in Python code.

**References:**
- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code (usage detected):**

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

#### detect-tensorflow

**Severity:** INFO
**Message:** Possibly found usage of AI tooling: Tensorflow

Detects usage of TensorFlow in Python code.

**References:**
- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code (usage detected):**

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

#### detect-pytorch

**Severity:** INFO
**Message:** Possibly found usage of AI tooling: PyTorch

Detects usage of PyTorch in Python code.

**References:**
- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code (usage detected):**

```python
# ruleid: detect-pytorch
import torch
# ruleid: detect-pytorch
x = torch.rand(5, 3)
print(x)
```

---

#### detect-huggingface

**Severity:** INFO
**Message:** Possibly found usage of AI: HuggingFace

Detects usage of HuggingFace Hub in Python code.

**References:**
- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code (usage detected):**

```python
# ruleid: detect-huggingface
from huggingface_hub import HfApi

api = HfApi()
api.create_repo(repo_id="super-cool-model")
```

---

### TypeScript / JavaScript

#### detect-openai

**Severity:** INFO
**Message:** Possibly found usage of AI: OpenAI

Detects usage of OpenAI APIs in TypeScript/JavaScript code.

**References:**
- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code (usage detected):**

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

#### detect-anthropic

**Severity:** INFO
**Message:** Possibly found usage of AI: Anthropic

Detects usage of Anthropic Claude APIs in TypeScript/JavaScript code.

**References:**
- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code (usage detected):**

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

#### detect-gemini

**Severity:** INFO
**Message:** Possibly found usage of AI: Gemini

Detects usage of Google Gemini APIs in TypeScript/JavaScript code.

**References:**
- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code (usage detected):**

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

#### detect-mistral

**Severity:** INFO
**Message:** Possibly found usage of AI: Mistral

Detects usage of Mistral APIs in TypeScript/JavaScript code.

**References:**
- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code (usage detected):**

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

#### detect-vercel-ai

**Severity:** INFO
**Message:** Possibly found usage of AI: VercelAI

Detects usage of Vercel AI SDK in TypeScript/JavaScript code.

**References:**
- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code (usage detected):**

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

#### detect-promptfoo

**Severity:** INFO
**Message:** Possibly found usage of AI tooling: promptfoo

Detects usage of promptfoo LLM evaluation framework in TypeScript/JavaScript code.

**References:**
- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code (usage detected):**

```typescript
// ruleid: detect-promptfoo
import promptfoo from 'promptfoo';

// ruleid: detect-promptfoo
const results = await promptfoo.evaluate(testSuite, options);
```

---

### Kotlin

#### detect-gemini

**Severity:** INFO
**Message:** Possibly found usage of AI: Gemini

Detects usage of Google Gemini APIs in Kotlin code.

**References:**
- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code (usage detected):**

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

### Swift

#### detect-gemini

**Severity:** INFO
**Message:** Possibly found usage of AI: Gemini

Detects usage of Google Gemini APIs in Swift code.

**References:**
- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code (usage detected):**

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

#### detect-apple-core-ml

**Severity:** INFO
**Message:** Possibly found usage of AI: Apple CoreML

Detects usage of Apple CoreML in Swift code.

**References:**
- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code (usage detected):**

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

### C#

#### detect-openai

**Severity:** INFO
**Message:** Possibly found usage of AI: OpenAI

Detects usage of OpenAI APIs in C# code.

**References:**
- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code (usage detected):**

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

### Generic (Any Language)

#### detect-generic-ai-api

**Severity:** INFO
**Message:** Possibly found usage of AI: HTTP Request

Detects direct HTTP requests to AI API endpoints.

**References:**
- https://semgrep.dev/blog/2024/detecting-shadow-ai

**Flagged code (usage detected):**

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

## Python Code Organization

### Django URL Configuration

#### conflicting-path-assignment

**Severity:** ERROR
**Message:** The path for `$URL` is assigned once to view `$VIEW` and once to `$DIFFERENT_VIEW`, which can lead to unexpected behavior. Verify what the intended target view is and delete the other route.

This rule detects when the same URL path is mapped to different views, which causes routing confusion.

**Incorrect code (hard to maintain):**

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

**Correct code (maintainable):**

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

#### duplicate-path-assignment-different-names

**Severity:** WARNING
**Message:** path for `$URL` is assigned twice with different names

This rule detects when the same URL path and view are registered with different names, which can cause confusion.

**Incorrect code (hard to maintain):**

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

#### duplicate-name-assignment

**Severity:** ERROR
**Message:** The name `$NAME` is used for both `$URL` and `$OTHER_URL`, which can lead to unexpected behavior when using URL reversing. Pick a unique name for each path.

**References:**
- https://docs.djangoproject.com/en/3.2/topics/http/urls/#naming-url-patterns

**Incorrect code (hard to maintain):**

```python
from django.urls import path

# ruleid: duplicate-name-assignment
urlpatterns = [
    path('path/to/view', views.example_view, name="test123"),
    path('path/to/other/view', views.other_view, name="test123"),
]
```

---

### Useless If Statements

#### useless-if-conditional

**Severity:** WARNING
**Message:** if block checks for the same condition on both branches (`$X`)

This rule detects if-elif chains where the same condition is checked multiple times.

**References:**
- https://docs.python.org/3/tutorial/controlflow.html

**Incorrect code (hard to maintain):**

```python
a, b, c = 1

# ruleid: useless-if-conditional
if a:
    print('1')
elif a:
    print('2')
```

**Correct code (maintainable):**

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

#### useless-if-body

**Severity:** WARNING
**Message:** Useless if statement; both blocks have the same body

This rule detects if-else statements where both branches execute identical code.

**References:**
- https://docs.python.org/3/tutorial/controlflow.html

**Incorrect code (hard to maintain):**

```python
# ruleid: useless-if-body
if a:
    print('1')
else:
    print('1')
```

---

### Return Statements

#### return-not-in-function

**Severity:** WARNING
**Message:** `return` only makes sense inside a function

This rule detects return statements that appear outside of any function definition.

**Incorrect code (hard to maintain):**

```python
def resolve(key: str) -> str:
    key = os.path.join(path, "keys", key)
    # ok: code-after-unconditional-return
    return key, key

# ruleid: return-not-in-function
return (a, b)
```

**Correct code (maintainable):**

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

### Useless Assignments

#### useless-assignment-keyed

**Severity:** INFO
**Message:** key `$Y` in `$X` is assigned twice; the first assignment is useless

This rule detects consecutive assignments to the same dictionary key, where the first assignment is immediately overwritten.

**Incorrect code (hard to maintain):**

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

**Correct code (maintainable):**

```python
# ok for this rule
x = 5
x = 5

x = y
x = y()

y() = y()
```

---

### Dead Code

#### useless-inner-function

**Severity:** ERROR
**Message:** function `$FF` is defined inside a function but never used

This rule detects inner functions that are defined but never called or returned.

**Incorrect code (hard to maintain):**

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

**Correct code (maintainable):**

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

### Function Call Issues

#### is-function-without-parentheses

**Severity:** WARNING
**Message:** Is "$FUNC" a function or an attribute? If it is a function, you may have meant $X.$FUNC() because $X.$FUNC is always true.

This rule detects when a method starting with `is_` is referenced without being called, which is usually a bug.

**Incorrect code (hard to maintain):**

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

**Correct code (maintainable):**

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

## Deprecated APIs

### Flask Deprecated APIs

#### flask-deprecated-apis

**Severity:** WARNING
**Message:** deprecated Flask API

This rule detects usage of deprecated Flask APIs that should be replaced with modern alternatives.

**Incorrect code (hard to maintain):**

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

**Correct code (maintainable):**

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

## Go Code Organization

### Useless If Statements

#### useless-if-conditional

**Severity:** WARNING
**Message:** Detected an if block that checks for the same condition on both branches (`$X`). The second condition check is useless as it is the same as the first, and therefore can be removed from the code.

**Incorrect code (hard to maintain):**

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

**Correct code (maintainable):**

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
