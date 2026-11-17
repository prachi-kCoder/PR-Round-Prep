# Cross-Site Scripting (XSS) -- PR Review Practice

**10 interview-style code-review questions with vulnerable code,
expected behavior, findings, and secure fixes**

> XSS is primarily a browser-side vulnerability. These exercises use
> HTML and JavaScript for rendering examples, with backend concepts
> where relevant. They are representative PR-review practice questions,
> not verified AWS assessment questions.

------------------------------------------------------------------------

## Question 1 -- Unsafe `innerHTML` Rendering

**Task:** Identify the security issue.

### Vulnerable code

``` html
<div id="comment"></div>
<script>
const userInput = '<img src=x onerror="alert(1)">';
document.getElementById("comment").innerHTML = userInput;
</script>
```

**Expected behavior:** The browser parses the string as HTML. The image
URL fails to load and its event handler may execute JavaScript.

**Finding:** Untrusted input is passed to the HTML parsing sink
`innerHTML`, creating a DOM XSS risk.

### Secure fix

``` html
<div id="comment"></div>
<script>
const userInput = '<img src=x onerror="alert(1)">';
document.getElementById("comment").textContent = userInput;
</script>
```

**Why it works:** `textContent` inserts the value as text instead of
parsing it as HTML. The markup is displayed literally.

------------------------------------------------------------------------

## Question 2 -- `document.write()` with User Input

**Task:** What is the security problem?

### Vulnerable code

``` html
<script>
const name = new URLSearchParams(location.search).get("name") || "";
document.write("Welcome, " + name);
</script>
```

**Finding:** `document.write()` parses the supplied string as HTML. If
an attacker controls the `name` parameter, they may inject markup or
executable event handlers.

**Expected behavior:** Ordinary input such as `Prachi` displays
`Welcome, Prachi`. Crafted HTML input may be interpreted as markup.

### Secure fix

``` html
<p id="welcome"></p>
<script>
const name = new URLSearchParams(location.search).get("name") || "";
document.getElementById("welcome").textContent =
    "Welcome, " + name;
</script>
```

**Why it works:** The value is inserted as text, not parsed HTML. Avoid
`document.write()` for untrusted data.

------------------------------------------------------------------------

## Question 3 -- Reflected XSS Through a URL Parameter

**Task:** Identify the vulnerability in this search page.

### Vulnerable code

``` html
<div id="results"></div>
<script>
const params = new URLSearchParams(location.search);
const search = params.get("q") || "";

document.getElementById("results").innerHTML =
    "You searched for: " + search;
</script>
```

**Finding:** Data from the URL is reflected into an HTML parsing sink
without context-appropriate encoding. This is a reflected/DOM XSS risk.

**Expected behavior:** A normal search term is displayed. HTML supplied
as the `q` parameter may be parsed as markup.

### Secure fix

``` html
<div id="results"></div>
<script>
const params = new URLSearchParams(location.search);
const search = params.get("q") || "";

document.getElementById("results").textContent =
    "You searched for: " + search;
</script>
```

**Why it works:** The query value is rendered as text. For
server-rendered HTML, use the framework's context-aware escaping rather
than manually concatenating raw input.

------------------------------------------------------------------------

## Question 4 -- Stored XSS Through Database Comments

**Task:** A comment is saved in a database and later displayed to every
visitor. What should the reviewer flag?

### Vulnerable rendering code

``` javascript
function renderComment(comment) {
    const item = document.createElement("div");
    item.innerHTML = comment;
    document.querySelector("#comments").appendChild(item);
}
```

Assume `comment` is retrieved from a database and may contain
attacker-supplied content.

**Finding:** Persisted user content is inserted as HTML. If it contains
executable markup, it can affect every user who views the comment. This
is stored (persistent) XSS.

**Important:** Storing a value in a database does not make it trusted.

### Secure fix for plain-text comments

``` javascript
function renderComment(comment) {
    const item = document.createElement("div");
    item.textContent = comment;
    document.querySelector("#comments").appendChild(item);
}
```

**Why it works:** Comments are treated as text. If the product genuinely
supports rich HTML, sanitize it with a maintained HTML sanitizer and a
restrictive allowlist before insertion.

------------------------------------------------------------------------

## Question 5 -- DOM-Based XSS Through `location.hash`

**Task:** Identify the unsafe source and sink.

### Vulnerable code

``` javascript
const value = location.hash.substring(1);
document.getElementById("output").innerHTML = value;
```

**Finding:** - Source: `location.hash`, which can be
attacker-controlled. - Sink: `innerHTML`, which parses strings as HTML.

This is a DOM-based XSS risk because client-side JavaScript moves
untrusted data into an unsafe DOM sink.

### Secure fix

``` javascript
const value = location.hash.substring(1);
document.getElementById("output").textContent = value;
```

**Why it works:** The value is rendered as text. URL decoding or input
validation alone would not make an HTML parsing sink safe.

------------------------------------------------------------------------

## Question 6 -- Unsafe HTML Attributes and Event Handlers

**Task:** Why is this code dangerous?

### Vulnerable code

``` javascript
function showImage(userUrl) {
    document.getElementById("preview").innerHTML =
        '<img src="' + userUrl + '">';
}
```

**Finding:** Untrusted data is concatenated into an HTML attribute
inside a string that is parsed by `innerHTML`. An attacker may break out
of the attribute context and inject additional markup or event handlers.

### Secure fix

``` javascript
function showImage(userUrl) {
    const image = document.createElement("img");

    const parsed = new URL(userUrl, window.location.origin);

    if (parsed.protocol !== "https:" ||
        parsed.origin !== window.location.origin) {
        throw new Error("Invalid image URL");
    }

    image.src = parsed.href;

    const preview = document.getElementById("preview");
    preview.replaceChildren(image);
}
```

**Why it works:** The image is created through DOM APIs instead of
building an HTML string. The example also restricts image URLs to HTTPS
on the same origin. Adapt the URL allowlist to the application's trusted
image hosts.

------------------------------------------------------------------------

## Question 7 -- Missing Output Encoding in Server-Side Templates

**Task:** A C++ backend creates an HTML response using a user-supplied
display name.

### Vulnerable code

``` cpp
#include <string>
using namespace std;

string makePage(const string& displayName) {
    return "<html><body><h1>Welcome, " +
           displayName +
           "</h1></body></html>";
}
```

**Finding:** The backend inserts untrusted input directly into an HTML
text context. If the response is served as HTML, attacker-supplied
markup may be interpreted by the browser.

### Secure fix

``` cpp
#include <string>
using namespace std;

string escapeHtmlText(const string& input) {
    string output;

    for (char c : input) {
        switch (c) {
            case '&': output += "&amp;"; break;
            case '<': output += "&lt;"; break;
            case '>': output += "&gt;"; break;
            case '"': output += "&quot;"; break;
            case '\'': output += "&#39;"; break;
            default: output += c; break;
        }
    }

    return output;
}

string makePage(const string& displayName) {
    return "<html><body><h1>Welcome, " +
           escapeHtmlText(displayName) +
           "</h1></body></html>";
}
```

**Why it works:** The helper encodes special characters for an HTML text
context. In production, prefer a well-maintained templating engine that
performs context-aware auto-escaping. This helper is not a universal
encoder for JavaScript, CSS, URL, or attribute contexts.

------------------------------------------------------------------------

## Question 8 -- Unsafe Rich-Text HTML Rendering

**Task:** The application allows formatted comments and uses
`innerHTML`. Is that always wrong?

### Vulnerable code

``` javascript
function renderRichText(htmlFromUser) {
    document.getElementById("article").innerHTML =
        htmlFromUser;
}
```

**Finding:** Directly rendering arbitrary user-supplied HTML can allow
script-capable markup, event handlers, dangerous URLs, or other active
content.

**Important distinction:** If rich text is a product requirement,
`textContent` may remove the intended formatting. The correct approach
is a maintained HTML sanitizer with a strict allowlist.

### Secure fix

``` javascript
// Example using DOMPurify, which must be installed and kept updated.
function renderRichText(htmlFromUser) {
    const cleanHtml = DOMPurify.sanitize(htmlFromUser, {
        ALLOWED_TAGS: [
            "p", "b", "strong", "i", "em",
            "ul", "ol", "li", "a"
        ],
        ALLOWED_ATTR: ["href"]
    });

    document.getElementById("article").innerHTML =
        cleanHtml;
}
```

**Why it works:** The sanitizer removes disallowed markup and attributes
before HTML insertion. Configure URL protocols and allowed attributes
carefully. Sanitization is not a substitute for safe handling in other
output contexts.

------------------------------------------------------------------------

## Question 9 -- Why Input Validation Alone Is Not Enough

**Task:** A developer allows only inputs that pass a basic check. Is the
following safe?

### Vulnerable code

``` javascript
function renderName(name) {
    if (name.length > 50) {
        throw new Error("Name too long");
    }

    document.getElementById("name").innerHTML = name;
}
```

**Finding:** Length validation does not make an HTML parsing sink safe.
A short input can still contain dangerous markup.

### Secure fix

``` javascript
function renderName(name) {
    if (name.length > 50) {
        throw new Error("Name too long");
    }

    document.getElementById("name").textContent = name;
}
```

**Why it works:** Length validation enforces a business constraint;
`textContent` ensures the value is rendered as text. These controls
solve different problems.

------------------------------------------------------------------------

## Question 10 -- Complete PR Review: Multiple XSS Issues

**Task:** Review the code and identify all risky flows.

### Vulnerable code

``` javascript
function renderProfile(profile) {
    document.getElementById("name").innerHTML =
        profile.name;

    document.getElementById("bio").innerHTML =
        profile.bio;

    document.getElementById("avatar").innerHTML =
        '<img src="' + profile.avatarUrl + '">';
}

function showSearchResult() {
    const query =
        new URLSearchParams(location.search).get("q") || "";

    document.getElementById("search").innerHTML =
        "Results for: " + query;
}
```

**Findings:**

1.  `profile.name` is inserted into an HTML parsing sink.
2.  `profile.bio` is inserted as HTML without sanitization.
3.  `profile.avatarUrl` is concatenated into an HTML attribute and
    parsed.
4.  The URL query parameter is reflected into `innerHTML`.

### Secure fix for plain-text fields

``` javascript
function renderProfile(profile) {
    document.getElementById("name").textContent =
        profile.name ?? "";

    document.getElementById("bio").textContent =
        profile.bio ?? "";

    const avatar = document.createElement("img");
    const parsed = new URL(
        profile.avatarUrl,
        window.location.origin
    );

    if (parsed.protocol !== "https:" ||
        parsed.origin !== window.location.origin) {
        throw new Error("Invalid avatar URL");
    }

    avatar.src = parsed.href;
    document.getElementById("avatar").replaceChildren(avatar);
}

function showSearchResult() {
    const query =
        new URLSearchParams(location.search).get("q") || "";

    document.getElementById("search").textContent =
        "Results for: " + query;
}
```

**Why this fix works:** - Plain-text fields use `textContent`. - The
avatar uses a DOM element rather than an HTML string. - The avatar URL
is checked against a restrictive same-origin HTTPS policy. - Search
input is displayed as text. - If rich text is required for the bio,
sanitize it with a maintained HTML sanitizer and an explicit allowlist
instead of assigning raw HTML.

------------------------------------------------------------------------

# Quick Revision -- XSS PR Review Checklist

  -----------------------------------------------------------------------
  Code pattern / situation            What to check
  ----------------------------------- -----------------------------------
  `innerHTML = userInput`             DOM XSS risk

  `document.write(userInput)`         HTML injection / XSS risk

  URL parameter inserted into HTML    Reflected or DOM XSS risk

  Database content rendered as HTML   Stored XSS risk

  `location.hash` passed to           DOM-based XSS risk
  `innerHTML`                         

  User data concatenated into HTML    Attribute-context injection risk
  attributes                          

  C++ backend concatenates raw data   Missing output encoding
  into HTML                           

  Rich text rendered without          HTML injection / XSS risk
  sanitization                        

  Length validation only              Not an XSS defense

  Sanitized rich text                 Verify sanitizer, allowlist and URL
                                      policy
  -----------------------------------------------------------------------

## 10 Key Interview Answers

1.  **What is XSS?** Injection of attacker-controlled content that
    executes in a victim's browser in the context of a vulnerable site.
2.  **Stored XSS?** Malicious content is persisted and later rendered to
    users.
3.  **Reflected XSS?** Request data is reflected unsafely in a response.
4.  **DOM-based XSS?** Client-side code moves untrusted data into an
    unsafe DOM sink.
5.  **What is a source?** A place where untrusted data enters, such as
    URL parameters or stored comments.
6.  **What is a sink?** An operation that can interpret data as code or
    markup, such as `innerHTML`.
7.  **Best fix for plain text?** Use `textContent` or safe framework
    text-binding.
8.  **What about rich HTML?** Use a maintained sanitizer with a strict
    allowlist.
9.  **Does input validation alone prevent XSS?** No; use
    context-appropriate output encoding or safe DOM APIs.
10. **Does HttpOnly prevent all XSS?** No. It prevents JavaScript from
    reading that cookie, but injected scripts may still perform actions
    as the user.

------------------------------------------------------------------------

**Production review reminders:** - Prefer safe DOM APIs and framework
auto-escaping. - Encode output for the exact context: HTML text,
attributes, JavaScript, CSS, and URLs require different handling. - Use
a maintained sanitizer when user-authored rich HTML is required. -
Consider Content Security Policy (CSP) and Trusted Types as
defense-in-depth, not replacements for fixing unsafe sinks. -
`HttpOnly`, `Secure`, and `SameSite` cookie attributes help protect
sessions but do not eliminate XSS.
