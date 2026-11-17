# SQL Injection -- C++ Code Review Practice

**10 interview-style questions with vulnerable code, expected behavior,
and secure fixes**

> These are representative AWS-style AI-assisted code-review practice
> questions, not verified AWS assessment questions. Examples use
> SQLite's C API.

------------------------------------------------------------------------

## Question 1 -- Basic SQL Injection: Authentication Bypass

**Task:** Identify the vulnerability and determine the generated SQL
query.

### Vulnerable code

``` cpp
#include <iostream>
#include <string>
using namespace std;

int main() {
    string username = "admin' OR '1'='1";

    string query =
        "SELECT * FROM users WHERE username = '" +
        username + "'";

    cout << query;
    return 0;
}
```

**Expected output**

``` sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1'
```

**Finding:** Direct concatenation allows input to alter SQL syntax. If
executed, the always-true condition may return unauthorized records.

### Secure fix

``` cpp
#include <iostream>
#include <string>
#include <sqlite3.h>
using namespace std;

bool findUser(sqlite3* db, const string& username) {
    const char* query =
        "SELECT 1 FROM users WHERE username = ? LIMIT 1";

    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(
            db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    if (sqlite3_bind_text(
            stmt, 1, username.c_str(), -1,
            SQLITE_TRANSIENT) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return false;
    }

    int result = sqlite3_step(stmt);
    bool found = (result == SQLITE_ROW);

    sqlite3_finalize(stmt);
    return found;
}
```

------------------------------------------------------------------------

## Question 2 -- Does `sqlite3_prepare_v2()` Alone Prevent SQL Injection?

**Task:** Is this implementation safe?

### Vulnerable code

``` cpp
#include <iostream>
#include <string>
#include <sqlite3.h>
using namespace std;

int main() {
    sqlite3* db = nullptr;
    sqlite3_open(":memory:", &db);

    string username = "admin' OR '1'='1";

    string query =
        "SELECT * FROM users WHERE username = '" +
        username + "'";

    sqlite3_stmt* stmt = nullptr;

    sqlite3_prepare_v2(
        db, query.c_str(), -1, &stmt, nullptr
    );

    cout << "Query prepared";

    sqlite3_finalize(stmt);
    sqlite3_close(db);
}
```

**Expected output**

``` text
Query prepared
```

**Finding:** The query is still vulnerable. `sqlite3_prepare_v2()`
receives SQL that has already been constructed through unsafe
concatenation. Preparing an unsafe query does not sanitize it.

### Secure fix

``` cpp
const char* query =
    "SELECT * FROM users WHERE username = ?";

sqlite3_stmt* stmt = nullptr;

if (sqlite3_prepare_v2(
        db, query, -1, &stmt, nullptr) == SQLITE_OK) {

    sqlite3_bind_text(
        stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT
    );

    // Execute and inspect the result here.
}

sqlite3_finalize(stmt);
```

------------------------------------------------------------------------

## Question 3 -- Parameterized Query

**Task:** A database contains one row with username `admin`. What is the
result when the supplied username is `admin' OR '1'='1`?

### Secure code

``` cpp
#include <iostream>
#include <string>
#include <sqlite3.h>
using namespace std;

int main() {
    sqlite3* db = nullptr;
    sqlite3_open(":memory:", &db);

    sqlite3_exec(db,
        "CREATE TABLE users(username TEXT);"
        "INSERT INTO users VALUES('admin');",
        nullptr, nullptr, nullptr);

    string username = "admin' OR '1'='1";

    const char* query =
        "SELECT * FROM users WHERE username = ?";

    sqlite3_stmt* stmt = nullptr;

    sqlite3_prepare_v2(
        db, query, -1, &stmt, nullptr
    );

    sqlite3_bind_text(
        stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT
    );

    cout << (sqlite3_step(stmt) == SQLITE_ROW
             ? "User found" : "User not found");

    sqlite3_finalize(stmt);
    sqlite3_close(db);
}
```

**Expected output**

``` text
User not found
```

**Finding:** The complete input is bound as one text value. SQLite
searches for a username literally equal to the supplied string; it does
not execute the embedded `OR` as SQL syntax.

### Secure fix

The code already uses the correct primary defense: a placeholder and
`sqlite3_bind_text()`. In production, also check the return values of
database operations and clean up resources on every path.

------------------------------------------------------------------------

## Question 4 -- SQL Injection Through an Integer-Like Input

**Task:** Identify the vulnerability and determine the generated query.

### Vulnerable code

``` cpp
#include <iostream>
#include <string>
using namespace std;

int main() {
    string employeeId = "101 OR 1=1";

    string query =
        "SELECT * FROM employees WHERE id = " +
        employeeId;

    cout << query;
    return 0;
}
```

**Expected output**

``` sql
SELECT * FROM employees WHERE id = 101 OR 1=1
```

**Finding:** The input is concatenated into SQL without binding. An
integer database column does not make unsafe query construction safe.

### Secure fix

``` cpp
const char* query =
    "SELECT * FROM employees WHERE id = ?";

sqlite3_stmt* stmt = nullptr;

if (sqlite3_prepare_v2(
        db, query, -1, &stmt, nullptr) != SQLITE_OK) {
    return false;
}

int employeeId = 101; // Parse and validate input first.

if (sqlite3_bind_int(stmt, 1, employeeId) != SQLITE_OK) {
    sqlite3_finalize(stmt);
    return false;
}

int result = sqlite3_step(stmt);
bool found = (result == SQLITE_ROW);

sqlite3_finalize(stmt);
return found;
```

------------------------------------------------------------------------

## Question 5 -- UNION-Based SQL Injection

**Task:** What query is generated, and why is this unsafe?

### Vulnerable code

``` cpp
#include <iostream>
#include <string>
using namespace std;

int main() {
    string productId = "10 UNION SELECT 1,2,3";

    string query =
        "SELECT id, name, price FROM products "
        "WHERE id = " + productId;

    cout << query;
}
```

**Expected output**

``` sql
SELECT id, name, price FROM products
WHERE id = 10 UNION SELECT 1,2,3
```

**Finding:** User input adds another `SELECT` through `UNION`. If
executed and the result columns are compatible, the injected query can
alter the returned result set.

### Secure fix

``` cpp
const char* query =
    "SELECT id, name, price FROM products WHERE id = ?";

sqlite3_stmt* stmt = nullptr;

if (sqlite3_prepare_v2(
        db, query, -1, &stmt, nullptr) != SQLITE_OK) {
    return false;
}

int productId = 10; // Validate and parse the external value.

sqlite3_bind_int(stmt, 1, productId);

int result = sqlite3_step(stmt);
bool found = (result == SQLITE_ROW);

sqlite3_finalize(stmt);
return found;
```

------------------------------------------------------------------------

## Question 6 -- SQL Comment Injection

**Task:** The username is `admin' --` and the password is `wrong`. What
query is generated?

### Vulnerable code

``` cpp
#include <iostream>
#include <string>
using namespace std;

int main() {
    string username = "admin' --";
    string password = "wrong";

    string query =
        "SELECT * FROM users WHERE username = '" +
        username +
        "' AND password = '" +
        password + "';";

    cout << query;
}
```

**Expected output**

``` sql
SELECT * FROM users WHERE username = 'admin' --' AND password = 'wrong';
```

**Finding:** In SQLite, `--` starts a comment that continues to the end
of the line. The password condition can therefore be commented out if
this statement is executed.

### Secure fix

``` cpp
const char* query =
    "SELECT password_hash FROM users WHERE username = ?";

sqlite3_stmt* stmt = nullptr;

if (sqlite3_prepare_v2(
        db, query, -1, &stmt, nullptr) != SQLITE_OK) {
    return false;
}

sqlite3_bind_text(
    stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT
);

int result = sqlite3_step(stmt);
bool authenticated = false;

if (result == SQLITE_ROW) {
    const unsigned char* hash = sqlite3_column_text(stmt, 0);

    if (hash != nullptr) {
        // Verify password against the stored hash using
        // a suitable password-hashing library (e.g. Argon2id).
        authenticated = verifyPasswordAgainstHash(
            password,
            reinterpret_cast<const char*>(hash)
        );
    }
}

sqlite3_finalize(stmt);
return authenticated;
```

`verifyPasswordAgainstHash()` is a placeholder for a real
password-hashing library function. Passwords should not be stored or
compared in plaintext.

------------------------------------------------------------------------

## Question 7 -- Database Error Disclosure

**Task:** Does this code demonstrate SQL Injection? What security issue
does it have?

### Code

``` cpp
#include <iostream>
#include <string>
#include <sqlite3.h>
using namespace std;

int main() {
    sqlite3* db = nullptr;
    sqlite3_open(":memory:", &db);

    string query = "SELECT * FROM unknown_table";

    char* errorMessage = nullptr;

    int result = sqlite3_exec(
        db, query.c_str(), nullptr, nullptr, &errorMessage
    );

    if (result != SQLITE_OK) {
        cout << errorMessage;
    }

    sqlite3_free(errorMessage);
    sqlite3_close(db);
}
```

**Typical expected output**

``` text
no such table: unknown_table
```

**Finding:** The query is static, so this snippet does not itself
demonstrate SQL Injection. However, returning raw database errors to
users can disclose schema and implementation details.

### Secure fix

``` cpp
int result = sqlite3_exec(
    db, query.c_str(), nullptr, nullptr, &errorMessage
);

if (result != SQLITE_OK) {
    // Log detailed error securely on the server.
    logDatabaseError(errorMessage);

    // Return a generic message to the external caller.
    cout << "Database operation failed";
}

sqlite3_free(errorMessage);
```

`logDatabaseError()` represents the application's server-side logging
function. Do not expose detailed database errors to external users.

------------------------------------------------------------------------

## Question 8 -- Second-Order SQL Injection

**Task:** The username was originally stored using a parameterized
query. A later function retrieves it and concatenates it into SQL.
Identify the issue.

### Vulnerable code

``` cpp
#include <iostream>
#include <string>
using namespace std;

int main() {
    string username = "admin' OR '1'='1";

    string query =
        "SELECT * FROM users WHERE username = '" +
        username + "'";

    cout << query;
}
```

**Expected output**

``` sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1'
```

**Finding:** This illustrates the unsafe second-stage use of previously
stored untrusted data. It is a second-order SQL Injection risk. Data
does not become trusted merely because it was stored in a database.

### Secure fix

``` cpp
const char* query =
    "SELECT * FROM users WHERE username = ?";

sqlite3_stmt* stmt = nullptr;

if (sqlite3_prepare_v2(
        db, query, -1, &stmt, nullptr) != SQLITE_OK) {
    return false;
}

sqlite3_bind_text(
    stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT
);

int result = sqlite3_step(stmt);
bool found = (result == SQLITE_ROW);

sqlite3_finalize(stmt);
return found;
```

------------------------------------------------------------------------

## Question 9 -- Dynamic Table Name and Parameter Placeholders

**Task:** Can a `?` placeholder be used to bind a table name?

### Vulnerable / incorrect code

``` cpp
#include <iostream>
#include <sqlite3.h>
using namespace std;

int main() {
    sqlite3* db = nullptr;
    sqlite3_open(":memory:", &db);

    sqlite3_exec(db,
        "CREATE TABLE users(id INTEGER);",
        nullptr, nullptr, nullptr);

    const char* query = "SELECT * FROM ?";

    sqlite3_stmt* stmt = nullptr;

    int result = sqlite3_prepare_v2(
        db, query, -1, &stmt, nullptr
    );

    cout << (result == SQLITE_OK
             ? "Prepared" : "Preparation failed");

    sqlite3_finalize(stmt);
    sqlite3_close(db);
}
```

**Expected output**

``` text
Preparation failed
```

**Finding:** Placeholders bind values, not SQL identifiers such as table
or column names. A table name must be selected from trusted, predefined
identifiers.

### Secure fix

``` cpp
#include <iostream>
#include <string>
#include <sqlite3.h>
using namespace std;

bool queryTable(sqlite3* db, const string& tableName) {
    if (tableName != "users" && tableName != "products") {
        return false;
    }

    string query = "SELECT * FROM " + tableName;

    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(
            db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    int result = sqlite3_step(stmt);
    bool success = (result == SQLITE_ROW || result == SQLITE_DONE);

    sqlite3_finalize(stmt);
    return success;
}
```

The allowlist must contain only trusted, predefined identifiers. Use
parameter binding for ordinary data values.

------------------------------------------------------------------------

## Question 10 -- Complete PR Review: Multiple SQL Injection Risks

**Task:** Identify all security problems in this code and propose a
secure fix.

### Vulnerable code

``` cpp
#include <iostream>
#include <string>
#include <sqlite3.h>
using namespace std;

bool getUser(
    sqlite3* db,
    string username,
    string sortColumn
) {
    string query =
        "SELECT * FROM users WHERE username = '" +
        username +
        "' ORDER BY " +
        sortColumn;

    sqlite3_stmt* stmt = nullptr;

    sqlite3_prepare_v2(
        db, query.c_str(), -1, &stmt, nullptr
    );

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        cout << "User found";
        sqlite3_finalize(stmt);
        return true;
    }

    sqlite3_finalize(stmt);
    return false;
}
```

**Finding 1 -- Username:** Direct concatenation makes the value
vulnerable to SQL Injection.

**Finding 2 -- Sort column:** Directly concatenating a user-controlled
SQL identifier can alter query syntax. Identifiers cannot generally be
bound using ordinary placeholders.

**Finding 3 -- Error handling:** The code does not check whether
`sqlite3_prepare_v2()` succeeded before calling `sqlite3_step()`.

### Secure fix

``` cpp
#include <iostream>
#include <string>
#include <sqlite3.h>
using namespace std;

bool getUser(
    sqlite3* db,
    const string& username,
    const string& sortColumn
) {
    if (sortColumn != "id" &&
        sortColumn != "username" &&
        sortColumn != "created_at") {
        return false;
    }

    string query =
        "SELECT * FROM users "
        "WHERE username = ? ORDER BY " + sortColumn;

    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(
            db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    if (sqlite3_bind_text(
            stmt, 1, username.c_str(), -1,
            SQLITE_TRANSIENT) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return false;
    }

    int result = sqlite3_step(stmt);
    bool found = (result == SQLITE_ROW);

    sqlite3_finalize(stmt);
    return found;
}
```

**Why this fix works:** - `username` is passed as a bound parameter. -
`sortColumn` is restricted to a trusted allowlist. - The prepare and
bind operations are checked. - The SQLite statement is finalized before
returning.

------------------------------------------------------------------------

# Quick Revision -- SQL Injection PR Review Checklist

  -----------------------------------------------------------------------
  Code pattern / situation            What to check
  ----------------------------------- -----------------------------------
  SQL string concatenation            Potential SQL Injection

  `sqlite3_prepare_v2()` after        Still vulnerable
  concatenation                       

  `?` with `sqlite3_bind_text()`      Correct parameter-binding approach

  Integer inserted through string     Potential SQL Injection
  concatenation                       

  User-controlled `UNION`             Query manipulation

  User-controlled SQL comments        Query manipulation

  Raw database errors sent to clients Information disclosure

  Stored input later concatenated     Second-order SQL Injection
  into SQL                            

  User input used as table or column  Use an allowlist
  name                                

  ORM with raw SQL fragments          Inspect query construction
  -----------------------------------------------------------------------

## 10 Key Interview Answers

1.  **Root cause:** Mixing untrusted data with SQL syntax.
2.  **Primary defense:** Parameterized queries.
3.  **Does prepare alone prevent SQLi?** No.
4.  **Is validation sufficient?** No.
5.  **Can integer inputs cause SQLi?** Yes, if concatenated unsafely.
6.  **Can stored data cause SQLi?** Yes, through second-order SQLi.
7.  **Can placeholders bind table names?** No.
8.  **Does HTTPS prevent SQLi?** No.
9.  **Does an ORM eliminate SQLi?** No, unsafe raw SQL can remain
    vulnerable.
10. **What limits the damage?** Least-privilege database permissions.

------------------------------------------------------------------------

**Practice note:** These examples are focused on recognizing unsafe
query construction and applying parameter binding. In production C++,
prefer RAII wrappers for SQLite statements and database handles, check
every SQLite return code, and use a dedicated password-hashing library
for authentication.
