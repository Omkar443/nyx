# NYX Runtime Network Intelligence Overview

## 1. Executive Summary
Phase 19 introduces **Runtime Network Intelligence** (`nyx/runtime/`) to continuously observe browser network traffic, client-side JavaScript execution, form inputs, and DOM events.

---

## 2. Runtime Intelligence Graph Schema

```json
{
  "requests": [
    {
      "method": "GET",
      "url": "https://example.com/api/v1/user",
      "headers": {},
      "params": {},
      "status_code": 200
    }
  ],
  "apis": [
    {
      "endpoint": "https://example.com/api/v1/user",
      "method": "GET",
      "type": "rest"
    }
  ],
  "parameters": ["username", "password", "id"],
  "technologies": ["nginx", "Express"],
  "interesting_events": [
    {
      "type": "dynamic_surface_discovered",
      "details": {"url": "https://example.com"}
    }
  ]
}
```

---

## 3. Observers
- `RequestLogger`: Logs raw HTTP requests, headers, query parameters, and status codes.
- `NetworkObserver`: Filters and categorizes REST API calls and GraphQL queries.
- `JSObserver`: Tracks loaded script tags, inline handlers, client-side endpoints, and console logs.
- `DOMObserver`: Monitors interactive forms, input elements, security events, and constructs the unified **Runtime Intelligence Graph**.
