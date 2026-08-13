# NYX Security Change Detection Guide

## 1. Executive Summary
The NYX Change Detection Engine identifies attack surface drift across recon intervals.

---

## 2. Event Types & Severity Mapping

| Change Event Type | Trigger Condition | Default Severity | Recommended Research Skills |
|---|---|---|---|
| `NEW_ENDPOINT` | New URI route or path discovered | `MEDIUM` | `hunt-api-misconfig`, `hunt-spa-api` |
| `NEW_PARAMETER` | New query/body parameter detected | `LOW` | `hunt-idor`, `hunt-sqli`, `hunt-xss` |
| `NEW_TECHNOLOGY` | New server header or framework detected | `INFO` | `technology map <tech>` |
| `GRAPHQL_EXPOSED` | GraphQL endpoint or schema detected | `HIGH` | `hunt-graphql`, `hunt-api-misconfig` |
| `AUTH_CHANGE` | Authentication flow or token type modified | `HIGH` | `hunt-ato`, `hunt-session`, `hunt-mfa-bypass` |
