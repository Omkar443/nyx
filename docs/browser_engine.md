# NYX Browser Automation Engine Overview

## 1. Executive Summary
Phase 19 adds the **Browser Automation Engine** (`nyx/browser/`) to NYX.
It provides Playwright foundation and Chrome DevTools Protocol (CDP) ready abstractions for managed browser sessions, cookie and header manipulation, authentication context storage, screenshot capture, HAR network export, and browser event hooks.

---

## 2. Browser Architecture Diagram

```
                             NYX Browser Engine
                            (BrowserController)
                                     |
           +-------------------------+-------------------------+
           |                         |                         |
           v                         v                         v
     BrowserSession 1          BrowserSession 2          BrowserSession 3
     (Target: app.com)         (Target: api.com)         (Target: auth.com)
           |                         |                         |
           +-------------------------+-------------------------+
                                     |
                                     v
                        Playwright / CDP Abstraction
                        (nyx.browser.session)
                                     |
                                     v
                        Browser Context & Event Hooks
                        (nyx.browser.context & events)
                                     |
                                     v
                        Session Profile Storage
                        (nyx.browser.storage)
```

---

## 3. Key Components
- `BrowserSession`: Manages active browser instances, navigation, cookie/header mutation, screenshot capture, and HAR export.
- `BrowserContext`: Data model holding target, session_id, cookies, headers, auth state, and permissions.
- `BrowserEvents`: Event bus for browser lifecycle, network requests, responses, and DOM events.
- `BrowserStorage`: Persists session profiles to `.engagement/database/browser_sessions.json`.
- `BrowserController`: Orchestrates managed browser instances.
