# NYX Frontend Dashboard Architecture

## 1. Overview
The frontend dashboard (`frontend/`) is built using **React 18**, **TypeScript**, **Vite**, and custom Glassmorphism CSS styling.

---

## 2. Component Structure

```text
frontend/src/
├── App.tsx                     # Main dashboard layout & sidebar navigation
├── main.tsx                    # React entry point
├── index.css                   # Glassmorphism & dark theme design system
├── api/
│   └── client.ts               # Typed REST API client with Auth headers
├── hooks/
│   └── useNyxEvents.ts         # Reusable WebSocket event hook
└── views/
    ├── DashboardView.tsx       # Mission metrics & security hypotheses preview
    ├── AttackSurfaceView.tsx   # Asset surface, endpoints, & tech stack
    ├── FindingsView.tsx        # Finding lifecycle cards, triage, & reports
    ├── EvidenceView.tsx       # Evidence vault & SHA-256 hash verification
    ├── IntelligenceView.tsx    # AI provider selection, reasoning, & skills
    ├── ExecutionView.tsx       # Controlled tool execution harness & logs
    └── SettingsView.tsx        # System health & API token configuration
```

---

## 3. Real-Time WebSocket Streaming
The `useNyxEvents` hook maintains a single persistent WebSocket connection to `/ws/events?token=<TOKEN>`. When security events occur on the backend (e.g. `recon_completed` or `finding_created`), the UI updates dynamically without full page reloads.
