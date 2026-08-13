# NYX Remote Worker Nodes & Operations Guide

## 1. Worker Lifecycle States
Remote worker nodes operate within defined lifecycle states managed by `WorkerHeartbeat`:

- `ONLINE`: Worker node is registered, active, and sending periodic liveness signals.
- `BUSY`: Worker node is executing an assigned agent workload.
- `OFFLINE`: Worker node has timed out (> 60 seconds without a heartbeat signal).
- `ERROR`: Worker node encountered an unhandled execution error.

---

## 2. Remote Task Dispatching & Recovery
The `WorkerScheduler` checks local agent availability first; if no local agent is free, it dispatches the task to an available remote worker node (`execution_mode="REMOTE"`).

If a remote worker fails or times out, `DistributedTaskQueue.fail_task()` automatically increments `retry_count` and re-queues the task until `max_retries` (default 3) is exceeded.
