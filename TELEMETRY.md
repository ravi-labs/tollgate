# Telemetry and Adoption Metrics

To help improve Tollgate and understand how it's being used in the wild, the library includes a lightweight, anonymous telemetry system.

## What is collected?

We collect only high-level, anonymous aggregates. We **NEVER** collect:
- Sensitive parameters or tool arguments.
- Agent IDs or personal identification.
- Content of your policies or manifests.
- IP addresses or specific hostnames.

The data we collect includes:
- **Outcome**: Whether a tool was `EXECUTED`, `BLOCKED`, `FAILED`, or `TIMED_OUT`.
- **Effect**: The effect type (e.g., `READ`, `WRITE`).
- **Framework**: The agent framework being used (e.g., `langchain`, `openai`, or `custom`).
- **Version**: The version of the Tollgate library.

## Why collect this?

This data helps us understand:
- Which agent frameworks are most popular for enforcement.
- The average ratio of blocked vs. allowed actions.
- Common failure points in tool execution.
- Growth in adoption metrics (e.g., total tool calls secured by Tollgate).

## How to Opt-out

Telemetry is enabled by default to help us grow the project, but we respect your privacy and make it easy to disable.

### Option 1: Environment Variable
Set the `TOLLGATE_TELEMETRY` environment variable to `0`:

```bash
export TOLLGATE_TELEMETRY=0
```

### Option 2: Code Configuration
When initializing the `ControlTower`, pass `enable_telemetry=False`:

```python
from tollgate import ControlTower

tower = ControlTower(
    ...,
    enable_telemetry=False
)
```

## Transparency

We believe in open-source transparency. The telemetry implementation is fully visible in `src/tollgate/telemetry.py`.

For download analytics, we use [Scarf Gateway](https://scarf.sh), which allows us to track library downloads from PyPI and GitHub without installing any trackers on your machine.
