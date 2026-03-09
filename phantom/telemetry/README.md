### Overview

To help make Phantom better for everyone, we collect anonymized data that helps us understand how to better improve our AI security agent for our users, guide the addition of new features, and fix common errors and bugs. This feedback loop is crucial for improving Phantom's capabilities and user experience.

We use [PostHog](https://posthog.com), an open-source analytics platform, for data collection and analysis. Our telemetry implementation is fully transparent - you can review the [source code](https://github.com/usephantom/phantom/blob/main/phantom/telemetry/posthog.py) to see exactly what we track.

### Telemetry Policy

Privacy is our priority. All collected data is anonymized by default. Each session gets a random UUID that is not persisted or tied to you. Your code, scan targets, vulnerability details, and findings always remain private and are never collected.

### What We Track

We collect only very **basic** usage data including:

**Session Errors:** Duration and error types (not messages or stack traces)\
**System Context:** OS type, architecture, Phantom version\
**Scan Context:** Scan mode (quick/standard/deep), scan type (whitebox/blackbox)\
**Model Usage:** Which LLM model is being used (not prompts or responses)\
**Aggregate Metrics:** Vulnerability counts by severity, agent/tool counts, token usage and cost estimates

For complete transparency, you can inspect our [telemetry implementation](https://github.com/usephantom/phantom/blob/main/phantom/telemetry/posthog.py) to see the exact events we track.

### What We **Never** Collect

- IP addresses, usernames, or any identifying information
- Scan targets, file paths, target URLs, or domains
- Vulnerability details, descriptions, or code
- LLM requests and responses

### How to Opt Out

Telemetry in Phantom is entirely **optional**:

```bash
export PHANTOM_TELEMETRY=0
```

You can set this environment variable before running Phantom to disable **all** telemetry.
