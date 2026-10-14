# ADR 0016: Power classification of Safe self-calls, and a refined P1

- Status: Accepted
- Date: 2026-10-14

## Context

The spec required every self-call to the Safe to be a matured timelock item. P1 allows actions that
only reduce power to be fast. Several self-calls look power-reducing:

- `disableModule`;
- raising the threshold;
- `removeOwner`.

Some of these can still harm the Safe.

## Options

### A. Everything timelocked
- (−) Slow incident response for clearly safe actions, such as disabling a compromised module.

### B. Anything that looks power-reducing is immediate
- (−) Raising the threshold "reduces power" but can freeze the Safe (see Decision).

### C. Immediate only if the action reduces power **and** cannot reduce the signers' ability to reach the threshold

## Decision

**Option C** (owner, 2026-10-14).

| Self-call | Treatment |
|---|---|
| `disableModule` | **Immediate** |
| `changeThreshold` (raise or lower) | Timelocked |
| `addOwnerWithThreshold` | Timelocked |
| `removeOwner` | Timelocked |
| `swapOwner` | Timelocked |
| `enableModule`, `setFallbackHandler` | Timelocked (power-adding) |
| `setGuard`, `setModuleGuard` | Escape path only (ADR 0014) |

Owner's reasoning: raising the threshold to N-of-N through a compromised UI, plus one lost key,
permanently freezes the Safe. That includes the escape path, which breaks R1.

**Refined P1:** an action may be fast only if it reduces power **and** cannot reduce the signers'
ability to reach the threshold.

## Consequences

- With `disableModule` immediate, the post-check must accept a module-list change that is
  **exactly** the removal of the disabled module, and nothing else.
- The threat model records the threshold-raise freeze scenario (§3.5).
- Timelocked owner and threshold changes can be cancelled by the guardian (ADR 0008), because they
  are not escape-path or guardian items.

## Delay class for timelocked self-calls (owner, 2026-10-14)

Timelocked self-calls use the **72h escape class**, because they change control (A1):

- `enableModule`, `setFallbackHandler`;
- `changeThreshold`, `addOwnerWithThreshold`, `removeOwner`, `swapOwner`.

Allowlist and cap changes stay at 48h (ADR 0011).
