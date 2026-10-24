# Triage Labels

The skills use five canonical triage roles. For the local issue tracker, each role maps directly to the value stored in an issue file’s `Status:` line.

| Canonical role    | Local status       | Meaning                                   |
| ----------------- | ------------------ | ----------------------------------------- |
| `needs-triage`    | `needs-triage`     | Maintainer needs to evaluate this issue   |
| `needs-info`      | `needs-info`       | Waiting on reporter for more information |
| `ready-for-agent` | `ready-for-agent`  | Fully specified, ready for an AFK agent   |
| `ready-for-human` | `ready-for-human`  | Requires human implementation             |
| `wontfix`         | `wontfix`          | Will not be actioned                      |

When a skill names a triage role, use the corresponding local status from this table.
