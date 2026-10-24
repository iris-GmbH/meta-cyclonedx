# Domain Docs

How engineering skills consume this repository’s domain documentation.

## Before exploring

Read:

- `CONTEXT.md`
- ADRs under `docs/adr/` that affect the area being changed

If either location is absent, proceed silently. Domain-modeling skills create these files lazily when terminology or decisions are resolved.

## Layout

This is a single-context repository:

```text
/
├── CONTEXT.md
└── docs/
    └── adr/
        └── NNNN-decision-name.md
```

## Use the glossary’s vocabulary

When an issue, proposal, test, or implementation names a domain concept, use the canonical term from `CONTEXT.md`. Do not substitute a term listed under `_Avoid_`.

If a needed concept is absent, reconsider whether it belongs to the project’s domain. Record genuine terminology gaps through the domain-modeling workflow.

## Flag ADR conflicts

Surface any conflict with an existing ADR explicitly rather than silently overriding it:

> Contradicts ADR-NNNN (decision title) — worth reopening because…
