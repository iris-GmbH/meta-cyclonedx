# Issue tracker: GitHub

Issues and specs for this repo live as GitHub issues on the maintained fork (`Jasper-Ben/meta-cyclonedx`). Use the `gh` CLI for all operations.

## Conventions

- **Create an issue**: `gh api --method POST repos/Jasper-Ben/meta-cyclonedx/issues --input -` with a JSON body (`title`, `body`, `labels`). Prefer the REST API over `gh issue create`: the GraphQL path resolves the parent repository (`iris-GmbH/meta-cyclonedx`), and that organization rejects fine-grained PATs with lifetimes above 366 days, which fails the whole call.
- **Read an issue**: `gh issue view <number> --comments`, filtering comments by `jq` and also fetching labels.
- **List issues**: `gh issue list --state open --json number,title,labels --label <label>` with appropriate `--label` and `--state` filters.
- **Comment on an issue**: `gh issue comment <number> --body "..."`
- **Apply / remove labels**: `gh issue edit <number> --add-label "..."` / `--remove-label "..."`
- **Close**: `gh issue close <number> --comment "..."`

## Epic and sub-issue structure

- The CRA / BSI TR-03183-2 epic is issue **#1**. Feature tickets are linked as GitHub **sub-issues** of the epic:
  `gh api --method POST repos/Jasper-Ben/meta-cyclonedx/issues/1/sub_issues -F sub_issue_id=<issue-db-id>`
  (the database id, from `gh api repos/.../issues/<n> --jq .id`, not the `#number`).
- **Blocking** uses GitHub's native issue dependencies:
  `gh api --method POST repos/Jasper-Ben/meta-cyclonedx/issues/<child>/dependencies/blocked_by -F issue_id=<blocker-db-id>`;
  remove an edge via `DELETE .../issues/<child>/dependencies/blocked_by/<blocker-db-id>`.
  A ticket is unblocked when every blocker is closed; `issue_dependencies_summary.blocked_by` reports the live open-blocker count.

## Triage state

Status is carried by the five canonical labels (see `triage-labels.md`). A closed ticket is done; do not add a status label beyond its last triage role.

## Pull requests as a triage surface

**PRs as a request surface: no.** _(Set to `yes` if this repo treats external PRs as feature requests; `/triage` reads this flag.)_

## Historical local tickets

The former `.scratch/` local-markdown tracker is fully migrated and deleted. `tr-03183-alignment` tickets 01–12 are issues #2–#13 and its spec is #14; `bitbake-acceptance-harness` spec and tickets are #15–#21. Mapping details live in the migration-record comments on the epic #1.

## Wayfinding operations

Used by `/wayfinder`. The **map** is a single issue with **child** issues as tickets.
- **Map**: a single issue labelled `wayfinder:map`, holding the Notes / Decisions-so-far / Fog body. Create via the REST issue endpoint with that label.
- **Child ticket**: an issue linked to the map as a GitHub sub-issue (endpoint above). Where sub-issues aren't enabled, add the child to a task list in the map body and put `Part of #<map>` at the top of the child body. Labels: `wayfinder:<type>` (`research`/`prototype`/`grilling`/`task`). Once claimed, the ticket is assigned to the driving dev.
- **Blocking**: the native issue dependencies described above. A ticket is unblocked when every blocker is closed.
- **Frontier query**: list the map's open children, drop any with an open blocker (`issue_dependencies_summary.blocked_by > 0`) or an assignee; first in map order wins.
- **Claim**: `gh issue edit <n> --add-assignee @me` — the session's first write.
- **Resolve**: `gh issue comment <n> --body "<answer>"`, then `gh issue close <n>`, then append a context pointer (gist + link) to the map's Decisions-so-far.
