# Zeus Repository Audit

Status: approved design; not yet implemented.

## Purpose

Zeus will provide a host-local, report-only repository audit. The operator runs
one command from a Git worktree, Zeus analyzes the committed `HEAD` in an
isolated disposable environment, and Zeus stores a bounded report under its
existing state directory.

The first version is intentionally narrow:

- It reports findings but never edits tracked source or pre-existing worktree
  entries. Its only host writes are confined to the effective Zeus state path.
- It never commits, pushes, deploys, publishes, or contacts application
  production services. The configured model provider is the only intentional
  external service boundary.
- It does not add a general plugin platform or enable template-provided skills.
- It does not add an HTTP API, a SQLite migration, or cross-host coordination.
- It does not audit dirty or untracked worktree content.

## Chosen Architecture

The audit is a native Zeus capability composed of a deterministic safety runner
and a bundled Hermes-compatible skill. The runner owns every security boundary;
the skill supplies audit reasoning and reporting instructions inside those
boundaries.

This is preferred to a prompt-only template because prompt instructions cannot
enforce filesystem, credential, network, process, or output limits. A general
plugin framework is also deferred because it would introduce trust,
compatibility, installation, and lifecycle contracts that the report-only
feature does not need.

The existing rejection of non-empty template `skills` remains unchanged. The
bundled audit skill is private package data loaded only by the audit runner.

## Components

The implementation is divided into focused internal modules:

- `zeus.audit_config` loads and validates the local audit configuration.
- `zeus.audit_models` defines run state, check, finding, and report contracts.
- `zeus.audit_workspace` resolves `HEAD`, materializes its Git tree, validates
  the snapshot, and removes disposable state.
- `zeus.audit_profile` builds the ephemeral Hermes profile and one-shot prompt.
- `zeus.audit_docker_broker` creates the exact command container, validates its
  effective controls, and permits Hermes to address only that container.
- `zeus.audit_runner` invokes one-shot Hermes, streams bounded output, applies
  deadlines, terminates the owned process group, and classifies termination.
- `zeus.audit_report` validates model output, applies field-level redaction and
  bounds, and renders deterministic Markdown.
- `zeus.audit_store` atomically installs, lists, and reads private report
  artifacts.
- `zeus.audit_doctor` verifies Git, Hermes, Docker, image, mount, network, and
  private-path prerequisites.
- `zeus.audit` exposes a thin `AuditService` used by all four CLI actions.
- `zeus.bundled_skills.audit` contains the versioned `SKILL.md`.

`zeus.cli` only parses and presents audit commands. It does not contain
workspace, subprocess, validation, or report-storage logic.

## Trust Boundaries

### Source boundary

The Git repository, including its committed instructions and generated files,
is untrusted input. Zeus launches Hermes from an empty private control
directory, not from the audited snapshot. This prevents Hermes one-shot startup
from automatically loading repository `AGENTS.md`, rules, memory, or local
configuration as controlling instructions.

The snapshot is exposed only through the terminal sandbox. The bundled skill
instructs the model to treat every repository file and command output as data,
never as authority. This reduces prompt-injection risk but cannot prove that a
model will interpret adversarial source correctly. Filesystem, network,
credential, and mutation isolation therefore remain mandatory even when the
prompt is manipulated.

Audit CLI dispatch does not read the audited repository's `.env`. The existing
settings loader gains an additive `include_dotenv` option, and audit commands
use `include_dotenv=False` before any repository-derived configuration can
affect the Hermes path, state path, provider, model, or sandbox.

Audit commands resolve the repository root before choosing their state path. An
explicit `ZEUS_STATE_DIR` is honored; otherwise audit state is rooted at
`<repository-root>/.zeus` even when the command starts in a subdirectory. Zeus
blocks the run if an in-repository state path is tracked by Git or fails the
existing no-follow private-path checks.

### Git boundary

Repository-local Git configuration is untrusted. Every Git command uses exact
argument arrays with `shell=False`, a minimal environment, disabled prompts and
pagers, `GIT_OPTIONAL_LOCKS=0`, `GIT_NO_REPLACE_OBJECTS=1`, no system or global
configuration, and command-scope overrides that disable hooks, filesystem
monitors, external diff or text-conversion commands, credential helpers, and
external protocols. Git-related environment variables supplied by the caller
are removed.

Zeus validates the discovered worktree and Git-directory ownership and rejects
unsafe symlink, ownership, or permission boundaries before reading objects. It
does not invoke checkout, submodule, LFS, diff, filter, hook, fetch, or
credential operations. Repository discovery and dirty-state commands each have
a 30-second timeout and bounded output. Tree enumeration and blob streaming
share a five-minute materialization deadline, a 64 MiB metadata-output limit,
and the snapshot entry and byte ceilings.

The overall audit deadline begins before the first Git subprocess. Git failure,
timeout, unexpected output, or an unenforceable configuration override blocks
analysis rather than falling back to a less constrained command.

### Filesystem boundary

Zeus resolves the repository root and exact `HEAD` commit, enumerates its tree
with NUL-delimited `git ls-tree`, and reads blobs through one bounded
`git cat-file --batch` process. It does not use checkout filters, Git LFS,
working-tree files, or export attributes. A defensive materializer accepts only
regular files, executable files, and confined relative symlinks, and rejects:

- absolute paths or `.` and `..` components;
- any path component whose case-folded name is `.git`;
- hard links, devices, FIFOs, sockets, and unsupported entry types;
- symlinks whose normalized target escapes the snapshot;
- duplicate paths and file/directory type conflicts;
- trees exceeding 100,000 entries or 1 GiB of materialized blob data.

Gitlinks and unresolved Git LFS pointer content are not fetched. They are
recorded as skipped external content in the report metadata.

The snapshot contains no `.git` directory, remotes, worktree metadata, or Zeus
state. Zeus copies it into a size-limited container tmpfs at `/workspace` before
analysis and validates the copy. The command container has no host bind mounts.
The real source worktree, audit control directory, Hermes home, Docker socket,
user home, caches, and credential paths are never mounted.

The workspace tmpfs is created with the audit UID and GID. Zeus seeds it through
the Docker archive interface using normalized ownership while preserving
regular-file modes and confined symlink targets. Before validation is sealed,
Zeus compares the copied manifest and executes a write-and-delete probe as the
same unprivileged UID used for every audit command. Ownership normalization
occurs through the trusted Docker daemon, not through a privileged process in
the command container.

Writes inside `/workspace` are allowed so builds and tests can operate normally.
They consume only the bounded tmpfs and disappear with the container. Zeus
itself may write only its private audit state and final report artifacts.

### Network boundary

Hermes runs as a host process because the selected model provider requires
egress. Repository-side tools run in one Zeus-created Docker container with
network mode `none`.

Hermes does not receive direct access to the Docker executable or socket. Zeus
places a private `docker` broker first in the subprocess `PATH`; the broker uses
an already-resolved absolute Docker executable and implements only the pinned
Hermes Docker command grammar. It permits bounded version and configured-image
inspection, emulates the backend's storage-capability probe without starting a
probe container, and emulates its label-filtered reuse lookup by returning the
prevalidated run container. It permits execution, inspection, and removal only
for that exact container ID. Unknown argument shapes, other IDs, real container
creation from Hermes, and attempts to change mounts, namespaces, security
controls, or networking fail closed.

Zeus creates and seeds the actual command container before starting Hermes. It
then inspects that container and requires all of these effective properties:

- network mode `none`;
- empty forwarded environment and no host bind mounts;
- a fixed unprivileged numeric user, all Linux capabilities dropped,
  no-new-privileges,
  Docker's default seccomp policy, and no host/device/privileged namespaces;
- a read-only container root filesystem with bounded temporary storage and the
  workspace and temporary tmpfs paths as its only writable locations;
- fixed CPU, memory, PID, temporary-storage, and command limits;
- an immutable, digest-qualified image that is already present locally;
- Docker pull policy `never`.

The broker records the validated container ID in private run state before it
will service an execution request. It caps each execution's output and call
duration, updates an aggregate run ledger, and removes the exact container if a
limit is exceeded. Hermes receives the prevalidated container ID through the
broker instead of creating or reconfiguring a container through its normal
Docker path. The ephemeral Hermes profile enables its reuse branch only for
this handshake; unique run labels and the private broker prevent reuse across
runs.

The broker protocol is versioned against the supported Hermes release. A
pinned-Hermes integration test must exercise the complete version, image
inspection, capability probe, reuse lookup, execution, network inspection, and
cleanup sequence. Any new or reordered Docker command is a compatibility
failure until the broker policy is reviewed and updated.

`audit doctor` checks that the platform can enforce the same controls, but every
run separately inspects its actual container before any repository command or
source-bearing model request. A missing, degraded, or unverifiable control
blocks the run. There is no fallback to Hermes's local terminal backend, and
configuration cannot enable terminal network access in version 1.

### Provider boundary

Zeus, the supported Hermes release, the local Docker daemon, the immutable
audit image, and the operator-selected model provider are trusted components.
Invoking `audit run` authorizes Hermes to send the audit prompt, selected source
excerpts, and command output to that provider. Zeus does not claim that the host
Hermes process is network-isolated from its provider, or that a third-party
provider has local retention semantics.

The skill requests targeted evidence rather than bulk repository output, and
all tool results remain bounded, but Zeus cannot guarantee that no committed
source text reaches the selected provider. Operators requiring that property
must configure a compatible local provider. The provider and model are shown
by `audit doctor` and recorded in report metadata. No terminal-side process can
use the provider connection.

### Credential boundary

The host Hermes subprocess receives a minimal environment and only the model
provider variables explicitly named in audit configuration. Configuration
stores variable names, never values. Values are read at invocation and are not
written into the ephemeral Hermes home, prompt, snapshot, command sandbox,
usage metadata, or reports.

Provider variable names must match the existing environment-name grammar and
each value is capped at 16 KiB before process creation.

The subprocess receives a synthetic `HOME` in the private control directory and
an ephemeral `HERMES_HOME`. Beyond the explicitly selected model-provider
variables, Git, SSH, infrastructure-cloud, package-registry, deployment,
messaging, and Docker credentials are neither inherited nor mounted. The
bundled skill declares no required environment variables or credential files.

### Model and output boundary

Zeus reads the packaged `SKILL.md` itself and embeds its exact versioned content
in a fresh one-shot prompt. Hermes skill discovery and management are not
enabled. Only the `terminal` toolset is enabled; memory, web, browser,
delegation, cron, messaging, MCP, file-editing, skill-management, and the
separate code-execution toolset are unavailable.

The final response must be one JSON object. Zeus reads at most 1 MiB from model
stdout, does not retain raw model output, and accepts only the documented
schema. A bounded redacted diagnostic excerpt may be included when parsing
fails. Markdown is generated deterministically from validated JSON rather than
accepted from the model.

Hermes stderr is separately capped at 256 KiB, redacted, and used only for a
bounded failure diagnostic. Output beyond either cap terminates the run-owned
process group and makes the report incomplete.

## Configuration

Configuration is optional JSON at:

```text
$ZEUS_STATE_DIR/audit/config.json
```

The directory is mode `0700` and the file is mode `0600`. Unknown fields and
invalid types fail closed. Schema version 1 supports:

- `provider` and `model`: optional explicit Hermes selection;
- `provider_env`: at most four environment-variable names made available only
  to the host Hermes process;
- `image`: an immutable Docker digest or digest-qualified reference;
- `categories`: a non-empty subset of the six supported categories;
- `exclude_paths`: repository-relative paths removed from the snapshot after
  safe materialization;
- `suggested_commands`: named argument arrays shown to the skill as preferred
  local verification commands, never shell strings;
- `limits`: bounded overrides for run duration, command duration, finding
  count, model output, report artifacts, snapshot entries, and snapshot bytes.

Version 1 has these hard ceilings:

- one concurrent audit per repository;
- 60 minutes overall, beginning before repository discovery;
- 30 seconds for each discovery or dirty-state Git command, five minutes for
  tree materialization, and 60 seconds for each Docker control operation;
- 10 minutes per terminal command, 64 terminal calls, 80 model iterations,
  2 MiB of combined output per terminal call, and 16 MiB across all calls;
- 2 CPUs, 4 GiB of memory, 256 processes, a 2 GiB workspace tmpfs, and 512 MiB
  of other temporary storage;
- 100 findings, 1 MiB of model stdout, and 1 MiB for each final artifact;
- 256 KiB of Hermes stderr and 16 KiB per selected provider variable;
- 100,000 snapshot entries, 64 MiB of Git metadata output, and 1 GiB of
  materialized blob data.

Configuration may lower run, command, finding, output, and snapshot limits but
cannot raise these ceilings. CPU, memory, process, tool-call, model-iteration,
temporary-storage, credential, and isolation limits are not configurable.

Each Zeus release defines a digest-qualified default audit image. An `image`
override must also be digest-qualified and locally present. Zeus never pulls an
image. Omitted provider and model values use Hermes defaults; when that provider
requires a credential, `provider_env` must name the required variable or
preflight blocks the run. Model stdout and each final report artifact are
individually capped at 1 MiB.

The six supported categories are:

1. security and trust boundaries;
2. correctness and reliability;
3. tests and continuous integration;
4. architecture and maintainability;
5. dependency and configuration hygiene using local evidence;
6. documentation and operational readiness.

## CLI Contract

Version 1 adds four local commands:

```text
zeus audit doctor [--json]
zeus audit run [--json]
zeus audit list [--json]
zeus audit show <run-id> [--json]
```

`audit doctor` performs all non-model preflight checks. It does not create a run
or download dependencies.

`audit run` audits the repository containing the current directory. Human
output contains a concise status, finding counts, target commit, and relative
report path. JSON output emits the final report envelope. Exit status is zero
only for `completed`; `partial`, `blocked`, `failed`, and `cancelled` return
nonzero.

If the effective state directory is inside the worktree and is not ignored,
audit artifacts can appear as new untracked state paths. Zeus does not modify
`.gitignore` or `.git/info/exclude`; it reports this condition during preflight.

`audit list` reads validated report envelopes and sorts newest first. Human
output shows run ID, status, target commit, time, and severity counts.

`audit show` validates the run ID before accessing storage. Human output prints
the generated Markdown report; `--json` prints the JSON report.

No audit command initializes `StateStore`, changes SQLite, starts a gateway, or
uses the public bot lifecycle facade.

Audit dispatch occurs before the normal CLI service construction, and audit
settings are loaded without repository `.env` input.

## Execution Flow

`zeus audit run` performs these steps:

1. Start the overall deadline and perform bounded repository-root discovery
   without following a caller-supplied path. Discovery failure is a pre-run CLI
   error and creates no artifact.
2. Derive an opaque repository ID from the canonical repository root and acquire
   `$ZEUS_STATE_DIR/locks/audits/<repository-id>.lock`. A concurrent run for the
   same repository fails without creating or changing a run.
3. Create a private control directory under
   `$ZEUS_STATE_DIR/audit/workspaces/<run-id>`, where the run ID is UUID hex.
4. Re-resolve and validate the worktree, Git directory, and exact
   `HEAD^{commit}` under the lock, then record whether tracked, staged, or
   untracked changes exist. File names and contents are not copied into
   metadata. Failure from this point produces a `blocked` run.
5. Materialize the exact committed tree, apply validated exclusions, and verify
   that `.git` is absent.
6. Create an ephemeral Hermes home containing only generated non-secret config,
   then load the packaged skill text into the one-shot prompt.
7. Through the Docker broker, create the exact command container, seed its
   tmpfs workspace, inspect every mandatory control, and seal its private
   container record against replacement.
8. Start Hermes in a new process group with only the broker-visible Docker path
   and with the remaining run deadline, terminal limits, and model-iteration
   limit enforced independently.
9. Validate, bound, redact, and normalize the final JSON response.
10. Terminate remaining run-owned processes, remove the exact run-owned
    container if present, and attempt to destroy the snapshot and ephemeral
    Hermes home.
11. Build authoritative run metadata after cleanup, including any cleanup
    failure, and render `report.md` from `report.json`.
12. Atomically install both files in the final run directory and release the
    lock.

On the next invocation, Zeus may remove stale staging directories or containers
only when their private metadata and unique Zeus audit labels identify them as
expired audit-owned resources. It never deletes an unlabeled or ambiguous
resource.

## Report Contract

Reports are stored at:

```text
$ZEUS_STATE_DIR/audits/<run-id>/report.json
$ZEUS_STATE_DIR/audits/<run-id>/report.md
```

Run directories are mode `0700`; report files are mode `0600`. Zeus writes both
files into a sibling staging directory, validates their final sizes, syncs
them, and renames the staging directory into place. Existing reports are never
replaced.

`zeus.private_io` gains bounded whole-file reading and atomic private-byte
writing so config and report operations retain its descriptor-relative,
no-follow protections. Report fields use `redact_secrets` and `sanitize_text`
individually; the existing lifecycle-detail sanitizer is not used as a report
container because its smaller lifecycle-event limit is a different contract.

The JSON envelope has schema version 1 and contains:

- `run_id`;
- an opaque repository ID, never an absolute repository path;
- `status`: `completed`, `partial`, `blocked`, `failed`, or `cancelled`;
- authoritative metadata: Zeus, Hermes, skill, and image versions; target
  commit; UTC start and finish times; termination reason; model and provider;
  and whether worktree changes were excluded;
- bounded summary text;
- checks run and skipped, with name, disposition, duration, and redacted
  observation but no raw command output;
- findings;
- severity counts and report completeness.

Fields unavailable at the point a run is blocked are `null` rather than
guessed. In particular, target commit, Hermes version, image digest, provider,
and model become required only after their corresponding preflight succeeds.

Each final finding receives a unique Zeus-generated ID and has:

- category;
- severity: `critical`, `high`, `medium`, `low`, or `note`;
- confidence: `high`, `medium`, or `low`;
- bounded title;
- one to four bounded evidence entries;
- bounded impact;
- bounded recommendation;
- bounded verification suggestion.

An evidence entry has one of three explicit forms:

- `source`: a repository-relative regular text file, existing start and optional
  end line, and a bounded observation;
- `check`: the name of a check present in the report and a bounded observation;
- `repository`: a bounded observation about an absent or repository-wide
  property plus the bounded inspection method that established it.

Source paths may not be absolute, traverse parents, or point into excluded
content. Check references must resolve to an actual recorded check. A
repository-level absence claim must name the bounded listing, search, or
configuration inspection used to establish it. Invalid findings are rejected
individually and counted. If rejection or truncation makes the report
incomplete, the run cannot be `completed`.

## Failure Semantics

Status classification is authoritative Zeus behavior:

- `completed`: all mandatory isolation checks passed and a complete valid
  report was installed.
- `partial`: isolation held and at least one valid finding or check result was
  recovered, but timeout, truncation, invalid entries, or a tool failure made
  the report incomplete.
- `blocked`: analysis did not start because Git, Hermes, Docker, image,
  credential, or isolation preflight failed after the run lock was acquired.
- `failed`: analysis started but no usable report could be recovered, or final
  artifact installation failed.
- `cancelled`: Zeus handled an operator interrupt or termination request.

A process timeout sends termination to the audit process group, waits a bounded
grace period, then escalates only against the exact run-owned processes. Cleanup
failure is recorded and makes an otherwise complete run partial. Abrupt host
termination may leave private staging state, which the next invocation handles
through the ownership rules above.

No failure path fabricates a complete report, mutates an older report, falls
back to host-local command execution, enables network access, or automatically
retries a model request. Lock contention is a CLI conflict and creates no run.
If final artifact installation fails, the CLI emits a bounded failure envelope
but no final run directory; older reports remain untouched.

## Compatibility

The feature is additive and host-local:

- Existing CLI commands, output, and exit behavior remain unchanged.
- Existing HTTP routes and OpenAPI remain unchanged.
- SQLite schema version 6 and `StateStore` remain unchanged.
- Hermes bot profiles, template schema, renderer behavior, and lifecycle
  ordering remain unchanged.
- Runtime Python dependencies remain standard-library only.
- Git, the supported Hermes release, Docker, and a preloaded immutable audit
  image are external runtime prerequisites for audit commands only.
- The existing generic Hermes adapter is not reused because it loads complete
  profile environments, permits generic passthrough, and buffers unbounded
  output. Audit subprocess construction has its own strict environment and
  streaming limits.

The first implementation supports the same POSIX environments as Zeus's private
state protections. Provider-backed end-to-end verification remains an explicit
environment-dependent gate and is not inferred from fake-Hermes or static
tests.

## Verification and Acceptance

Unit tests cover:

- configuration defaults, strict parsing, bounds, and unknown fields;
- Git root and `HEAD` resolution;
- dirty and untracked content exclusion;
- exact Git-tree materialization, symlink handling, entry limits, and byte
  limits;
- path confinement, exclusion behavior, normalized seed ownership, copied
  modes and symlinks, and unprivileged workspace writeability;
- minimal host environment and empty terminal environment forwarding;
- Docker-broker command filtering, exact-container identity, inspection
  requirements, execution and aggregate output ledgers, and fail-closed
  handling of unsupported Hermes Docker behavior;
- report schema validation, evidence verification, redaction, size limits,
  deterministic Markdown, and atomic installation;
- run locking, status classification, cancellation, timeout, and stale cleanup;
- CLI human and JSON output plus exit behavior;
- installed-wheel access to the bundled skill.

Fake-Hermes integration tests cover a complete report, mixed valid and invalid
findings, malformed output, oversized output, nonzero exit, timeout, interrupt,
and cleanup failure.

A pinned-Hermes integration test drives the supported release through the
broker's exact initialization, in-run reuse, terminal execution, inspection,
and cleanup handshake. It requires the prevalidated container to be reused and
fails on every unexpected Docker argument shape.

Docker isolation tests prove that an audit command can write inside the
snapshot but cannot:

- observe `.git`;
- read a sentinel from the real worktree, host home, or host environment;
- resolve DNS, connect externally, or reach a service bound to the host's
  loopback or container gateway;
- access the Docker socket or host credential paths;
- persist a child process or file after cleanup.

The test also inspects the effective container network mode and mounts rather
than trusting configuration text. It asks the broker to address a different
container, start a second container, add a mount or capability, and execute
before validation; every request must fail. Tracked source content and all
pre-existing Git status entries must match their pre-run values. Any new host
path must be confined to the effective Zeus state directory.

The implementation is accepted when targeted unit and fake-Hermes tests pass,
the Docker isolation test passes on Linux, the wheel contains and can load the
skill, repository checks pass, and no existing CLI, API, schema, marker, or
lifecycle contract changes.

## Scheduling Boundary

Scheduling is a separate follow-up phase. A host-local systemd timer or launchd
job may invoke the same `zeus audit run` command and consume its exit status.
Scheduled execution receives no additional tools, credentials, network,
authority, or report behavior.

The first version does not send notifications, open issues, create branches,
commit, push, deploy, or remediate findings. Cross-host placement, approvals,
rollout policy, and aggregation remain outside Zeus.
