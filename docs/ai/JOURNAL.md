# The review journal and the coordination log

The review journal holds the proposals, the decisions about them and their
undo records, the document readings, and the decisions the AI made on its
own. Everything that reads or writes it goes through `review.Journal`.

## Where it is kept

`review.OpenJournal(path, repo)` returns the journal for a configured
journal path (`options.ai.journal`, `AMASS_REVIEW_JOURNAL`, or the default
in the output directory) and the session's repository:

- **When the repository keeps the asset-db journal** (PostgreSQL and SQLite,
  `repository.JournalStore`), the review journal is the log's `review`
  topic. Every engine, MCP server and `amass` command on that database
  shares it.
- **Otherwise** (Neo4j, or no database), it is the file at `path`, with one
  JSON object `{"kind": ..., "data": ...}` per line.
- **With no path** there is no journal: `OpenJournal` returns nil, and the
  callers that need one say `-journal required`.

The journal is passed through the lens, `ai/cli`, MCP and engine code as a
`*review.Journal`, not as a path. One process can serve sessions on
different databases that share a journal path, and each still gets its
own database's journal.

- **Engine:** `support.ReviewJournal` keeps one journal per path and
  database.
- **MCP:** the operator holds the journal it opened at setup.

## Records and reading

- **Appends:** an append to the database writes a `review` record with the
  record's kind, its data, and as key the `id` (or `proposal_id`) of what it
  is about. The actor is `amass@<host>`. The database assigns the sequence
  number.
- **Reads:** `History` reads only the records after the last sequence
  number this `Journal` has read, and keeps the rest in memory, so a
  long-lived journal (an engine session, the MCP operator) reads each
  record once.
- **Readers:** the typed readers (`ScopeExpansions`, `OwnershipEntries` and
  the others) work the same on either store.
- **Snapshots:** `review.JournalOf(lines)` is a read-only journal of given
  records. `lens/cli.DecisionsSince` uses it to compare the decisions
  before and after a cursor, which counts records.
- **Incomplete lines:** a file journal reads only complete lines, so a line
  still being written is read the next time.

## Moving a file journal in

`amass review import-journal -journal <file>`:

- renames old signal IDs in the file (`migrate-signals`), then appends its
  records to the database journal in order;
- records a `journal_import` marker keyed by the SHA-256 of the file;
- does nothing on a second import of the same file;
- leaves the file in place.

While the database holds the journal, `amass review` notes a configured
file that was never imported (`Journal.FileNotImported`), because its
records aren't read. Trained adjudicator models are still files beside the
journal path.

## The log and leases

The asset-db journal is a general log: topic, kind, key, JSON data, actor,
time and the record that caused it. It's ordered by a sequence number the
database assigns, so new kinds and topics need no schema change. Leases
(`repository.LeaseStore`) give named work to one holder at a time.

`internal/coord` wraps a topic (`coord.Open(repo, name)`, `Append`,
`Read`); the review journal and the MCP runs (`runs`) and watches
(`watches`, a removal is a record with `removed` set) use it.

The `models` topic holds trained classifier models (`ai.ModelTopic`): each
record's kind is an adjudicator kind and its data the model, and
`AdjudicatorKind.LoadFor` uses the newest, falling back to the model file
beside the journal path when the database has none. `amass ai train` keeps
models there when the journal is in the database (`AdjudicatorKind.Keep`).

The `hubs` topic holds the hub thresholds (`internal/hubs`): for one kind
of shared value (a `hubs.Source`), how many holders a value may have
before the signals treat it as a provider's rather than an owner's.
`hubs.Table` derives each from a histogram of holders per value (a robust
outlier in log scale: modified z-score above 3.5, never below 5) and
appends it under the source's key:

- `<label>|<direction>`: the values a relation label links, from
  asset-db's `DegreeHistograms`;
- `<label>|<direction>|<type>.<key>=<value>`: the same, only the values
  whose attribute equals value (each fingerprint `id_type` has its own),
  from `DegreeHistogramWhere`;
- `tag:<type>|<property>|<prefixes>`: a tag's exact values starting with a
  signal's prefixes (the TXT verification tokens), from
  `TagValueHistogram`;
- `attr:<type>|<key>`: an attribute's exact values (certificate key
  identifiers), from `AttributeValueHistogram`.

Others reuse a record younger than six hours; the `hubs:<key>` lease lets
one process compute at a time. With fewer than 1,000 values of the kind,
or without the histogram read (Neo4j), the caller's fixed limit applies
(`graph.SourceHubRule`, falling back to `lens.GapMaxShared` and the other
fixed limits).

The `work` topic is what the workers of one enumeration share. Each
session's scope (`scope.Replicate`) appends a `scope_add` record, keyed by
the job, for each entry it adds after starting (the asset type, the entry,
the session that added it, and `admitted` when an admission decision added
it). Each decision a decider makes (not matching or the policy, which give
every worker the same answer) is appended as an `admission` record: the
asset, the outcome, who decided, the rationale and the evidence it was
decided on. A model's decision about an asset is made by the worker holding
the lease `admit:<job>:<type>|<key>`; the others keep the request pending
until its record arrives, or reject it as undecided after the admission
timeout. The session's follower (`followWork`, every 2 seconds) reads only
its job's records (`Topic.ReadWhere` with the job's key) and applies the
other workers': an admitted asset stays admitted, and a rejection only adds
its evidence, so the asset is decided again only on new evidence. Finding
jobs, the pool's choice and leaving a job read only the job records
(`job`, `job_worker`, `job_finished`, `job_stopped`), never the jobs'
per-asset records; asset-db's `ReadJournalFiltered` serves both reads from
the (topic, key, seq) and (topic, kind, seq) indexes.
A session's backlog is the work queue named by its job
(`repository.WorkQueue`; its leases are renewed while the session runs).

Jobs (`engine/sessions/jobs.go`): a session on a database with the journal,
leases and work queues works on a job. A new session's job is its own ID,
recorded as a `job` record holding the scope's fingerprint, the collection
run and the configuration without database settings or data source
credentials. A session of a scope a running job already covers joins it
instead (unless the option `join_running_jobs` is false): it takes the
job's configuration with its own database, credentials, resolvers,
interface, routes and AI settings, works under the job's run and queue, and
replays the job's records. Each worker appends a `job_worker` record and
holds the lease `worker:<job>:<session>`, renewed every 20 seconds with its
count of background work, which the other workers add to their progress,
and its main model's requests (`ModelBreaker.Requests`, counted for every
admission and name the model is asked about). A done work item keeps the
owner that did it, so `Session.Workers` (served at
`GET /sessions/{token}/workers`) reports each worker's leased and done items
(`CountWorkByOwner`) with its liveness, background work and model requests.
The last worker to leave (`job-end:<job>` lease) finishes the run and
appends `job_finished`, or `job_stopped` with work left; a worker leaving
others behind keeps the queue and appends `job_left` with its model
requests, which its lease no longer reports. The other workers end when
they read the job's end. A job whose worker leases have all expired is
ended, its run stopped and its queue deleted, by the next session that
looks.

One engine per public address: the engine finds its public address at
startup (`amassnet.FindEgress`, asking OpenDNS's name servers for
`myip.opendns.com` through its interface; `-egress` or `AMASS_EGRESS`
overrides it) and each session on a shared database, and each pool, holds
the lease `egress:<address>`, renewed with the worker lease. A second engine
process on the same address is refused (`errSecondEngine`). The lease is not
released when a session ends; it expires a minute after the engine's last
session. One worker per engine: `manager.NewSession` gives a client the
engine's session already working on the running job of its scope on its
database (`workingOn`, reported as joined), and counts clients, so
`CancelSession` ends the session only for its last client; a job's end ends
it for all (`endSession`).

Pool workers (`amass engine -worker -config <file>`, `sessions.StartPool`):
every 15 seconds, an engine with room (fewer pool sessions than
`-worker-sessions` or `AMASS_WORKER_SESSIONS`, default 5) joins the running
job with the most queued work per live worker (the older job on a tie),
other than the jobs its sessions already work on (`manager.jobs`) and the
jobs at their cap on live workers (the option `max_job_workers` in the job
record's configuration; 0 or unset is no cap), using its configuration's
database and credentials, and leaves a job after five checks in a row with
no work left. The cap holds pools back only: an engine asked for the job's
scope joins it, and two pools checking at once may each take the last
place.

`coord.Leases` takes them for this process (`Try`, and `Hold`, which renews
a lease every third of its time until released; a database without leases
gives every one):

- `run:<id>`: the manager supervising a run, renewed while it does. A
  manager resuming at startup leaves a run another holds to it, rather than
  supervising it twice or marking it lost.
- `watch:<id>:<due time>` and `watch-summary:<run>`: the server that starts
  a watch's due run, and that summarizes its finished run.
- `doc:<sha256>`: the engine reading a document version, renewed while it
  reads; the others count it as remaining and see it read in the journal.
- `sweep:merge-duplicates`: the engine applying merges; another engine's
  duplicate search records its proposals without applying them meanwhile.

Planned: one enumeration spread across the engines on a database, where
the job record carries the job's complete effective configuration without
data source credentials, and each engine finds the keys through the
providers in [SECRETS.md](SECRETS.md).
