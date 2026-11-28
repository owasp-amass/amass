# Data source credentials

Engines and tools that share an Asset Database can share data source
credentials through it, so a key added once is used by every engine on the
database. The database holds only ciphertext; the master key stays with the
processes.

## Providers

`secrets.Fill` gives a session's configuration credentials when it starts
(`engine/sessions/credentials.go`). A data source takes all of its
credentials from the first provider that has any:

1. The datasources file (`options.datasources`), as before.
2. The environment: `AMASS_SECRET_<SOURCE>_<FIELD>`, the source's name in
   capitals with anything but letters and digits as `_`, such as
   `AMASS_SECRET_SHODAN_APIKEY`. Fields are `apikey`, `secret`, `username`
   and `password`.
3. The database store, when the process has the master key.

A source the file doesn't list is added with the file's `minimum_ttl`.
Filled credentials are kept under the account `shared`. A source whose name
has punctuation is matched to the file and the store through
`secrets.SourceKey`. A source that only the environment names gets the
key's name in lower case, so give such a source a file entry or use the
store, which keeps the exact name.

## The store

asset-db's `repository.SecretStore` (PostgreSQL and SQLite) keeps
`secret` rows: name, ciphertext, nonce, key ID, time and who set it.
`internal/secrets.Store` encrypts with AES-256-GCM:

- The secret's name is `<source>/<field>`, and it's the additional
  authenticated data, so a ciphertext copied to another name doesn't open.
- The master key is 32 random bytes, base64, in `AMASS_SECRETS_KEY` or the
  file `AMASS_SECRETS_KEY_FILE` names. Its ID is the first 8 bytes of its
  SHA-256, in hex.
- A secret under another key ID is skipped, not an error, so engines mid-
  rotation keep running on what they can open.
- Every change is appended to the journal's `secrets` topic with the name,
  actor and key ID, never the value.

Without the master key, or on a database without the store (Neo4j),
`secrets.Open` returns nil and the other providers still work. There,
`amass secrets` says to use the data sources file or the environment.

## Tools

`amass secrets` (`internal/secrets/cli`):

- `new-key` prints a new master key.
- `set <source> <field>` stores the value on standard input, never a flag,
  so it stays out of the process list.
- `list` shows source, field, key ID, time and actor, without values.
- `delete <source> [field]` removes one field, or all of a source's.
- `rotate` re-encrypts every secret the current key opens under the key on
  standard input. Give every engine and tool the new key afterwards.

The MCP server's `data_source_key_link` page writes to the store when the
server has the master key, and `data_sources` reports each source's
provider (`credentials_from`; sources not listed there use the file).

## Compose

`scripts/up` makes `data/state/.secrets-key` (mode 0600) the first time, and
the engine, `ai`, `mcp`, `mcp-stdio` and `secrets` services read it through
`AMASS_SECRETS_KEY_FILE`. The `secrets` service runs `amass secrets`:
`docker compose run --rm -T secrets set Shodan apikey < shodan.key`. The key
file isn't committed; back it up with the database, since the store can't be
read without it.

## Credentials found exposed

The `Exposed-Secrets` plugin (`engine/plugins/leaks`) scans what the
enumeration stored with `internal/secretscan` (formats in
`internal/semantics/secret_patterns.json`): URLs, including their decoded
query strings, service banners and response headers, and TXT records.

- An identifier (an AWS access key ID, an AWS account ID from an ARN) is an
  `Identifier` in full, linked by `discloses` from where it was found. An
  access key ID is linked by `cloud_account` to the account it carries
  (`secretscan.AWSAccountFromKeyID`).
- A secret is an `exposed_secret` Identifier, `<kind>:<SHA-256>`, with the
  properties `secret_kind` and `secret_preview` (masked). Its value is sealed
  in this store as `found:<kind>:<hash>` (`Store.PutFound`) when the process
  has the master key; without one only the hash and preview are kept.
  `Store.Found` opens it again. Found credentials are never data source
  credentials: `Values` and `List` skip them, and `Rotate` re-seals them with
  the rest.
- Found credentials are never used or tested.

### Reading a found credential

`amass secrets found <reference>` prints a found credential's value, where
the reference is the `exposed_secret` Identifier's ID, with or without the
`exposed_secret:` prefix (`exposed_secret:github_token:<hash>`). It needs the
master key, like every other `amass secrets` command, and each read is
audited with the operator as the actor (`Store.Found`). The value is shown
only there: never in a lens, an MCP result, a model's prompt or a log.

### What models see

Every model provider (`internal/ai/llm`: Anthropic, Ollama and the
OpenAI-compatible client) passes the history through `llm.Masked` before a
request, so a credential in any message, a tool result included, reaches the
model as its kind and masked preview (`secretscan.Mask`). Identifiers, such
as AWS account and access key IDs, stay whole. The caller's history is not
changed.

### The leaked credentials exposure class

The exposure lens reports `leaked_credentials` ("Leaked credentials") for each
credential an asset of the footprint discloses: its kind, masked preview,
where it was found (masked too, since a URL's query can carry the key), the
AWS account of an access key ID found beside an AWS key, and the reference
`amass secrets found` takes. A credential found only outside the footprint is
not reported. It reads with one value search for `exposed_secret`
Identifiers, then each one's incoming `discloses`. The report lists it first
among its key findings: it is the only priority 1 finding in
`internal/semantics/report.json`.
