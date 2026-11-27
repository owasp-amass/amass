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
