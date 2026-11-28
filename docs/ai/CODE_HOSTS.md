# Code-host organizations

The `Code-Hosts` plugin (`engine/plugins/codehost`) reads an organization's
public GitHub and GitLab organizations from each in-scope registered domain;
the catalog is `internal/semantics/code_hosts.json`.

**Candidates (`candidates`):** the GitHub and GitLab accounts the
organization's stored `website` and `social_media_profile` URLs name
(`semantics.AccountHandle`, which the accounts lens also uses), then the
GitHub organization named for the domain's first label (`owasp.org` is
`github.com/owasp`). Each is read once per session.

**Tie:** a named account is the organization's own. A guessed GitHub
organization is kept only when its profile's website or email is in the
footprint (`support.Footprint`: the domain searched for and every domain in
scope); otherwise nothing past its profile is read. A GitLab group names no
website, so only a named group is read.

**GitHub budget:** GitHub answers 60 unauthenticated requests an hour, so the
engine shares one budget of `github.requests_per_hour` (`githubBudget`), first
come first served. A request with no budget left is not made. A tied
organization costs three requests: its profile, its public repositories and
its public members.

**Storage (`store`):**
- `Account{unique_id: <host>:<handle>, account_type: code_host_organization}`,
  `Organization --account--> Account` when the domain's organization is known,
  and `namespace_domain` → the footprint domain that tied it (the domain
  searched for when it was named).
- The profile as the account's `ContactRecord`, keyed by its page: the website
  URL, the email Identifier and the organization it names.
- `verified_domain: true` when GitHub shows the organization verified a
  domain (GitHub does not say which).
- Each repository that is not a fork as `repository` → URL, and the profile's
  and repositories' homepages as `website` → URL, dispatched so scope decides
  what is collected from them.
- Public members as `code_host_user` Accounts (`member`). No Person is created.

Commit emails are not read: they cost one request per repository, which the
unauthenticated budget cannot cover.
