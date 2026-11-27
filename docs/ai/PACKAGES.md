# Package registry namespaces

The `Package-Registries` plugin (`engine/plugins/packages`) reads each in-scope
registered domain's published packages; the catalog is
`internal/semantics/package_registries.json`.

**Maven Central:** the groupId is the domain reversed (`mavenGroup`). The
search API is queried with `g:<group>` and `g:<group>.*`; only artifacts in the
group or a group under it are kept, newest first, at most `max_packages`. The
newest version's POM is read for the first `max_poms` artifacts (`parsePOM`):
`<url>` (role `project`), `<organization><url>` (`organization`), `<scm><url>`
(`repository`), and `<organization><name>`, which becomes the Product's
`manufacturer` through `org.CreateOrgAsset`. Values holding `${…}` are skipped.

**npm:** the registry search is queried with `text=<domain>`. A package is
kept when its publisher's or a maintainer's address is at the domain
(`ownAddress`) or its homepage is on it (`ownHost`). Its namespace is its scope,
or `~<publisher>` for an unscoped package.

**Storage (`store`):**
- `Account{unique_id: <registry>:<namespace>, account_type: package_namespace}`;
  `namespace_domain` → the apex FQDN for a Maven group (named for it) or an npm
  namespace with a maintainer address at it. Those addresses are the
  namespace's `ContactRecord` (`Account --contact--> ContactRecord --id-->`
  email `Identifier`), keyed by the registry's namespace page
  (`pkg.namespacePage`).
- `Product{unique_id: purl, product_name, product_type: software_package,
  category: maven|npm}` joined by `package`, with `id` → a `purl` Identifier.
- Each http(s) URL becomes `Product --website--> URL` with a `url_role` edge
  property, and is dispatched. Code-host and registry URLs are kept for later
  evidence; `packageURL` drops only other schemes.

The controlled-footprint walk (`lens.platformStep`) does not pass control or
ownership between a URL and its host when the host is a shared platform
(`lens.SharedPlatformHost`: `semantics.AccountPlatformHost`, the code hosts and
social sites of `account_platforms.json`, or a `registry_hosts` site). The URL
stays in the footprint; the platform's domain does not. This also covers an
organization's `social_media_profile` and `website` URLs on those hosts.

`namespace_domain` is an `attribute` relation in `oam_relations.yaml`, so
control does not flow through it in the controlled-footprint walk. The
evidence comes from the related-domains lens instead (`lens.packagePivot`):
from each own apex through `namespace_domain`, `package` and `website`, the
organization URL of a Maven package is `package-publisher-site` (strong); any
other package URL is `package-website` (supporting). URLs on shared platforms,
`hosting_domains` (each project its own subdomain) and cloud hosting domains
give no signal (`publisherHost`). See `HORIZONTALS.md`.
