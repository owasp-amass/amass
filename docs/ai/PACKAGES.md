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

**The footprint (`footprint`, `footprintOf`):** the domain searched for and
every domain in the session's scope. The text-searched registries keep a
package only when an address or URL it names is in the footprint
(`footprint.address`, `footprint.host`, `footprint.tiedURLs`), and record that
domain as `pkg.domain`.

**npm:** the registry search is queried with `text=<domain>`. A package is
kept when its publisher's or a maintainer's address, or its homepage, is in
the footprint. Its namespace is its scope, or `~<publisher>` for an unscoped
package.

**NuGet, crates.io, RubyGems, Packagist** (`registries.go`): each is searched
by text for the domain.
- NuGet keeps a package whose `projectUrl` is in the footprint; its namespace
  is `~<first owner>`.
- crates.io and RubyGems keep a package whose homepage or documentation URL is
  in the footprint. Their namespace is `~<first owner>`, read from the
  registry's owners list (`crates.owners`, `rubygems.owners`) for at most
  `max_metadata` packages; a package whose owners could not be read has no
  namespace, so no Account is stored and the lenses do not reach it.
- Packagist's search gives names only; the metadata of at most `max_metadata`
  packages (`repo.packagist.org/p2/<vendor>/<name>.json`) is read, and a
  package is kept when its homepage, an author's homepage or an author's
  address is in the footprint. Its namespace is its vendor, and the authors'
  addresses become the namespace's ContactRecord, like npm maintainers.
- PyPI has no search API and Docker Hub is searched only by name, so neither
  is read from a domain.

**Storage (`store`):**
- `Account{unique_id: <registry>:<namespace>, account_type: package_namespace}`;
  `namespace_domain` → `pkg.domain`: the apex FQDN for a Maven group (named for
  it), or the footprint domain that kept the package. Maintainers' and
  authors' addresses in the footprint are the
  namespace's `ContactRecord` (`Account --contact--> ContactRecord --id-->`
  email `Identifier`), keyed by the registry's namespace page
  (`pkg.namespacePage`).
- `Product{unique_id: purl, product_name, product_type: software_package,
  category: maven|npm|nuget|cargo|gem|composer}` joined by `package` (when
  the registry has namespaces), with `id` → a `purl` Identifier.
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
