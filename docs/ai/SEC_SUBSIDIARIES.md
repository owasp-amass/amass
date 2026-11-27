# SEC subsidiary lists (Exhibit 21)

The `SEC-EDGAR` plugin's filings handler (`engine/plugins/api/edgar`) resolves
an Organization to its CIK by name, then reads the subsidiaries the registrant
lists in its newest annual report (`exhibit21.go`):

- **Filing:** the newest `10-K` / `10-K405` (exhibit type `EX-21`, Regulation
  S-K Item 601(b)(21)) or `20-F` (exhibit type `EX-8`) in the submissions
  feed's recent filings. Amendments are skipped because they usually refile
  only some parts.
- **Exhibit:** found in the filing index page's document table
  (`<accession>-index.htm`, columns Seq, Description, Document, Type, Size);
  `EX-21` matches `EX-21` and `EX-21.1` but not `EX-210`. An iXBRL link
  (`/ix?doc=`) is reduced to its archive path. Documents over 4 MiB are
  skipped.
- **Parsing:** table rows first (name in the first cell after an optional row
  number, the jurisdiction in the first later cell that resolves to one, or a
  short second cell kept as written); otherwise lines of text with the
  jurisdiction in trailing parentheses, after a column gap, or after
  `, ` / ` - `. A line with no jurisdiction counts only when it ends in a
  company form. Headings ("Subsidiaries of ...", "Name of subsidiary",
  jurisdiction-only rows) and footnote markers are dropped. At most 5,000
  entries are kept per filing as a guard against a misread exhibit.
- **Jurisdictions:** `semantics.JurisdictionCode` (catalog
  `internal/semantics/jurisdictions.json`) maps US states, Canadian provinces,
  the parts of the United Kingdom and US spellings to GLEIF-style codes
  (`US-DE`, `CA-ON`, `GB`, `US`); other country names go through the country
  lookup, which is given whole names only so that two- and three-letter words
  are not read as country codes. `org.CreateOrgAsset` dedups on the code, so a
  subsidiary GLEIF also reports converges on one record.
- **Storage:** each subsidiary is created through `org.CreateOrgAsset` with
  the registrant as the subject of a `subsidiary` edge at the EDGAR source
  confidence (80, since the CIK is matched by name), as GLEIF's child records
  are. Every subsidiary is dispatched; each collector's monitoring TTL keeps
  later runs from repeating its lookups for the same organizations.
