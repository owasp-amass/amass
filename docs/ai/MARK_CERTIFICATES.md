# Mark certificates (BIMI)

The `BIMI` plugin (`engine/plugins/bimi`) reads each in-scope apex's `default._bimi` TXT record and fetches the PEM named by its `a=` tag. A certificate with the BIMI extended key usage (1.3.6.1.5.5.7.3.31), valid now, that lists the apex in its DNS names is stored and dispatched to the certificate handler with the parsed certificate as event meta, so its names and subject ContactRecord are stored as for any certificate and it takes part in this signal and the certificate subject evidence. The plugin adds the mark details to the subject ContactRecord (key `x509 Certificate: <serial>, Subject`): a `trademark` Identifier `<country>:<registration number>` whose trademark office is its issuing authority (`Identifier --issuing_authority--> ContactRecord --organization--> Organization`, ContactRecord key `x509 Certificate: <serial>, Trademark Office`), an `lei` Identifier, and `mark_type` and `word_mark` properties, read from the subject attributes defined in the BIMI Group VMC Requirements (OIDs 1.3.6.1.4.1.53087.1.2–.6 and .13). The BIMI record's logo (`l=`) is the subject ContactRecord's `url`; the certificates lens reads both through `certificates.json` (`authority_label`, `logo_label`).

Because the certificate is stored like any other, it feeds the existing
certificate signals (see `SIGNALS.md`, "Listed on the organization's
certificate") and the certificate subject evidence; the plugin adds no signal
of its own. Only valid mark certificates that list the queried apex are kept,
so a BIMI record pointing to another organization's certificate adds nothing.
