package sources

type OpenUKArchive struct {
	BaseDataSource
	baseURL string
}

func NewOpenUKArchive() DataSource {
	o := &OpenUKArchive{baseURL: "http://www.webarchive.org.uk/wayback/archive"}

	o.BaseDataSource = *NewBaseDataSource(ARCHIVE, "Open UK Arc")
	return o
}

func (o *OpenUKArchive) Query(domain, sub string) []string {
	if sub == "" {
		return []string{}
	}
	return runArchiveCrawler(o.baseURL, domain, sub, o)
}

func (o *OpenUKArchive) Subdomains() bool {
	return true
}
