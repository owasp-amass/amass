-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "ArchiveIt"
type = "archive"

function start()
    setratelimit(5)
end

function vertical(ctx, domain)
    scrape(ctx, {['url']=buildurl(domain)})
end

function buildurl(domain)
    return "https://wayback.archive-it.org/all/timemap/cdx?matchType=domain&fl=original&collapse=urlkey&url=" .. domain
end
