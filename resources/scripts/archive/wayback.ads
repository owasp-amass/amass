-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "Wayback"
type = "archive"

function start()
    setratelimit(5)
end

function vertical(ctx, domain)
    scrape(ctx, {['url']=buildurl(domain)})
end

function buildurl(domain)
    return "https://web.archive.org/cdx/search/cdx?matchType=domain&fl=original&output=json&collapse=urlkey&url=" .. domain
end
