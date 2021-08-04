-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "ArchiveToday"
type = "archive"

function start()
    setratelimit(2)
end

function vertical(ctx, domain)
    crawl(ctx, buildurl(domain), 3)
end

function buildurl(domain)
    return "http://archive.is/*." .. domain
end
