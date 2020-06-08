-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "ArchiveIt"
type = "archive"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    crawl(ctx, buildurl(domain))
end

function resolved(ctx, name)
    crawl(ctx, buildurl(name))
end

function buildurl(domain)
    return "https://wayback.archive-it.org/all/" .. year() .. "/" .. domain
end
