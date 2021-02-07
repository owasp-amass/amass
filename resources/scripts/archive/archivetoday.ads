-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "ArchiveToday"
type = "archive"

function start()
    setratelimit(5)
end

function vertical(ctx, domain)
    scrape(ctx, "http://archive.is/*." .. domain)
end
