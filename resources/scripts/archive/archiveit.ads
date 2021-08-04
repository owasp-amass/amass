-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local url = require("url")

name = "ArchiveIt"
type = "archive"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    for i=1,25,1 do
        local ok = scrape(ctx, {['url']=buildurl(domain, i)})
        if not ok then
            break
        end

        checkratelimit()
    end
end

function buildurl(domain, pagenum)
    local params = {
        show="Sites",
        q=domain,
        page=pagenum,
    }
    return "https://archive-it.org/explore?" .. url.build_query_string(params)
end
