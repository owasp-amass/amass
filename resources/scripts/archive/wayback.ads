-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local url = require("url")

name = "Wayback"
type = "archive"

function start()
    set_rate_limit(5)
end

function vertical(ctx, domain)
    scrape(ctx, {url=build_url(domain)})
end

function build_url(domain)
    local params = {
        ['matchType']="domain",
        ['fl']="original",
        ['output']="json",
        ['collapse']="url",
        ['url']=domain,
    }

    return "https://web.archive.org/cdx/search/cdx?" .. url.build_query_string(params)
end
