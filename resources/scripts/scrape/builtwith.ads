-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "BuiltWith"
type = "scrape"

function start()
    set_rate_limit(3)
end

function vertical(ctx, domain)
    scrape(ctx, {url=build_url(domain)})
end

function build_url(domain)
    return "https://builtwith.com/relationships/" .. domain
end
