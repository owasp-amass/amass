-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "SiteDossier"
type = "scrape"

function start()
    set_rate_limit(4)
end

function vertical(ctx, domain)
    local p = 1

    while(true) do
        local ok = scrape(ctx, {url=build_url(domain, p)})
        if not ok then
            break
        end

        check_rate_limit()
        p = p + 100
    end
end

function build_url(domain, pagenum)
    return "http://www.sitedossier.com/parentdomain/" .. domain .. "/" .. pagenum
end
