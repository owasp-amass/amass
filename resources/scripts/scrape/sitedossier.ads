-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "SiteDossier"
type = "scrape"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    local p = 1

    while (true)
        local ok = scrape(ctx, {url=buildurl(domain, p)})
        if not ok then
            break
        end

        checkratelimit()
        p = p + 100
    end
end

function buildurl(domain, pagenum)
    return "http://www.sitedossier.com/parentdomain/" .. domain .. "/" .. pagenum
end
