-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "ArchiveIt"
type = "archive"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    local p = 1
    local resp, err = request(buildurl(domain, p))
    if (err ~= nil and err ~= "") then
        return
    end

    local match = find(resp, "No metadata results")
    if (match ~= nil or #match ~= 0) then
        return
    end

    while(true) do
        local u = buildurl(domain, p)
        local ok = scrape(ctx, {url=u})
        if not ok then
            break
        end

        checkratelimit()
        p = p + 1
    end
end

function buildurl(domain, page)
    return "https://archive-it.org/explore?show=Sites&q=" .. domain .. "&page=" .. page
end
