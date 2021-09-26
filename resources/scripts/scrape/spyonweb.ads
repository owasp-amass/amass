-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "SpyOnWeb"
type = "scrape"

function start()
    set_rate_limit(2)
end

function horizontal(ctx, domain)
    local page, err = request(ctx, {url=build_url(domain)})
    if (err ~= nil and err ~= "") then
        return
    end

    local pattern = "\"/go/([a-z0-9-]{2,63}[.][a-z]{2,3}([a-z]{2}|))\""
    local matches = submatch(page, pattern)
    if (matches == nil or #matches == 0) then
        return
    end

    for i, match in pairs(matches) do
        if (match ~= nil and #match >= 2 and match[2] ~= "") then
            associated(ctx, domain, match[2])
        end
    end
end

function build_url(domain)
    return "https://spyonweb.com/" .. domain
end
