-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "SpyOnWeb"
type = "scrape"

function start()
    setratelimit(4)
end

function horizontal(ctx, domain)
    local page, err = request(ctx, {url=buildurl(domain)})
    if (err ~= nil and err ~= "") then
        return
    end

    local pattern = "\"/go/([a-z0-9]{2,63}+[.][a-z]{2,3}+([.][a-z]{2}|))\""
    local matches = submatch(page, pattern)
    if (matches == nil or #matches == 0) then
        return
    end

    for i, name in pairs(matches) do
        associated(ctx, domain, name)
    end
end

function buildurl(domain)
    return "https://spyonweb.com/" .. domain
end
