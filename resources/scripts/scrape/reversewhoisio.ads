-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "ReverseWhoisIO"
type = "scrape"

function start()
    setratelimit(5)
end

function horizontal(ctx, domain)
    local page, err = request(ctx, {url=buildurl(domain)})
    if (err ~= nil and err ~= "") then
        return
    end

    local domainre = "</td><td>(" .. subdomainre .. ")</td>"
    local matches = submatch(page, domainre)
    if (matches == nil or #matches == 0) then
        return
    end

    for _, name in pairs(matches) do
        associated(ctx, domain, name)
    end
end

function buildurl(domain)
    return "https://www.reversewhois.io/?searchterm=" .. domain
end
