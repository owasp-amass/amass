-- Copyright 2022 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "DNSHistory"
type = "scrape"

function start()
    set_rate_limit(2)
end

function vertical(ctx, domain)
    local p = 1
    local pattern = "/dns\\-records/(.*)\">"

    while(true) do
        local page, err = request(ctx, {['url']=build_url(domain, p)})
        if (err ~= nil and err ~= "") then
            log(ctx, "vertical request to service failed: " .. err)
            return
        end

        local matches = submatch(page, pattern)
        if (matches == nil or #matches == 0) then
            return
        end

        for _, match in pairs(matches) do
            new_name(ctx, match[2])
        end

        local nxt = find(page, "next</a>")
        if (nxt == nil or #nxt == 0) then
            return
        end

        p = p + 1
    end
end

function build_url(domain, pagenum)
    return "https://dnshistory.org/subdomains/" .. pagenum .. "/" .. domain
end
