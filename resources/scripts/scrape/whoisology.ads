-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local url = require("url")

name = "Whoisology"
type = "scrape"

function start()
    set_rate_limit(2)
end

function horizontal(ctx, domain)
    local hurl = "https://whoisology.com/" .. domain
    local page, err = request(ctx, {url=hurl})
    if (err ~= nil and err ~= "") then
        return
    end

    local pattern = "<a href=\"https://whoisology.com/email/([.@a-zA-Z0-9]{8,86})"
    local matches = submatch(page, pattern)
    if (matches == nil or #matches == 0) then
        return
    end

    local email = matches[1][2]
    for i=1,5 do
        page, err = request(ctx, {url=build_url(email, i)})
        if (err ~= nil and err ~= "") then
            return
        end

        pattern = "<a href=\"https://whoisology.com/(" .. subdomain_regex .. ")"
        matches = submatch(page, pattern)
        if (matches == nil or #matches == 0) then
            break
        end

        for _, match in pairs(matches) do
            if (match ~= nil and #match >= 2 and match[2] ~= "") then
                associated(ctx, domain, match[2])
            end
        end
    end
end

function build_url(email, pagenum)
    local params = {
        ['value']=email,
        ['page']=pagenum,
        ['action']="email",
        ['section']="admin",
        ['letter']="",
        ['tlds']="",
    }

    return "https://whoisology.com/search_ajax/search?" .. url.build_query_string(params)
end
