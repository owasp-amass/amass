-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local url = require("url")

name = "ArchiveIt"
type = "archive"

function start()
    set_rate_limit(2)
end

function vertical(ctx, domain)
    scrape(ctx, {['url']=first_url(domain)})

    local found = pages(ctx, domain)
    if not found then
        return
    end

    for i=1,50,1 do
        local ok = scrape(ctx, {['url']=second_url(domain, i)})
        if not ok then
            break
        end
    end
end

function first_url(domain)
    local params = {
        ['url']=domain,
        ['matchType']="domain",
        ['fl']="original",
        ['collapse']="urlkey",
    }
    return "https://wayback.archive-it.org/all/timemap/cdx?" .. url.build_query_string(params)
end

function second_url(domain, pagenum)
    local params = {
        ['show']="Sites",
        ['q']=domain,
        ['page']=pagenum,
    }
    return "https://archive-it.org/explore?" .. url.build_query_string(params)
end

function pages(ctx, domain)
    local u = "https://archive-it.org/explore?show=Sites&q=" .. domain
    local resp, err = request(ctx, {['url']=u})
    if (err ~= nil and err ~= "") then
        log(ctx, "pages request to service failed: " .. err)
        return false
    end

    local match = find(resp, "No metadata results")
    if (match == nil or #match == 0) then
        return false
    end

    return true
end
