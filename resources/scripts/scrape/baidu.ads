-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local url = require("url")
local json = require("json")

name = "Baidu"
type = "scrape"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    apirequest(ctx, domain)
    doscrape(ctx, domain)
end

function doscrape(ctx, domain)
    for i=1,10 do
        checkratelimit()

        local ok = scrape(ctx, {['url']=buildurl(domain, i)})
        if not ok then
            break
        end
    end
end

function buildurl(domain, pagenum)
    local query = "site:" .. domain .. " -site:www." .. domain
    local params = {
        wd=query,
        oq=query,
        pn=tostring(pagenum),
    }

    return "https://www.baidu.com/s?" .. url.build_query_string(params)
end

function apirequest(ctx, domain)
    local page, err = request({['url']=apiurl(domain)})
    if (err ~= nil and err ~= "") then
        return
    end

    local resp = json.decode(page)
    if (resp == nil or resp.code ~= 0 or #resp['data'] == 0) then
        return
    end

    for i, tb in pairs(resp.data) do
        newname(ctx, tb.domain)
    end
end

function apiurl(domain)
    return "https://ce.baidu.com/index/getRelatedSites?site_address=" .. domain
end
