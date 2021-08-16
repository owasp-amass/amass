-- Copyright 2020-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "Censys"
type = "cert"

function start()
    set_rate_limit(3)
end

function vertical(ctx, domain)
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
        c = cfg.credentials
    end

    if (c == nil or c.key == nil or
        c.key == "" or c.secret == nil or c.secret == "") then
        for i=1,10 do
            local ok = scrape(ctx, {url=build_url(domain, i)})
            if not ok then
                break
            end
        end
        return
    end

    api_query(ctx, cfg, domain)
end

function build_url(domain, pagenum)
    return "https://censys.io/certificates/_search?q=" .. domain .. "&page=" .. pagenum
end

function api_query(ctx, cfg, domain)
    local p = 1

    while(true) do
        local err, body, resp
        body, err = json.encode({
            ['query']="parsed.names: " .. domain,
            ['page']=p,
            ['fields']={"parsed.names"},
        })
        if (err ~= nil and err ~= "") then
            return
        end

        resp, err = request(ctx, {
            method="POST",
            data=body,
            url="https://www.censys.io/api/v1/search/certificates",
            headers={['Content-Type']="application/json"},
            id=cfg['credentials'].key,
            pass=cfg['credentials'].secret,
        })
        if (err ~= nil and err ~= "") then
            return
        end

        local d = json.decode(resp)
        if (d == nil or d.status ~= "ok" or #d.results == 0) then
            return
        end

        for _, r in pairs(d.results) do
            for _, v in pairs(r['parsed.names']) do
                new_name(ctx, v)
            end
        end

        if d['metadata'].page >= d['metadata'].pages then
            return
        end

        p = p + 1
    end
end
