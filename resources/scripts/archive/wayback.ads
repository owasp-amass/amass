-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "Wayback"
type = "archive"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    local resp
    local vurl = buildurl(domain)
    local cfg = datasrc_config()

    -- Check if the response data is in the graph database
    if (cfg.ttl ~= nil and cfg.ttl > 0) then
        resp = obtain_response(vurl, cfg.ttl)
    end

    if (resp == nil or resp == "") then
        local err

        resp, err = request({
            url=vurl,
            headers={['Content-Type']="application/json"},
        })
        if (err ~= nil and err ~= "") then
            return
        end
    
        if (cfg.ttl ~= nil and cfg.ttl > 0) then
            cache_response(vurl, resp)
        end
    end
    
    sendnames(ctx, resp)
end

function buildurl(domain)
    return "http://web.archive.org/cdx/search/cdx?url=*." .. domain .. "&output=json&collapse=urlkey"
end

function sendnames(ctx, content)
    local names = find(content, subdomainre)
    if names == nil then
        return
    end

    local found = {}
    for i, v in pairs(names) do
        if found[v] == nil then
            newname(ctx, v)
            found[v] = true
        end
    end
end
