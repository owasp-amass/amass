-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "NetCraft"
type = "scrape"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    local last = "last="

    for i=1,101,20 do
        local u = "https://searchdns.netcraft.com/?restriction=site+ends+with&host=" .. domain .. "&from=" .. tostring(i) .. "&" .. last
        local resp, err = request(ctx, {['url']=u})
        if (err ~= nil and err ~= "") then
            break
        end

        sendnames(ctx, resp)

        last = findlast(resp)
        if last == nil then
            break
        end
    end
end

function findlast(page) do
    local match = find(page, "last=" .. subdomainre)
    if (match == nil or #match == 0) then
        return
    end

    return match[1]
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
