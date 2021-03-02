-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "Spyse"
type = "api"

function start()
    setratelimit(1)
end

function check()
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
        c = cfg.credentials
    end

    if (c ~= nil and c.key ~= nil and c.key ~= "") then
        return true
    end
    return false
end

function vertical(ctx, domain)
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
        c = cfg.credentials
    end

    if (c == nil or c.key == nil or c.key == "") then
        return
    end

    for i = 0,10000,100 do
        local u = subsurl(domain, i)

        local resp = getpage(ctx, u, c.key, cfg.ttl)
        if (resp == "") then
            break
        end

        local d = json.decode(resp)
        if (d == nil or #(d['data'].items) == 0) then
            return false
        end

        for i, item in pairs(d['data'].items) do
            sendnames(ctx, item.name)
        end
    end
end

function subsurl(domain, offset)
    return "https://api.spyse.com/v3/data/domain/subdomain?domain=" .. domain .. "&limit=100&offset=" .. tostring(offset)
end

function horizontal(ctx, domain)
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
        c = cfg.credentials
    end

    if (c == nil or c.key == nil or c.key == "") then
        return
    end

    -- Spyse API domain/related/domain often returns false positives (domains not owned by the provided domain)
    --horizonnames(ctx, domain, c.key, cfg.ttl)
    horizoncerts(ctx, domain, c.key, cfg.ttl)
end

function horizonnames(ctx, domain, key, ttl)
    for i = 0,10000,100 do
        u = namesurl(domain, i)

        resp = getpage(ctx, u, key, ttl)
        if (resp == "") then
            break
        end

        local d = json.decode(resp)
        if (d == nil or #(d['data'].items) == 0) then
            break
        end

        for i, item in pairs(d['data'].items) do
            if (item.domain.name ~= "") then
                local names = find(item.domain.name, subdomainre)

                if (names ~= nil and #names > 0 and names[1] ~= "") then
                    associated(ctx, domain, names[1])
                end
            end
        end
    end
end

function namesurl(domain, offset)
    return "https://api.spyse.com/v3/data/domain/related/domain?domain=" .. domain .. "&limit=100&offset=" .. tostring(offset)
end

function horizoncerts(ctx, domain, key, ttl)
    local u = "https://api.spyse.com/v3/data/domain/org?domain=" .. domain
    local resp = getpage(ctx, u, key, ttl)
    if (resp == "") then
        return
    end

    local d = json.decode(resp)
    if (d == nil or d['data'].id == nil) then
        return
    end
    local orgid = d['data'].id

    for i = 0,10000,100 do
        u = certsurl(orgid, i)

        resp = getpage(ctx, u, key, ttl)
        if (resp == "") then
            break
        end

        local d = json.decode(resp)
        if (d == nil or #(d['data'].items) == 0) then
            break
        end

        for i, item in pairs(d['data'].items) do
            local san = item.parsed.extensions.subject_alt_name

            if (san ~= nil and #(san.dns_names) > 0) then
                for j, name in pairs(san.dns_names) do
                    local names = find(name, subdomainre)

                    if (names ~= nil and #names > 0 and names[1] ~= "") then
                        associated(ctx, domain, names[1])
                    end
                end
            end
        end
    end
end

function certsurl(id, offset)
    return "https://api.spyse.com/v3/data/org/cert/subject?id=" .. id .. "&limit=100&offset=" .. tostring(offset)
end

function asn(ctx, addr, asn)
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
        c = cfg.credentials
    end

    if (c == nil or c.key == nil or c.key == "") then
        return
    end

    local prefix
    if (asn == 0) then
        if (addr == "") then
            return
        end

        asn, prefix = getasn(ctx, addr, c.key, cfg.ttl)
        if (asn == 0) then
            return
        end
    end

    local a = asinfo(ctx, asn, c.key, cfg.ttl)
    if (a == nil or #(a.netblocks) == 0) then
        return
    end

    if (prefix == "") then
        prefix = a.netblocks[1]
        parts = split(prefix, "/")
        addr = parts[1]
    end

    newasn(ctx, {
        ['addr']=addr,
        ['asn']=asn,
        ['prefix']=prefix,
        ['desc']=a.desc,
        ['netblocks']=a.netblocks,
    })
end

function getasn(ctx, ip, key, ttl)
    local u = "https://api.spyse.com/v3/data/ip?ip=" .. tostring(ip)

    local resp = getpage(ctx, u, key, ttl)
    if (resp == "") then
        return 0, ""
    end

    local d = json.decode(resp)
    if (d == nil or #(d['data'].items) == 0) then
        return 0, ""
    end

    local cidr
    local asn = 0
    for i, item in pairs(d['data'].items) do
        local num = item.isp_info.as_num

        if (asn == 0 or asn < num) then
            asn = num
            cidr = item.cidr
        end
    end

    return asn, cidr
end

function asinfo(ctx, asn, key, ttl)
    local u = "https://api.spyse.com/v3/data/as?asn=" .. tostring(asn)

    local resp = getpage(ctx, u, key, ttl)
    if (resp == "") then
        return nil
    end

    local d = json.decode(resp)
    if (d == nil or #(d['data'].items) == 0) then
        return nil
    end

    local cidrs = {}
    for i, p in pairs(d.items[1].ipv4_cidr_array) do
        table.insert(cidrs, p.ip .. "/" .. tostring(p.cidr))
    end
    for i, p in pairs(d.items[1].ipv6_cidr_array) do
        table.insert(cidrs, p.ip .. "/" .. tostring(p.cidr))
    end

    return {
        desc=d.items[1].as_org,
        netblocks=cidrs,
    }
end

function getpage(ctx, url, key, ttl)
    local resp, err = request(ctx, {
        ['url']=url,
        headers={
            ['Authorization']="Bearer " .. key,
            ['Content-Type']="application/json",
        },
    })
    if (err ~= nil and err ~= "") then
        return ""
    end

    return resp
end

function sendnames(ctx, content)
    local names = find(content, subdomainre)
    if (names == nil) then
        return
    end

    local found = {}
    for i, v in pairs(names) do
        if (found[v] == nil) then
            newname(ctx, v)
            found[v] = true
        end
    end
end

function split(str, delim)
    local result = {}
    local pattern = "[^%" .. delim .. "]+"

    local matches = find(str, pattern)
    if (matches == nil or #matches == 0) then
        return result
    end

    for i, match in pairs(matches) do
        table.insert(result, match)
    end

    return result
end
