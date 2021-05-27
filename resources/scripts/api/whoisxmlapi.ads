-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "WhoisXMLAPI"
type = "api"

function start()
    setratelimit(2)
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

    local resp, err = request(ctx, {
        url=verturl(domain, c.key),
        headers={['Content-Type']="application/json"},
    })
    if (err ~= nil and err ~= "") then
        return
    end

    local j = json.decode(resp)
    if (j == nil or j.result == nil or j.result.count == 0 or #(j.result.records) == 0) then
        return
    end

    for _, r in pairs(j.result.records) do
        newname(ctx, r.domain)
    end
end

function verturl(domain, key)
    return "https://subdomains.whoisxmlapi.com/api/v1?apiKey=" .. key .. "&domainName=" .. domain
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

    local body, err = json.encode({
        apiKey=c.key, 
        searchType="current",
        mode="purchase",
        basicSearchTerms={
            include={domain},
        },
    })
    if (err ~= nil and err ~= "") then
        return
    end

    resp, err = request(ctx, {
        method="POST",
        data=body,
        url="https://reverse-whois.whoisxmlapi.com/api/v2",
        headers={['Content-Type']="application/json"},
    })
    if (err ~= nil and err ~= "") then
        return
    end

    local j = json.decode(resp)
    if (j == nil or j.domainsCount == 0) then
        return
    end

    for _, name in pairs(j.domainsList) do
        associated(ctx, domain, name)
    end
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

        asn = getasn(ctx, addr, c.key)
        if (asn == 0) then
            return
        end
    end

    local a = asinfo(ctx, asn, c.key)
    if (a == nil) then
        return
    end

    newasn(ctx, {
        ['addr']=addr,
        ['asn']=asn,
        ['prefix']=a.netblocks[1],
        ['cc']=a.cc,
        ['registry']=a.registry,
        ['desc']=a.desc,
        ['netblocks']=a.netblocks,
    })
end

function getasn(ctx, ip, key)
    local resp, err = request(ctx, {
        url="https://ip-netblocks.whoisxmlapi.com/api/v2?apiKey=" .. key .. "&ip=" .. ip,
        headers={['Content-Type']="application/json"},
    })
    if (err ~= nil and err ~= "") then
        return 0
    end

    local j = json.decode(resp)
    if (j == nil or j.result == nil or j.result.count == 0 or #(j.result.inetnums) == 0) then
        return
    end

    local asn = 0
    for _, r in pairs(j.result.inetnums) do
        if r.as ~= nil and r.as.asn > 0 then
            asn = r.as.asn
            break
        end
    end

    return asn
end

function asinfo(ctx, asn, key)
    local resp, err = request(ctx, {
        url="https://ip-netblocks.whoisxmlapi.com/api/v2?apiKey=" .. key .. "&asn=" .. tostring(asn),
        headers={['Content-Type']="application/json"},
    })
    if (err ~= nil and err ~= "") then
        return nil
    end

    local j = json.decode(resp)
    if (j == nil or j.result == nil or j.result.count == 0 or #(j.result.inetnums) == 0) then
        return nil
    end

    local cc = ""
    local name = ""
    local registry = ""
    local netblocks = {}
    for i, r in pairs(j.result.inetnums) do
        if i == 1 then
            registry = r.source
            if r.org ~= nil then
                cc = r.org.country
                name = r.org.name
            end
        end
        if r.as ~= nil and r.as.asn == asn and r.as.route ~= nil and r.as.route ~= "" then
            table.insert(netblocks, r.as.route)
        end
    end

    return {
        ['asn']=asn,
        desc=name,
        ['cc']=cc,
        ['registry']=registry,
        ['netblocks']=netblocks,
    }
end
