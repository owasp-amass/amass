-- Copyright 2020-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "Spyse"
type = "api"

function start()
    set_rate_limit(1)
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

    local step = 100
    for i = 0,10000,step do
        local resp, body, err
        body, err = json.encode({
            ['search_params']={
                {
                    ['name']={
                        ['operator']="ends",
                        ['value']="." .. domain
                    },
                }
            },
            ['limit']=100,
            ['offset']=i,
        })
        if (err ~= nil and err ~= "") then
            break
        end

        resp, err = request(ctx, {
            url="https://api.spyse.com/v4/data/domain/search",
            method="POST",
            data=body,
            headers={
                ['Authorization']="Bearer " .. c.key,
                ['Content-Type']="application/json",
            },
        })
        if (err ~= nil and err ~= "") then
            break
        end

        local d = json.decode(resp)
        if (d == nil or d.data == nil or
            d['data'].items == nil or #d['data'].items == 0) then
            return false
        end

        for _, item in pairs(d['data'].items) do
            send_names(ctx, item.name)
        end

        if (i+step >= d['data'].total_items) then
            break
        end
    end
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

    hcerts(ctx, domain, c.key, cfg.ttl)
end


function hcerts(ctx, domain, key, ttl)
    local resp = get_page(ctx, build_url(domain, "domain"), key, ttl)
    if (resp == "") then
        return
    end

    local d = json.decode(resp)
    if (d == nil or d.data == nil or d['data'].items == nil or
        #d['data'].items == 0 or d['data'].items[0].cert_summary == nil) then
        return
    end

    local certid = d['data'].items[0].cert_summary.fingerprint_sha256
    resp = get_page(ctx, build_url(certid, "certificate"), key, ttl)
    if (resp == "") then
        return
    end

    d = json.decode(resp)
    if (d == nil or d.data == nil or
        d['data'].items == nil or #(d['data'].items) == 0) then
        return
    end

    local san = d['data'].items[0].parsed.extensions.subject_alt_name
    if (san ~= nil and #(san.dns_names) > 0) then
        for _, name in pairs(san.dns_names) do
            local n = find(name, subdomain_regex)

            if (n ~= nil and #n > 0 and n[1] ~= "") then
                associated(ctx, domain, n[1])
            end
        end
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

        asn, prefix = get_asn(ctx, addr, c.key, cfg.ttl)
        if (asn == 0) then
            return
        end
    end

    local a = as_info(ctx, asn, c.key, cfg.ttl)
    if (a == nil or a.netblocks == nil or #(a.netblocks) == 0) then
        return
    end

    if (prefix == "") then
        prefix = a.netblocks[1]
        parts = split(prefix, "/")
        addr = parts[1]
    end

    new_asn(ctx, {
        ['addr']=addr,
        ['asn']=asn,
        ['prefix']=prefix,
        ['desc']=a.desc,
        ['netblocks']=a.netblocks,
    })
end

function get_asn(ctx, ip, key, ttl)
    local resp = get_page(ctx, u, build_url(ip, "ip"), ttl)
    if (resp == "") then
        return 0, ""
    end

    local d = json.decode(resp)
    if (d == nil or d.data == nil or
        d['data'].items == nil or #(d['data'].items) == 0) then
        return 0, ""
    end

    local cidr
    local asn = 0
    for _, item in pairs(d['data'].items) do
        local num = item.isp_info.as_num

        if (asn == 0 or asn < num) then
            asn = num
            cidr = item.cidr
        end
    end

    return asn, cidr
end

function as_info(ctx, asn, key, ttl)
    local resp = get_page(ctx, build_url(tostring(asn), "as"), key, ttl)
    if (resp == "") then
        return nil
    end

    local d = json.decode(resp)
    if (d == nil or d.data == nil or
        d['data'].items == nil or #(d['data'].items) == 0) then
        return nil
    end

    local cidrs = {}
    if d['data'].items[1].ipv4_cidr_array ~= nil then
        for _, p in pairs(d['data'].items[1].ipv4_cidr_array) do
            if p.ip ~= nil and p.cidr ~= nil then
                table.insert(cidrs, p.ip .. "/" .. tostring(p.cidr))
            end
        end
    end
    if d['data'].items[1].ipv6_cidr_array ~= nil then
        for _, p in pairs(d['data'].items[1].ipv6_cidr_array) do
            if p.ip ~= nil and p.cidr ~= nil then
                table.insert(cidrs, p.ip .. "/" .. tostring(p.cidr))
            end
        end
    end

    return {
        desc=d['data'].items[1].as_org,
        netblocks=cidrs,
    }
end

function build_url(target, query)
    return "https://api.spyse.com/v4/data/" .. query .. "/" .. target
end

function get_page(ctx, url, key, ttl)
    local resp, err = request(ctx, {
        url=url,
        headers={['Authorization']="Bearer " .. key,},
    })
    if (err ~= nil and err ~= "") then
        return ""
    end
    return resp
end

function split(str, delim)
    local result = {}
    local pattern = "[^%" .. delim .. "]+"

    local matches = find(str, pattern)
    if (matches == nil or #matches == 0) then
        return result
    end

    for _, match in pairs(matches) do
        table.insert(result, match)
    end

    return result
end
