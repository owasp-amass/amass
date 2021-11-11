-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "FullHunt"
type = "api"

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    local resp, err = request(ctx, {['url']=build_url(domain)})
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    end

    local j = json.decode(resp)
    if (j == nil or j.hosts == nil or #(j.hosts) == 0) then
        return
    end

    for _, h in pairs(j.hosts) do
        if (h.domain ~= nil and h.domain == domain and h.host ~= nil and h.host ~= "") then
            new_name(ctx, h.host)
            if (h.ip_address ~= nil and h.ip_address ~= "") then
                new_addr(ctx, h.ip_address, domain)
            end
            if (h.dns ~= nil) then
                if (h.dns.cname ~= nil and #(h.dns.cname) > 0) then
                    names_from_table(ctx, domain, h.dns.cname)
                end
                if (h.dns.ptr ~= nil and #(h.dns.ptr) > 0) then
                    names_from_table(ctx, domain, h.dns.ptr)
                end
                if (h.dns.a ~= nil and #(h.dns.a) > 0) then
                    addrs_from_table(ctx, domain, h.dns.a)
                end
                if (h.dns.aaaa ~= nil and #(h.dns.aaaa) > 0) then
                    addrs_from_table(ctx, domain, h.dns.aaaa)
                end
            end
        end
    end
end

function names_from_table(ctx, domain, t)
    if t == nil then
        return
    end
    for _, name in pairs(t) do
        if in_scope(ctx, name) then
            new_name(ctx, name)
        end
    end
end

function addrs_from_table(ctx, domain, t)
    if t == nil then
        return
    end
    for _, addr in pairs(t) do
        new_addr(ctx, addr, domain)
    end
end

function build_url(domain)
    return "https://fullhunt.io/api/v1/domain/" .. domain .. "/details"
end
