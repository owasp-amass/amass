-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

name = "Active DNS"
type = "dns"

local cfg

function start()
    cfg = config()
end

function vertical(ctx, domain)
    if (cfg == nil or cfg.mode ~= "active") then
        return
    end

    for _, addr in pairs(ns_addrs(ctx, domain)) do
        zone_walk(ctx, domain, addr)
        zone_transfer(ctx, domain, addr)
    end
end

function subdomain(ctx, name, domain, times)
    if (cfg == nil or cfg.mode ~= "active" or times > 1) then
        return
    end

    for _, addr in pairs(ns_addrs(ctx, name)) do
        zone_walk(ctx, name, addr)
        zone_transfer(ctx, name, addr)
    end
end

function ns_addrs(ctx, name)
    local addrs = {}

    local resp, err = resolve(ctx, name, "NS")
    if (err ~= nil or #resp == 0) then
        return addrs
    end

    for _, record in pairs(resp) do
        resp, err = resolve(ctx, record['rrdata'], "A")
        if (err == nil and #resp > 0) then
            for _, rr in pairs(resp) do
                table.insert(addrs, rr['rrdata'])
            end
        end

        resp, err = resolve(ctx, record['rrdata'], "AAAA")
        if (err == nil and #resp > 0) then
            for _, rr in pairs(resp) do
                table.insert(addrs, rr['rrdata'])
            end
        end
    end

    return addrs
end
