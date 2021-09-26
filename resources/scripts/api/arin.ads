-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "ARIN"
type = "api"

function start()
    set_rate_limit(1)
end

function asn(ctx, addr, asn)
    if addr == "" then
        return
    end

    local resp, err = request(ctx, {url=asn_url(addr)})
    if (err ~= nil and err ~= "") then
        log(ctx, "asn request to service failed: " .. err)
        return
    end

    local j = json.decode(resp)
    if (j == nil or j.cidr0_cidrs == nil or j.arin_originas0_originautnums == nil or 
        #(j.cidr0_cidrs) == 0 or #(j.arin_originas0_originautnums) == 0) then
        return
    end
    local asn = j.arin_originas0_originautnums[1]

    if (j.cidr0_cidrs[1]['v4prefix'] == nil or j.cidr0_cidrs[1]['v4prefix'] == "") then
        return
    end
    local cidr = j.cidr0_cidrs[1]['v4prefix'] .. "/" .. tostring(j.cidr0_cidrs[1]['length'])

    if j.entities[1]['vcardArray'] == nil then
        return
    end
    local desc = j.name .. " - " .. j.entities[1]['vcardArray'][2][2][4]

    new_asn(ctx, {
        ['addr']=addr,
        ['asn']=asn,
        ['desc']=desc,
        ['prefix']=cidr,
    })
end

function asn_url(addr)
    return "https://rdap.arin.net/registry/ip/" .. addr
end
