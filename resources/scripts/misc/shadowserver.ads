-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

name = "ShadowServer"
type = "misc"

local shadowServerWhoisAddress = ""
-- shadowServerWhoisURL is the URL for the ShadowServer whois server.
local shadowServerWhoisURL = "asn.shadowserver.org"

function start()
    set_rate_limit(2)
end

function asn(ctx, addr, asn)
    if (shadowServerWhoisAddress == "") then
        shadowServerWhoisAddress = get_whois_addr(ctx)
        if (shadowServerWhoisAddress == "") then return end
    end

    local result
    if (asn == 0) then
        if (addr == "") then return end

        result = origin(ctx, addr)
        if (result == nil) then return end

        local cidrs = netblocks(ctx, result.asn)
        if (cidrs == nil or #cidrs == 0) then return end
        result['netblocks'] = cidrs
    else
        local cidrs = netblocks(ctx, asn)
        if (cidrs == nil or #cidrs == 0) then return end

        if (addr == "") then
            local parts = split(cidrs[1], "/")
            if (#parts < 2) then return end
            addr = parts[1]
        end

        result = origin(ctx, addr)
        if (result == nil) then return end
        result['netblocks'] = cidrs
    end

    new_asn(ctx, result)
end

function origin(ctx, addr)
    if not is_ipv4(addr) then return nil end

    local name = reverse_ip(addr) ..  ".origin.asn.shadowserver.org"
    local resp, err = resolve(ctx, name, "TXT", false)
    if ((err ~= nil and err ~= "") or #resp == 0) then
        log(ctx, "failed to resolve the TXT record for " .. name .. ": " .. err)
        return nil
    end

    local fields = split(resp[1].rrdata, "|")
    return {
        ['addr']=addr,
        ['asn']=tonumber(trim_space(fields[1])),
        ['prefix']=trim_space(fields[2]),
        ['cc']=trim_space(fields[4]),
        ['desc']=trim_space(fields[3]) .. " - " .. trim_space(fields[5]),
    }
end

function netblocks(ctx, asn)
    local conn, err = socket.connect(ctx, shadowServerWhoisAddress, 43, "tcp")
    if (err ~= nil and err ~= "") then
        log(ctx, "failed to connect to " .. shadowServerWhoisAddress .. " on port 43: " .. err)
        return nil
    end

    _, err = conn:send("prefix " .. tostring(asn) .. "\n")
    if (err ~= nil and err ~= "") then
        log(ctx, "failed to send the ASN parameter to " .. shadowServerWhoisAddress .. ": " .. err)
        conn:close()
        return nil
    end

    local data
    data, err = conn:recv_all()
    if (err ~= nil and err ~= "") then
        log(ctx, "failed to receive the response from " .. shadowServerWhoisAddress .. ": " .. err)
        conn:close()
        return nil
    end

    local netblocks = {}
    for _, block in pairs(split(data, "\n")) do
        table.insert(netblocks, trim_space(block))
    end

    conn:close()
    return netblocks
end

function split(str, delim)
    local result = {}
    local pattern = "[^%" .. delim .. "]+"

    local matches = find(str, pattern)
    if (matches == nil or #matches == 0) then return result end

    for _, match in pairs(matches) do
        table.insert(result, match)
    end
    return result
end

function get_whois_addr(ctx)
    local resp, err = resolve(ctx, shadowServerWhoisURL, "A", false)
    if ((err ~= nil and err ~= "") or #resp == 0) then
        log(ctx, "failed to resolve the A record for " .. shadowServerWhoisURL .. ": " .. err)
        return ""
    end
    return resp[1].rrdata
end

function is_ipv4(addr)
    local octets = { addr:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$") }

    if (#octets == 4) then
        for _, v in pairs(octets) do
            if tonumber(v) > 255 then return false end
        end
        return true
    end
    return false
end

function reverse_ip(addr)
    local octets = { addr:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$") }

    local ip = ""
    for i, o in pairs(octets) do
        local n = o

        if (i ~= 1) then n = n .. "." end
        ip = n .. ip
    end
    return ip 
end

function trim_space(s)
    if (s == nil) then return "" end
    return s:match( "^%s*(.-)%s*$" )
end
