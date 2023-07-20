-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

name = "TeamCymru"
type = "misc"

function asn(ctx, addr, asn)
    if (addr == "") then return end

    local result = origin(ctx, addr)
    if (result == nil or result.asn == 0) then return end
    result['netblocks'] = result.prefix
    
    local desc = get_desc(ctx, result.asn)
    if (desc == "") then return end
    result['desc'] = desc

    new_asn(ctx, result)
end

function origin(ctx, addr)
    local name = ""
    local arpa = ".origin.asn.cymru.com"

    if is_ipv4(addr) then
        name = reverse_ipv4(addr)
    else
        name = ipv6_nibble(addr)
        arpa = ".origin6.asn.cymru.com"
    end
    if (name == "") then return nil end

    local n = name .. arpa
    local resp, err = resolve(ctx, n, "TXT", false)
    if ((err ~= nil and err ~= "") or #resp == 0) then
        log(ctx, "failed to resolve the TXT record for " .. n .. ": " .. err)
        return nil
    end

    local fields = split(resp[1].rrdata, "|")
    return {
        ['addr']=addr,
        ['asn']=tonumber(trim_space(fields[1])),
        ['prefix']=trim_space(fields[2]),
        ['registry']=trim_space(fields[4]),
        ['cc']=trim_space(fields[3]),
    }
end

function get_desc(ctx, asn)
    local name = "AS" .. tostring(asn) .. ".asn.cymru.com"

    local resp, err = resolve(ctx, name, "TXT", false)
    if ((err ~= nil and err ~= "") or #resp == 0) then
        log(ctx, "failed to resolve the TXT record for " .. name .. ": " .. err)
        return ""
    end

    local fields = split(resp[1].rrdata, "|")
    if (#fields < 5) then return "" end

    return trim_space(fields[5])
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

function trim_space(s)
    return s:match( "^%s*(.-)%s*$" )
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

function reverse_ipv4(addr)
    local octets = { addr:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$") }

    local ip = ""
    for i, o in pairs(octets) do
        local n = o
        if (i ~= 1) then n = n .. "." end
        ip = n .. ip
    end
    return ip 
end

function ipv6_nibble(addr)
    local ip = expand_ipv6(addr)
    if (ip == "") then return ip end

    local parts = split(ip, ":")
    -- padding
    local mask = "0000"
    for i, part in ipairs(parts) do
      parts[i] = mask:sub(1, #mask - #part) .. part
    end
    -- 32 parts from 8
    local temp = {}
    for i, hdt in ipairs(parts) do
      for part in hdt:gmatch("%x") do
        temp[#temp+1] = part
      end
    end
    parts = temp

    local reverse = {}
    for i = #parts, 1, -1 do
        table.insert(reverse, parts[i])
    end
    return table.concat(reverse, ".")
end

function expand_ipv6(addr)
    -- preserve ::
    addr = string.gsub(addr, "::", ":z:")
    -- get a table of each hexadectet
    local hexadectets = {}
    for hdt in string.gmatch(addr, "[%.z%x]+") do
        hexadectets[#hexadectets+1] = hdt
    end
      
    -- deal with :: and check for invalid address
    local z_done = false
    for index, value in ipairs(hexadectets) do
        if value == "z" and z_done then
            -- can't have more than one ::
            return ""
        elseif value == "z" and not z_done then
            z_done = true
            hexadectets[index] = "0"
            local bound = 8 - #hexadectets
            for i = 1, bound, 1 do
              table.insert(hexadectets, index+i, "0")
            end
        elseif tonumber(value, 16) > 65535 then
            -- more than FFFF!
            return ""
        end
    end
      
    -- make sure we have exactly 8 hexadectets
    if (#hexadectets > 8) then return "" end
    while (#hexadectets < 8) do
        hexadectets[#hexadectets+1] = "0"
    end
      
    return (table.concat(hexadectets, ":"))
end
