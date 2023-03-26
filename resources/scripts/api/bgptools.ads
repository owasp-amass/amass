-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "BGPTools"
type = "misc"

local bgptoolsWhoisAddress = ""
-- bgptoolsWhoisURL is the URL for the BGP.Tools whois server.
local bgptoolsWhoisURL = "bgp.tools"
-- bgptoolsTableFile is the path to the file containing ASN prefixes.
local bgptoolsTableFile = ""
local useragent = "OWASP Amass "

function start()
    local cfg = config()

    set_rate_limit(1)
    if (cfg ~= nil) then
        useragent = useragent .. cfg.version .. " - admin@owasp.com"
    end
end

function asn(ctx, addr, asn)
    if (bgptoolsWhoisAddress == "" and not get_whois_addr(ctx)) then return end
    -- Check if the table file containing ASN prefixes needs to be acquired
    if (need_table_file(ctx) and not get_table_file(ctx)) then return end

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

    table.insert(result['netblocks'], result['prefix'])
    new_asn(ctx, result)
end

function origin(ctx, addr)
    local conn, err = socket.connect(ctx, bgptoolsWhoisAddress, 43, "tcp")
    if (err ~= nil and err ~= "") then
        log(ctx, "failed to connect to the whois server: " .. err)
        return nil
    end

    _, err = conn:send("begin\n" .. addr .. "\nend")
    if (err ~= nil and err ~= "") then
        log(ctx, "failed to send the whois server request: " .. err)
        conn:close()
        return nil
    end

    local data
    data, err = conn:recv_all()
    conn:close()
    if (err ~= nil and err ~= "") then
        log(ctx, "failed to read the whois server response: " .. err)
        return nil
    end

    local fields = split(data, "|")
    return {
        ['addr']=addr,
        ['asn']=tonumber(trim_space(fields[1])),
        ['prefix']=trim_space(fields[3]),
        ['cc']=trim_space(fields[4]),
        ['registry']=trim_space(fields[5]),
        ['desc']=trim_space(fields[7]),
    }
end

function netblocks(ctx, asn)
    local prefixes = io.open(bgptoolsTableFile, "r")

    local netblocks = {}
    for line in prefixes:lines() do
        local j = json.decode(line)
        if (j ~= nil and j.ASN ~= nil and j.ASN == asn and j.CIDR ~= nil and j.CIDR ~= "") then
            table.insert(netblocks, j.CIDR)
        end
    end
    prefixes:close()

    return netblocks
end

function need_table_file(ctx)
    bgptoolsTableFile = output_dir(ctx) .. "/bgptools.jsonl"

    local modified = mtime(bgptoolsTableFile)
    if (modified == 0) then return true end

    hoursfrom = os.difftime(os.time(), modified) / (60 * 60)
    wholehours = math.floor(hoursfrom)
    if (wholehours > 24) then
        os.remove(bgptoolsTableFile)
        return true
    end

    return false
end

function get_table_file(ctx)
    local resp, err = request(ctx, {
        ['url']="https://bgp.tools/table.jsonl",
        ['headers']={['User-Agent']=useragent},
    })
    if (err ~= nil and err ~= "") then
        log(ctx, "table.jsonl file request to service failed: " .. err)
        return
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "table.jsonl file request to service returned with status: " .. resp.status)
        return
    end

    local prefixes = io.open(bgptoolsTableFile, "w")
    if (prefixes == nil) then
        log(ctx, "failed to write the table.jsonl file")
        return false
    end

    prefixes:write(resp.body)
    prefixes:close()
    return true
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
    local resp, err = resolve(ctx, bgptoolsWhoisURL, "A", false)
    if ((err ~= nil and err ~= "") or #resp == 0) then
        log(ctx, "failed to resolve the whois server address: " .. err)
        return false
    end

    bgptoolsWhoisAddress = resp[1].rrdata
    return true
end

function trim_space(s)
    if (s == nil) then return "" end
    return s:match( "^%s*(.-)%s*$" )
end
