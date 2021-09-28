-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "Crtsh"
type = "cert"

function start()
    set_rate_limit(3)
end

function vertical(ctx, domain)
    local vurl = "https://crt.sh/?q=" .. domain .. "&output=json"

    local resp, err = request(ctx, {['url']=vurl})
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    end
    resp = "{\"subdomains\":" .. resp .. "}"

    local d = json.decode(resp)
    if (d == nil or d.subdomains == nil or #(d.subdomains) == 0) then
        return
    end

    for _, r in pairs(d.subdomains) do
        new_name(ctx, r['common_name'])

        for _, n in pairs(split(r['name_value'], "\\n")) do
            new_name(ctx, n)
        end
    end
end

function split(str, delim)
    local pattern = "[^%" .. delim .. "]+"

    local matches = find(str, pattern)
    if (matches == nil or #matches == 0) then
        return {str}
    end

    local result = {}
    for _, match in pairs(matches) do
        table.insert(result, match)
    end

    return result
end
