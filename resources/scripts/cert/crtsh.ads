-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "Crtsh"
type = "cert"

function start()
    setratelimit(2)
end

function vertical(ctx, domain)
    local resp, err = request(ctx, {
        ['url']=buildurl(domain),
        headers={['Content-Type']="application/json"},
    })
    if (err ~= nil and err ~= "") then
        return
    end

    dec = json.decode(resp)
    if (dec == nil or #dec == 0) then
        return
    end

    for i, r in pairs(dec) do
        local parts = split(r.name_value, "\n")
        if #parts == 0 then
            table.insert(parts, r.name_value)
        end

        for j, name in pairs(parts) do
            newname(ctx, name)
        end
    end
end

function buildurl(domain)
    return "https://crt.sh/?q=%25." .. domain .. "&output=json"
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
