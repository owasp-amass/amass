-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "Crtsh"
type = "cert"

function start()
    set_rate_limit(3)
end

function vertical(ctx, domain)
    local url = "https://crt.sh/?q=" .. domain .. "&output=json"

    local resp, err = request(ctx, {['url']=url})
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "vertical request to service returned with status code: " .. resp.status)
        return
    end
    local body = "{\"subdomains\":" .. resp.body .. "}"

    local d = json.decode(body)
    if (d == nil) then
        log(ctx, "failed to decode the JSON response")
        return
    elseif (d.subdomains == nil or #(d.subdomains) == 0) then
        return
    end

    for _, r in pairs(d.subdomains) do
        if (r['common_name'] ~= nil and r['common_name'] ~= "") then
            new_name(ctx, r['common_name'])
        end

        for _, n in pairs(split(r['name_value'], "\\n")) do
            if (n ~= nil and n ~= "") then
                new_name(ctx, n)
            end
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
