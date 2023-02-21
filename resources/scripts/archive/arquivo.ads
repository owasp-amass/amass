-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local url = require("url")
local json = require("json")

name = "Arquivo"
type = "archive"

function start()
    set_rate_limit(5)
end

function vertical(ctx, domain)
    local resp, err = request(ctx, {['url']=build_url(domain)})
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "vertical request to service returned with status code: " .. resp.status)
        return
    end

    local d = json.decode(resp.body)
    if (d == nil) then
        log(ctx, "failed to decode the JSON response")
        return
    elseif (d.response_items == nil or #(d.response_items) == 0) then
        return
    end

    for _, r in pairs(d.response_items) do
        send_names(ctx, r.originalURL)
    end
end

function build_url(domain)
    local params = {
        ['q']=domain,
        ['offset']="0",
        ['maxItems']="500",
    }

    return "https://arquivo.pt/textsearch?" .. url.build_query_string(params)
end
