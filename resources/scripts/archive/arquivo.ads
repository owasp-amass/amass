-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local url = require("url")
local json = require("json")

name = "Arquivo"
type = "archive"

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    local resp, err = request(ctx, {url=build_url(domain)})
    if (err ~= nil and err ~= "") then
        return
    end

    local d = json.decode(resp)
    if (d == nil or #d.response_items == 0) then
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
        ['maxItems']="600",
        ['siteSearch']="",
        ['type']="",
        ['collection']="",
    }

    return "https://arquivo.pt/textsearch?" .. url.build_query_string(params)
end
