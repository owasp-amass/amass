-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "Sublist3rAPI"
type = "api"

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    local page, err = request(ctx, {url=build_url(domain)})
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    end

    local resp = json.decode(page)
    if (resp == nil or #resp == 0) then
        return
    end

    for i, v in pairs(resp) do
        new_name(ctx, v)
    end
end

function build_url(domain)
    return "https://api.sublist3r.com/search.php?domain=" .. domain
end
