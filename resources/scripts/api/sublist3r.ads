-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "Sublist3rAPI"
type = "api"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    local page, err = request(ctx, {url=buildurl(domain)})
    if (err ~= nil and err ~= "") then
        return
    end

    local resp = json.decode(page)
    if (resp == nil or #resp == 0) then
        return
    end

    for i, v in pairs(resp) do
        newname(ctx, v)
    end
end

function buildurl(domain)
    return "https://api.sublist3r.com/search.php?domain=" .. domain
end
