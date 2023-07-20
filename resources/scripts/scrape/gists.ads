-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local url = require("url")

name = "Gists"
type = "scrape"

function start()
    set_rate_limit(2)
end

function vertical(ctx, domain)
    local gist_re = "https://gist[.]github[.]com/[a-zA-Z0-9-]{1,39}/[a-z0-9]{32}"
    for i=1,20 do
        local resp, err = request(ctx, {['url']=build_url(domain, i)})
        if (err ~= nil and err ~= "") then
            log(ctx, "vertical request to service failed: " .. err)
            return
        elseif (resp.status_code < 200 or resp.status_code >= 400) then
            log(ctx, "vertical request to service returned with status code: " .. resp.status)
            return
        end

        local gists = find(resp.body, gist_re)
        if (gists == nil or #gists == 0) then
            break
        end

        for _, gist in pairs(gists) do
            scrape(ctx, {['url']=gist})
        end
    end
end

function build_url(domain, pagenum)
    local params = {
        ['ref']="searchresults",
        ['q']=domain,
        ['p']=pagenum,
    }
    return "https://gist.github.com/search?" .. url.build_query_string(params)
end
