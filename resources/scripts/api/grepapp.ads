-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local url = require("url")

name = "GrepApp"
type = "api"

function start()
    set_rate_limit(2)
end

function vertical(ctx, domain)
    scrape(ctx, {['url']=api_url(domain)})
end

function api_url(domain)
    local params = {
        ['regexp']="true",
        ['q']="([_a-zA-Z0-9]{1}[_a-zA-Z0-9-]{0,61}[a-zA-Z0-9]{1}." .. domain .. ")",
    }

    return "https://grep.app/api/search?" .. url.build_query_string(params)
end
