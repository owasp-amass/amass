-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local url = require("url")

name = "PKey"
type = "scrape"

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    local params = {
        ['zone']=domain,
        ['submit']="",
    }

    scrape(ctx, {
        ['url']="https://www.pkey.in/tools-i/search-subdomains",
        ['method']="POST",
        ['header']={['Content-Type']="application/x-www-form-urlencoded"},
        ['body']=url.build_query_string(params),
    })
end
