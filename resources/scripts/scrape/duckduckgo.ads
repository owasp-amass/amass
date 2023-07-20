-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

name = "DuckDuckGo"
type = "scrape"

function start()
    set_rate_limit(2)
end

function vertical(ctx, domain)
    local url = "https://html.duckduckgo.com/html/?q=site:" .. domain .. " -site:www." .. domain

    scrape(ctx, {['url']=url})
end
