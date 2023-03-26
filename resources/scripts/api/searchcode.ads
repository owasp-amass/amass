-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

name = "Searchcode"
type = "api"

function start()
    set_rate_limit(2)
end

function vertical(ctx, domain)
    for i=0,49 do
        local ok = scrape(ctx, {['url']=build_url(domain, i)})
        if not ok then
            return
        end
    end
end

function build_url(domain, pagenum)
    return "https://searchcode.com/api/codesearch_I/?per_page=100&q=." .. domain .. "&p=" .. pagenum
end
