-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

name = "UKWebArchive"
type = "archive"

function start()
    set_rate_limit(3)
end

function vertical(ctx, domain)
    scrape(ctx, {['url']=build_url(domain)})
end

function build_url(domain)
    return "https://www.webarchive.org.uk/wayback/archive/cdx?matchType=domain&output=json&url=" .. domain
end
