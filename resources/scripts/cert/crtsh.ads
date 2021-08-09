-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "Crtsh"
type = "cert"

function start()
    set_rate_limit(2)
end

function vertical(ctx, domain)
    local vurl = "https://crt.sh/?q=%25." .. domain .. "&output=json"

    scrape(ctx, {['url']=vurl})
end
