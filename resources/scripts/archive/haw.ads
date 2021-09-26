-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "HAW"
type = "archive"

function start()
    set_rate_limit(4)
end

function vertical(ctx, domain)
    local page, err = request(ctx, {url=build_url(domain)})
    if (err ~= nil and err ~= "") then
        return
    end

    send_names(ctx, page:gsub("<b>", ""))
end

function build_url(domain)
    return "https://haw.nsk.hr/proxy.php?subject=keywords&start=undefined&q=" .. domain
end
