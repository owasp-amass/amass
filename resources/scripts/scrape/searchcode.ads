-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "Searchcode"
type = "scrape"

function start()
    set_rate_limit(3)
end

function vertical(ctx, domain)
    for i=0,20 do
        local page, err = request(ctx, {url=build_url(domain, i)})
        if (err ~= nil and err ~= "") then
            break
        end

        page = page:gsub("<strong>", "")
        local ok = find_names(ctx, page)
        if not ok then
            break
        end

        check_rate_limit()
    end
end

function build_url(domain, pagenum)
    return "https://searchcode.com/?q=." .. domain .. "&p=" .. pagenum
end

function find_names(ctx, content)
    local names = find(content, subdomain_regex)
    if (names == nil or #names == 0) then
        return false
    end

    for i, name in pairs(names) do
        new_name(ctx, name)
    end
    return true
end
