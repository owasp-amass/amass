-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

name = "Reverse DNS"
type = "dns"

local cfg

function start()
    cfg = config()
end

function resolved(ctx, name, domain, records)
    if (cfg == nil or cfg.mode == "passive") then
        return
    end

    if not in_scope(ctx, name) then
        return
    end

    for _, rec in pairs(records) do
        if (rec.rrtype == 1 or rec.rrtype == 28) then
            _ = reverse_sweep(ctx, rec.rrdata)
        end
    end
end
