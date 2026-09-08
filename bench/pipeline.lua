local depth = 1

function init(args)
    if args[1] ~= nil then
        depth = assert(tonumber(args[1]), "pipeline depth must be a number")
    end
    assert(depth >= 1 and depth % 1 == 0, "pipeline depth must be a positive integer")
end

function request()
    local requests = {}
    for i = 1, depth do
        requests[i] = wrk.format()
    end
    return table.concat(requests)
end
