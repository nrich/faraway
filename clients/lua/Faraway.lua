#!/usr/bin/lua 

module('Faraway', package.seeall)

local http = require('socket.http')
local json = require('json')
local socket = require('socket')

function New(construct)
    local host = construct.Host or '127.0.0.1'
    local ssl = construct.SSL or false
    local port = construct.Port

    if not port then
	if ssl then port = 9096 else port = 9095 end
    end

    if ssl then
	ssl = require('ssl')
    end

    local die_on_err = construct.DieOnError or false
    local simple_return = construct.DieOnError or construct.SimpleReturn or false

    local faraway = {}

    local function call_remote(self, action, data)
	local url = string.format('http://%s:%s/%s', host, port, action)

	local object = {
	    timestamp = os.time(),
	    data = data or {},
	}

	object.checksum = 1

	local str = json.encode(object)

	local body = ''

        local req, status = assert(http.request({
            url = url,
            method = 'POST',
            headers = {
                ["Content-Length"] = string.len(str),
                ["Content-Type"] =  "application/x-www-form-urlencoded",
            },
            source = ltn12.source.string(str),
	    sink = function(chunk, src_err)
		if chunk == nil then
		    if src_err then
			error(src_err)
		    else
		    end 

		    return true
		elseif chunk == "" then
		    return true
		else
		    body = body .. chunk

		    return true
		end
		
		return nil, err
	    end,

	    create = function()
		if not ssl then
		    return socket.tcp()
		end

		local params = {
		    mode = "client",
		    protocol = "sslv3",
		    --key = "/etc/certs/clientkey.pem",
		    --certificate = "/etc/certs/client.pem",
		    --cafile = "/etc/certs/CA.pem",
		    verify = "none",
		    options = "all",
		}
		
		local s = socket.tcp()

		local conn = {
		    connect = function(t, host, port)
			s:connect(host, port)
			s = ssl.wrap(s, params)
			s:dohandshake()

			return true
		    end,
		}

		setmetatable(conn, {
		    __index = function(t, k)
			return function(c, ...)
			    local f = s[k]

			    return f(s, ...)
			end
		    end
		})

		return conn
	    end,
        }))

	local response = json.decode(body)
	response.err = tonumber(response.err)

	if die_on_err then
	    if response.err ~= 0 then
		error(response.errmsg)
	    end
	end

	return response
    end

    setmetatable(faraway, {
	__index = function(self, key) 
	    local v = rawget(self, key)

	    if v ~= nil then 
		return v 
	    else
		local func = function(self, data)
		    return call_remote(self, key, data)
		end

		return func
	    end
	end,
    })

    return faraway
end
