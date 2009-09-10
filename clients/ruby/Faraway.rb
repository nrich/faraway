#!/usr/bin/ruby

require 'net/http'
require 'net/https'
require 'uri'
require 'json'

class Faraway
    def initialize(args)
	@ssl = args[:ssl] || false
	@port = args[:port]

	if @port.nil? then
	    @port = @ssl ? 9096 : 9095
	end

	@host = args[:host] || '127.0.0.1'
    end

    def method_missing(m, *args)
	return call_remote(m, args)
    end

    def call_remote(action, data = {})
	http = Net::HTTP.new(@host, @port)
	http.use_ssl=@ssl

	obj = {
	    'timestamp' => Time.now.to_i,
	    'checksum' => 1,
	    'data' => data,
	}

	headers = {
	    'Content-Type' => 'application/x-www-form-urlencoded'
	}

	res, data = http.post("/#{action}", JSON.JSON(obj), headers)

	return JSON.parse(res.body)
    end
end

