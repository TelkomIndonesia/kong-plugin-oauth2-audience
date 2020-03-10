local plugin = require('kong.plugins.base_plugin'):extend()
local plugin_name = ({...})[1]:match('^kong%.plugins%.([^%.]+)')
local access = require('kong.plugins.' .. plugin_name .. '.access')

function plugin:new()
  plugin.super.new(self, plugin_name)
end

function plugin:access(conf)
  plugin.super.access(self)
  return access.execute(conf)
end

plugin.PRIORITY = 1000
return plugin
