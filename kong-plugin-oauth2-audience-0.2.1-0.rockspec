package = "kong-plugin-oauth2-audience"
version = "0.2.1-0"
local pluginName = package:match("^kong%-plugin%-(.+)$") 

supported_platforms = {"linux", "macosx"}
source = {
  url = "git+https://git.rucciva.one/mainapi/kong-plugin-oauth2-audience",
  tag = "0.2.1"
}

description = {
  summary = "Kong is a scalable and customizable API Management Layer built on top of Nginx.",
  homepage = "http://getkong.org",
  license = "MIT"
}

dependencies = {
    "lua-resty-openidc == 1.7.2-1",
    "lua-resty-jwt == 0.2.2-0"
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins."..pluginName..".handler"] = "kong/plugins/"..pluginName.."/handler.lua",
    ["kong.plugins."..pluginName..".schema"] = "kong/plugins/"..pluginName.."/schema.lua",
    ["kong.plugins."..pluginName..".access"] = "kong/plugins/"..pluginName.."/access.lua",
    ["kong.plugins."..pluginName..".error"] = "kong/plugins/"..pluginName.."/error.lua",
    ["kong.plugins."..pluginName..".daos"] = "kong/plugins/"..pluginName.."/daos.lua",
    ["kong.plugins."..pluginName..".migrations.init"] = "kong/plugins/"..pluginName.."/migrations/init.lua",
    ["kong.plugins."..pluginName..".migrations.000_base"] = "kong/plugins/"..pluginName.."/migrations/000_base.lua",
  }
}
