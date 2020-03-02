-- workaround for https://github.com/Kong/kong/issues/5549.
-- remove it when https://github.com/Kong/kong/pull/5599 is included in master.
local ffi = require('ffi')
ffi.cdef [[
struct evp_md_ctx_st
    {
    const EVP_MD *digest;
    ENGINE *engine;
    unsigned long flags;
    void *md_data;
    EVP_PKEY_CTX *pctx;
    int (*update)(EVP_MD_CTX *ctx,const void *data,size_t count);
    };
]]
--

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
