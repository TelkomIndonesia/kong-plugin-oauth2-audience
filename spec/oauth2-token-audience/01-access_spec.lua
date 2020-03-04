local os = require 'os'
local http = require 'resty.http'
local ngx = require 'ngx'
local cjson = require 'cjson'

local helpers = require 'spec.helpers'
local plugin_name = 'oauth2-token-audience'
local spec_nginx_conf = 'spec/fixtures/custom_nginx.template'

local function split(inputstr, sep)
    if sep == nil then
        sep = '%s'
    end
    local t = {}
    for str in string.gmatch(inputstr, '([^' .. sep .. ']+)') do
        table.insert(t, str)
    end
    return t
end

local function get_plugin_config(is_jwt)
    local conf = {
        required_scope = split(os.getenv('OAUTH2_CLIENT_SCOPE'), ' '),
        issuer = os.getenv(is_jwt and 'IDP_JWT_ISSUER' or 'IDP_OPAQUE_ISSUER'),
        introspection_endpoint = os.getenv(
            is_jwt and 'IDP_JWT_INTROSPECTION_ENDPOINT' or 'IDP_OPAQUE_INTROSPECTION_ENDPOINT'
        ),
        introspection_client_id = os.getenv('OAUTH2_CLIENT_ID'),
        introspection_client_secret = os.getenv('OAUTH2_CLIENT_SECRET'),
        ssl_verify = false
    }
    return conf
end

local function get_token(is_jwt, scope, audience)
    local httpc = http.new()
    local uri = os.getenv(is_jwt and 'IDP_JWT_TOKEN_ENDPOINT' or 'IDP_OPAQUE_TOKEN_ENDPOINT')
    local req = {
        method = 'POST',
        body = ngx.encode_args(
            {
                grant_type = 'client_credentials',
                scope = scope or os.getenv('OAUTH2_CLIENT_SCOPE'),
                audience = audience or 'unknown'
            }
        ),
        headers = {
            ['Authorization'] = 'basic ' ..
                ngx.encode_base64(os.getenv('OAUTH2_CLIENT_ID') .. ':' .. os.getenv('OAUTH2_CLIENT_SECRET')),
            ['Content-Type'] = 'application/x-www-form-urlencoded'
        },
        ssl_verify = false
    }
    local res, err = httpc:request_uri(uri, req)
    if res and res.status ~= 200 then
        err = res.status .. ':' .. res.body
    end
    if err then
        return nil, err
    end
    local j = cjson.decode(res.body)
    return j.access_token, err
end

for _, strategy in helpers.each_strategy() do
    describe(
        'Plugin: ' .. plugin_name .. ' [#' .. strategy .. ']',
        function()
            local proxy_client

            setup(
                function()
                    local bp = helpers.get_db_utils(strategy, nil, {plugin_name})

                    local route = bp.routes:insert({hosts = {'test.com'}})
                    bp.plugins:insert(
                        {
                            name = plugin_name,
                            route = {id = route.id},
                            config = get_plugin_config()
                        }
                    )

                    assert(
                        helpers.start_kong(
                            {
                                database = strategy,
                                plugins = 'bundled,' .. plugin_name,
                                nginx_conf = spec_nginx_conf
                            }
                        )
                    )
                end
            )

            teardown(
                function()
                    helpers.stop_kong()
                end
            )

            before_each(
                function()
                    proxy_client = helpers.proxy_client()
                end
            )

            after_each(
                function()
                    if proxy_client then
                        proxy_client:close()
                    end
                end
            )

            describe(
                'when no access token is given',
                function()
                    local r
                    it(
                        'respond with 400',
                        function()
                            r =
                                proxy_client:get(
                                '/request',
                                {
                                    headers = {
                                        ['Host'] = 'test.com'
                                    }
                                }
                            )
                            assert.response(r).has.status(400)
                        end
                    )
                end
            )

            describe(
                'when access token is invalid',
                function()
                    local r
                    it(
                        'respond with 401',
                        function()
                            r =
                                proxy_client:get(
                                '/request',
                                {
                                    headers = {
                                        ['Host'] = 'test.com',
                                        ['authorization'] = 'bearer 12345'
                                    }
                                }
                            )
                            assert.response(r).has.status(401)
                        end
                    )
                end
            )

            describe(
                'when access token valid but unknown audience',
                function()
                    local r
                    it(
                        'respond with 401',
                        function()
                            local token, err = get_token()
                            assert.is_nil(err)
                            assert.is_not_nil(token)

                            r =
                                proxy_client:get(
                                '/request',
                                {
                                    headers = {
                                        ['Host'] = 'test.com',
                                        ['Authorization'] = 'bearer ' .. token
                                    }
                                }
                            )
                            assert.response(r).has.status(401)
                        end
                    )
                end
            )
        end
    )
end
