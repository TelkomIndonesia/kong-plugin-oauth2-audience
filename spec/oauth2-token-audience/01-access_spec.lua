local helpers = require 'spec.helpers'
local plugin_name = 'oauth2-token-audience'
describe(
    'Demo-Plugin: myplugin (access)',
    function()
        local proxy_client

        setup(
            function()
                local bp = helpers.get_db_utils(nil, nil, {plugin_name})

                -- create route that point to default service (local nginx listen in 127.0.0.1:15555)
                local route =
                    bp.routes:insert(
                    {
                        hosts = {'test1.com'}
                    }
                )

                -- add plugin to the api
                bp.plugins:insert {
                    name = plugin_name,
                    route = {id = route.id}
                }

                -- start kong and custom mock service
                assert(
                    helpers.start_kong(
                        {
                            plugins = 'bundled,' .. plugin_name,
                            nginx_conf = 'spec/fixtures/custom_nginx.template'
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
            'myplugin',
            function()
                local r
                it(
                    'successfully send the request',
                    function()
                        r =
                            proxy_client:get(
                            '/request',
                            {
                                headers = {
                                    ['Host'] = 'test1.com'
                                }
                            }
                        )
                        assert.response(r).has.status(200)
                    end
                )

                it(
                    "gets a 'hello-world' header",
                    function()
                        -- validate that the request succeeded, response status 200
                        -- now check the request (as echoed by mockbin) to have the header
                        local header_value = assert.request(r).has.header('hello-world')
                        -- validate the value of that header
                        assert.equal('this is on a request', header_value)
                    end
                )
            end
        )
    end
)
