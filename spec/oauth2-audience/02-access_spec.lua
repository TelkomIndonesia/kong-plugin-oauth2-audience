local ngx = require 'ngx'

local helpers = require 'spec.helpers'
local spec_nginx_conf = 'spec/fixtures/custom_nginx.template'

local plugin_name = 'oauth2-audience'
local schema_name = 'oauth2_audiences'
local oauth2_server = require('spec.' .. plugin_name .. '.oauth2-server')
local env = oauth2_server.env
local get_plugin_config = oauth2_server.get_plugin_config
local get_audience_credential = oauth2_server.get_audience_credential
local fetch_token = oauth2_server.fetch_token
local revoke = oauth2_server.revoke

for _, strategy in helpers.each_strategy() do
  describe('Plugin: ' .. plugin_name .. ' (Access) [#' .. strategy .. ']', function()
    local proxy_client
    local consumer

    setup(function()
      local bp, db = helpers.get_db_utils(strategy, nil, {plugin_name})

      local route = bp.routes:insert({hosts = {'oauth2.com'}})
      bp.plugins:insert({name = plugin_name, route = {id = route.id}, config = get_plugin_config()})

      local route1 = bp.routes:insert({hosts = {'oauth2-jwt.com'}})
      bp.plugins:insert({name = plugin_name, route = {id = route1.id}, config = get_plugin_config(true)})

      local route2 = bp.routes:insert({hosts = {'alias.oauth2.com'}})
      bp.plugins:insert({
        name = plugin_name,
        route = {id = route2.id},
        config = get_plugin_config(false, {issuer = env.idp_opaque_issuer_alias})
      })

      local route3 = bp.routes:insert({hosts = {'alias.oauth2-jwt.com'}})
      bp.plugins:insert({
        name = plugin_name,
        route = {id = route3.id},
        config = get_plugin_config(true, {issuer = env.idp_jwt_issuer_alias})
      })

      local route4 = bp.routes:insert({hosts = {'prefixed.oauth2.com'}})
      bp.plugins:insert({
        name = plugin_name,
        route = {id = route4.id},
        config = get_plugin_config(false, {audience_prefix = env.idp_kong_audience_prefix})
      })

      local route5 = bp.routes:insert({hosts = {'prefixed.oauth2-jwt.com'}})
      bp.plugins:insert({
        name = plugin_name,
        route = {id = route5.id},
        config = get_plugin_config(true, {audience_prefix = env.idp_kong_audience_prefix})
      })

      local route6 = bp.routes:insert({hosts = {'short-ttl.oauth2.com'}})
      bp.plugins:insert({
        name = plugin_name,
        route = {id = route6.id},
        config = get_plugin_config(false, {introspection_cache_max_ttl = 0.001})
      })
      local route7 = bp.routes:insert({hosts = {'short-ttl.oauth2-jwt.com'}})
      bp.plugins:insert({
        name = plugin_name,
        route = {id = route7.id},
        config = get_plugin_config(true, {jwt_introspection = true, introspection_cache_max_ttl = 0.001})
      })

      local route8 = bp.routes:insert({hosts = {'introspected.oauth2-jwt.com'}})
      bp.plugins:insert({
        name = plugin_name,
        route = {id = route8.id},
        config = get_plugin_config(true, {jwt_introspection = true})
      })

      consumer = db.consumers:insert({username = "client"})
      db[schema_name]:insert(get_audience_credential(false, {consumer = {id = consumer.id}}))
      db[schema_name]:insert(get_audience_credential(true, {consumer = {id = consumer.id}}))
      db[schema_name]:insert({
        consumer = {id = consumer.id},
        audience = env.oauth2_client_audience_invalid_iss,
        issuer = "https://other.idp.tld/",
        client_id = env.oauth2_client_id
      })
      db[schema_name]:insert({
        consumer = {id = consumer.id},
        audience = env.oauth2_client_audience_invalid_client_id,
        issuer = env.idp_opaque_issuer,
        client_id = 'other-client'
      })

      assert(helpers.start_kong({database = strategy, plugins = 'bundled,' .. plugin_name, nginx_conf = spec_nginx_conf}))
    end)

    teardown(function()
      helpers.stop_kong()
    end)

    before_each(function()
      proxy_client = helpers.proxy_client()
    end)

    after_each(function()
      if proxy_client then
        proxy_client:close()
      end
    end)

    for _, is_jwt in ipairs({false, true}) do
      local host = is_jwt and 'oauth2-jwt.com' or 'oauth2.com'
      local host_alias = is_jwt and 'alias.oauth2-jwt.com' or 'alias.oauth2.com'
      local host_prefixed = is_jwt and 'prefixed.oauth2-jwt.com' or 'prefixed.oauth2.com'
      local host_short_ttl = is_jwt and 'short-ttl.oauth2-jwt.com' or 'short-ttl.oauth2.com'
      local host_introspected = is_jwt and 'introspected.oauth2-jwt.com' or 'oauth2.com'

      describe('when no access token is given', function()
        it('respond with 401', function()
          local r = proxy_client:get('/request', {headers = {['Host'] = host}})
          assert.response(r).has.status(401)
          local v = assert.response(r).has.header('www-authenticate')
          assert.equal('Bearer realm="service"', v)
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt ' or '') .. 'access token is invalid', function()
        it('respond with 401', function()
          local r = proxy_client:get('/request', {headers = {['Host'] = host, ['authorization'] = 'bearer 12345'}})
          assert.response(r).has.status(401)
          local v = assert.response(r).has.header('www-authenticate')
          assert.equal(1, v:find('Bearer realm="service"'), v)
          assert.is_not_nil(v:find('error="invalid_token"'), v)
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt ' or '') .. 'access token valid but plugin\'s issuer did not match', function()
        it('respond with 401', function()
          local token = fetch_token(is_jwt)
          local r = proxy_client:get('/request', {headers = {['Host'] = host_alias, ['Authorization'] = 'bearer ' .. token}})
          assert.response(r).has.status(401)
          local v = assert.response(r).has.header('www-authenticate')
          assert.equal(1, v:find('Bearer realm="service"'), v)
          assert.is_not_nil(v:find('error="invalid_token"'), v)
          assert.is_not_nil(v:find('error_description="invalid issuer"'), v)
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt ' or '') .. 'access token valid but unregistered audience', function()
        it('respond with 401', function()
          local token = fetch_token(is_jwt, env.oauth2_client_audience_unregisted)
          local r = proxy_client:get('/request', {headers = {['Host'] = host, ['Authorization'] = 'bearer ' .. token}})
          assert.response(r).has.status(401)
          local v = assert.response(r).has.header('www-authenticate')
          assert.equal(1, v:find('Bearer realm="service"'), v)
          assert.is_not_nil(v:find('error="invalid_token"'), v)
          assert.is_not_nil(v:find('error_description="invalid audience"'), v)
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt ' or '') .. 'access token valid but client_id did not match', function()
        it('respond with 401', function()
          local token = fetch_token(is_jwt, env.oauth2_client_audience_invalid_client_id)
          local r = proxy_client:get('/request', {headers = {['Host'] = host, ['Authorization'] = 'bearer ' .. token}})
          assert.response(r).has.status(401)
          local v = assert.response(r).has.header('www-authenticate')
          assert.equal(1, v:find('Bearer realm="service"'), v)
          assert.is_not_nil(v:find('error="invalid_token"'), v)
          assert.is_not_nil(v:find('error_description="invalid client_id for the given audience"'), v)
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt ' or '') .. 'access token valid but issuer did not match', function()
        it('respond with 401', function()
          local token = fetch_token(is_jwt, env.oauth2_client_audience_invalid_iss)
          local r = proxy_client:get('/request', {headers = {['Host'] = host, ['Authorization'] = 'bearer ' .. token}})
          assert.response(r).has.status(401)
          local v = assert.response(r).has.header('www-authenticate')
          assert.equal(1, v:find('Bearer realm="service"'), v)
          assert.is_not_nil(v:find('error="invalid_token"'), v)
          assert.is_not_nil(v:find('error_description="invalid issuer for the given audience"'), v)
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt ' or '') .. 'access token match credential', function()
        it('respond with 200', function()
          local token = fetch_token(is_jwt)
          local r = proxy_client:get('/request', {headers = {['Host'] = host, ['Authorization'] = 'bearer ' .. token}})
          assert.response(r).has.status(200)

          local h
          h = assert.request(r).has.header('x-oauth2-issuer')
          assert.equal(is_jwt and env.idp_jwt_issuer or env.idp_opaque_issuer, h)
          h = assert.request(r).has.header('x-oauth2-client')
          assert.equal(env.oauth2_client_id, h)
          h = assert.request(r).has.header('x-oauth2-subject')
          assert.equal(env.oauth2_client_id, h)

          h = assert.request(r).has.header('x-consumer-id')
          assert.equal(consumer.id, h)
          h = assert.request(r).has.header('x-authenticated-audience')
          assert.equal(is_jwt and env.oauth2_jwt_client_audience or env.oauth2_client_audience, h)
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt ' or '') .. 'access token match prefixed credential', function()
        it('respond with 200', function()
          local audience = env.idp_kong_audience_prefix ..
                             (is_jwt and env.oauth2_jwt_client_audience or env.oauth2_client_audience)
          local token = fetch_token(is_jwt, audience)
          local r = proxy_client:get('/request', {headers = {['Host'] = host_prefixed, ['Authorization'] = 'bearer ' .. token}})
          assert.response(r).has.status(200)

          local h
          h = assert.request(r).has.header('x-oauth2-issuer')
          assert.equal(is_jwt and env.idp_jwt_issuer or env.idp_opaque_issuer, h)
          h = assert.request(r).has.header('x-oauth2-client')
          assert.equal(env.oauth2_client_id, h)
          h = assert.request(r).has.header('x-oauth2-subject')
          assert.equal(env.oauth2_client_id, h)

          h = assert.request(r).has.header('x-consumer-id')
          assert.equal(consumer.id, h)
          h = assert.request(r).has.header('x-authenticated-audience')
          assert.equal(is_jwt and env.oauth2_jwt_client_audience or env.oauth2_client_audience, h)
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt ' or '') .. 'access token did not match prefixed credential', function()
        it('respond with 200', function()
          local token = fetch_token(is_jwt)
          local r = proxy_client:get('/request', {headers = {['Host'] = host_prefixed, ['Authorization'] = 'bearer ' .. token}})
          assert.response(r).has.status(401)
          local v = assert.response(r).has.header('www-authenticate')
          assert.equal(1, v:find('Bearer realm="service"'), v)
          assert.is_not_nil(v:find('error="invalid_token"'), v)
          assert.is_not_nil(v:find('error_description="missing suitable audience in access token metadata"'), v)
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt ' or '') .. 'access token match credential but scope insuficient', function()
        it('respond with 403', function()
          local token = fetch_token(is_jwt, nil, env.oauth2_client_scope_unrequired)
          local r = proxy_client:get('/request', {headers = {['Host'] = host, ['Authorization'] = 'bearer ' .. token}})
          assert.response(r).has.status(403)
          local v = assert.response(r).has.header('www-authenticate')
          assert.equal(1, v:find('Bearer realm="service"'), v)
          assert.is_not_nil(v:find('error="insufficient_scope"'), v)
          assert.is_not_nil(v:find('error_description="missing one or more required scope"'), v)
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt' or '') .. ' access token match credential but required audiences are missing',
               function()
        it('respond with 403', function()
          local token = fetch_token(is_jwt, {is_jwt and env.oauth2_jwt_client_audience or env.oauth2_client_audience})
          local r = proxy_client:get('/request', {headers = {['Host'] = host, ['Authorization'] = 'bearer ' .. token}})
          assert.response(r).has.status(403)
          local v = assert.response(r).has.header('www-authenticate')
          assert.equal(1, v:find('Bearer realm="service"'), v)
          assert.is_not_nil(v:find('error="insufficient_scope"'), v)
          assert.is_not_nil(v:find('error_description="missing one or more required audiences"'), v)
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt ' or '') .. 'access token valid but revoked after cache expire', function()
        it('respond with 401', function()
          local token = fetch_token(is_jwt)

          for i = 1, 2 do
            local r = proxy_client:get('/request',
                                       {headers = {['Host'] = host_short_ttl, ['Authorization'] = 'bearer ' .. token}})
            assert.response(r).has.status(200)
            ngx.sleep(0.5)
          end

          -- revoke
          revoke(is_jwt, token)
          local r =
            proxy_client:get('/request', {headers = {['Host'] = host_short_ttl, ['Authorization'] = 'bearer ' .. token}})
          assert.response(r).has.status(401)
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt ' or '') .. 'access token valid but revoked before cache expire', function()
        it('respond with 401', function()
          local token = fetch_token(is_jwt)

          for i = 1, 3 do
            local r = proxy_client:get('/request',
                                       {headers = {['Host'] = host_introspected, ['Authorization'] = 'bearer ' .. token}})
            assert.response(r).has.status(200)
            ngx.sleep(0.5)
            revoke(is_jwt, token)
          end

        end)
      end)
    end

    describe('when jwt access token valid and revoked before cache expire but without jwt_introspection', function()
      it('does not introspect the token', function()
        local token = fetch_token(true)
        local host = 'oauth2-jwt.com'

        for i = 1, 3 do
          local r = proxy_client:get('/request', {headers = {['Host'] = host, ['Authorization'] = 'bearer ' .. token}})
          assert.response(r).has.status(200)
          ngx.sleep(0.5)
          revoke(true, token)
        end

      end)
    end)

  end)
end
