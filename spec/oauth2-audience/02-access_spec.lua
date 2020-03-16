local ngx = require 'ngx'
local cjson = require 'cjson'

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

local pre_auth_simulation = [[
  local consumer = {id = "%s"}
  local credential = {id = "%s"}
  kong.client.authenticate(consumer, credential)
  kong.service.request.set_header("x-consumer-id", consumer.id)
]]

local token_locations = {'authorization', 'query', 'body'}
local function tokenize(req, token, location)
  if string.lower(location or '') == 'query' then
    req.query = req.query or {}
    req.query.access_token = token
    return req
  end

  if string.lower(location or '') == 'body' then
    req.method = "POST"
    req.headers = req.headers or {}
    req.headers["Content-Type"] = "application/x-www-form-urlencoded"
    req.body = req.body or {}
    req.body.access_token = token
    return req
  end

  req.headers = req.headers or {}
  req.headers[location or 'Authorization'] = 'bearer ' .. token
  return req
end

local function assert_www_authenticate_header(res, realm, err, description)
  local v = assert.response(res).has.header('www-authenticate')
  assert.equal(1, v:find(string.format('Bearer realm="%s"', realm)), v)
  if err then
    assert.is_not_nil(v:find(string.format('error="%s"', err)), v)
  else
    assert.is_nil(v:find('error='), v)
  end
  if description then
    assert.is_not_nil(v:find(string.format('error_description="%s"', description)), v)
  else
    assert.is_nil(v:find('error_description='), v)
  end
end

local function assert_upstream_credential(res, token, location)
  if string.lower(location or '') == 'query' then
    local h = assert.request(res).has.queryparam('access_token')
    return assert.equal(token, h)
  end

  if string.lower(location or '') == 'body' then
    local h = assert.request(res).has.formparam('access_token')
    return assert.equal(token, h)
  end

  local h = assert.request(res).has.header(location)
  return assert.equal('bearer ' .. token, h)
end

for _, strategy in helpers.each_strategy() do
  describe('Plugin: ' .. plugin_name .. ' (Access) [#' .. strategy .. ']', function()
    local proxy_client
    local consumer, credential, anonymous

    setup(function()
      local bp, db = helpers.get_db_utils(strategy, nil, {plugin_name})

      consumer = db.consumers:insert({username = "client"})
      credential = db[schema_name]:insert(get_audience_credential(false, {consumer = {id = consumer.id}}))
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

      anonymous = db.consumers:insert({username = "anonymous"})

      local route = bp.routes:insert({hosts = {'oauth2.com', 'introspected.oauth2.com'}})
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

      local route8 = bp.routes:insert({hosts = {'hidden.oauth2.com'}})
      bp.plugins:insert({
        name = plugin_name,
        route = {id = route8.id},
        config = get_plugin_config(false, {hide_credentials = true})
      })
      local route9 = bp.routes:insert({hosts = {'hidden.oauth2-jwt.com'}})
      bp.plugins:insert({
        name = plugin_name,
        route = {id = route9.id},
        config = get_plugin_config(true, {hide_credentials = true})
      })

      local route10 = bp.routes:insert({hosts = {'discovery-disabled.oauth2.com'}})
      bp.plugins:insert({
        name = plugin_name,
        route = {id = route10.id},
        config = get_plugin_config(false, {issuer = "https://invalid.tld", oidc_conf_discovery = false})
      })
      local route11 = bp.routes:insert({hosts = {'discovery-disabled.oauth2-jwt.com'}})
      bp.plugins:insert({
        name = plugin_name,
        route = {id = route11.id},
        config = get_plugin_config(true, {issuer = "https://invalid.tld", oidc_conf_discovery = false, jwt_introspection = true})
      })

      local route12 = bp.routes:insert({hosts = {'introspected.oauth2-jwt.com'}})
      bp.plugins:insert({
        name = plugin_name,
        route = {id = route12.id},
        config = get_plugin_config(true, {jwt_introspection = true})
      })

      local route13 = bp.routes:insert({hosts = {'anonymous.oauth2.com'}})
      bp.plugins:insert({
        name = plugin_name,
        route = {id = route13.id},
        config = get_plugin_config(false, {anonymous = anonymous.id})
      })
      local route14 = bp.routes:insert({hosts = {'authenticated.oauth2.com'}})
      bp.plugins:insert({
        name = plugin_name,
        route = {id = route14.id},
        config = get_plugin_config(false, {anonymous = consumer.id})
      })
      bp.plugins:insert({
        name = 'pre-function',
        route = {id = route14.id},
        config = {functions = {string.format(pre_auth_simulation, consumer.id, credential.id)}}
      })
      local route15 = bp.routes:insert({hosts = {'multiple-auth.oauth2.com'}})
      bp.plugins:insert({name = plugin_name, route = {id = route15.id}, config = get_plugin_config()})
      bp.plugins:insert({
        name = 'pre-function',
        route = {id = route15.id},
        config = {functions = {string.format(pre_auth_simulation, consumer.id, credential.id)}}
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
      local host_introspected = is_jwt and 'introspected.oauth2-jwt.com' or 'introspected.oauth2.com'
      local host_hidden = is_jwt and 'hidden.oauth2-jwt.com' or 'hidden.oauth2.com'
      local host_discovery_disabled = is_jwt and 'discovery-disabled.oauth2-jwt.com' or 'discovery-disabled.oauth2.com'

      describe('when no access token is given', function()
        it('respond with 401', function()
          local r = proxy_client:get('/request', {headers = {['Host'] = host}})
          assert.response(r).has.status(401)
          assert_www_authenticate_header(r, 'service')
        end)
      end)

      for _, location in ipairs(token_locations) do
        describe('when ' .. (is_jwt and 'jwt ' or '') .. 'access token in ' .. location .. ' is invalid', function()
          it('respond with 401', function()
            local req = {headers = {['Host'] = host}}
            local r = proxy_client:get('/request', tokenize(req, 12345, location))
            assert.response(r).has.status(401)
            assert_www_authenticate_header(r, 'service', 'invalid_token', 'invalid or expired access token')
          end)
        end)
      end

      describe('when ' .. (is_jwt and 'jwt ' or '') .. 'access token is valid but plugin\'s issuer did not match', function()
        it('respond with 401', function()
          local token = fetch_token(is_jwt)
          local req = {headers = {['Host'] = host_alias}}
          local r = proxy_client:get('/request', tokenize(req, token))
          assert.response(r).has.status(401)
          assert_www_authenticate_header(r, 'service', 'invalid_token', 'invalid issuer')
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt ' or '') ..
                 'access token valid but issuer invalid due to discovery disabled and wrong issuer', function()
        it('respond with 401', function()
          local token = fetch_token(is_jwt, env.oauth2_client_audience_invalid_iss)
          local req = {headers = {['Host'] = host_discovery_disabled}}
          local r = proxy_client:get('/request', tokenize(req, token))
          assert.response(r).has.status(401)
          assert_www_authenticate_header(r, 'service', 'invalid_token', 'invalid issuer')
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt ' or '') .. 'access token valid but unregistered audience', function()
        it('respond with 401', function()
          local token = fetch_token(is_jwt, env.oauth2_client_audience_unregisted)
          local req = {headers = {['Host'] = host}}
          local r = proxy_client:get('/request', tokenize(req, token))
          assert.response(r).has.status(401)
          assert_www_authenticate_header(r, 'service', 'invalid_token', 'invalid audience')
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt ' or '') .. 'access token valid but client_id did not match', function()
        it('respond with 401', function()
          local token = fetch_token(is_jwt, env.oauth2_client_audience_invalid_client_id)
          local req = {headers = {['Host'] = host}}
          local r = proxy_client:get('/request', tokenize(req, token))
          assert.response(r).has.status(401)
          assert_www_authenticate_header(r, 'service', 'invalid_token', 'invalid client_id for the given audience')
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt ' or '') .. 'access token valid but issuer did not match', function()
        it('respond with 401', function()
          local token = fetch_token(is_jwt, env.oauth2_client_audience_invalid_iss)
          local req = {headers = {['Host'] = host}}
          local r = proxy_client:get('/request', tokenize(req, token))
          assert.response(r).has.status(401)
          assert_www_authenticate_header(r, 'service', 'invalid_token', 'invalid issuer for the given audience')
        end)
      end)

      for _, location in ipairs(token_locations) do
        describe('when ' .. (is_jwt and 'jwt ' or '') .. 'access token in ' .. location .. ' match credential', function()
          it('respond with 200', function()
            local token = fetch_token(is_jwt)
            local req = {headers = {['Host'] = host}}
            local r = proxy_client:get('/request', tokenize(req, token, location))
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

            assert_upstream_credential(r, token, location)
          end)
        end)
      end

      for _, location in ipairs(token_locations) do
        describe('when ' .. (is_jwt and 'jwt ' or '') .. 'access token in ' .. location ..
                   ' match credential and credential hidden', function()
          it('respond with 200', function()
            local token = fetch_token(is_jwt)
            local req = {headers = {['Host'] = host_hidden}}
            local r = proxy_client:get('/request', tokenize(req, token, location))
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

            local body = cjson.decode(assert.res_status(200, r))
            assert.is_nil(body.headers[location])
            assert.is_nil(body.uri_args[location])
            assert.is_nil(body.post_data[location])
          end)
        end)
      end

      describe('when ' .. (is_jwt and 'jwt ' or '') .. 'access token match prefixed credential', function()
        it('respond with 200', function()
          local audience = env.idp_kong_audience_prefix ..
                             (is_jwt and env.oauth2_jwt_client_audience or env.oauth2_client_audience)
          local token = fetch_token(is_jwt, audience)
          local req = {headers = {['Host'] = host_prefixed}}
          local r = proxy_client:get('/request', tokenize(req, token))
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

          h = assert.request(r).has.header('authorization')
          assert.equal('bearer ' .. token, h)
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt ' or '') .. 'access token did not match prefixed credential', function()
        it('respond with 200', function()
          local token = fetch_token(is_jwt)
          local req = {headers = {['Host'] = host_prefixed}}
          local r = proxy_client:get('/request', tokenize(req, token))
          assert.response(r).has.status(401)
          assert_www_authenticate_header(r, 'service', 'invalid_token', 'missing suitable audience in access token metadata')
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt ' or '') .. 'access token match credential but scope insuficient', function()
        it('respond with 403', function()
          local token = fetch_token(is_jwt, nil, env.oauth2_client_scope_unrequired)
          local req = {headers = {['Host'] = host}}
          local r = proxy_client:get('/request', tokenize(req, token))
          assert.response(r).has.status(403)
          assert_www_authenticate_header(r, 'service', 'insufficient_scope', 'missing one or more required scope')
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt' or '') .. ' access token match credential but required audiences are missing',
               function()
        it('respond with 403', function()
          local token = fetch_token(is_jwt, {is_jwt and env.oauth2_jwt_client_audience or env.oauth2_client_audience})
          local req = {headers = {['Host'] = host}}
          local r = proxy_client:get('/request', tokenize(req, token))
          assert.response(r).has.status(403)
          assert_www_authenticate_header(r, 'service', 'insufficient_scope', 'missing one or more required audiences')
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt ' or '') .. 'access token valid but revoked after cache expire', function()
        it('respond with 401', function()
          local token = fetch_token(is_jwt)
          local req = {headers = {['Host'] = host_short_ttl}}

          for i = 1, 2 do
            local r = proxy_client:get('/request', tokenize(req, token))
            assert.response(r).has.status(200)
            ngx.sleep(0.5)
          end

          -- revoke
          revoke(is_jwt, token)
          local r = proxy_client:get('/request', tokenize(req, token))
          assert.response(r).has.status(401)
          assert_www_authenticate_header(r, 'service', 'invalid_token', 'invalid or expired access token')
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt ' or '') .. 'access token valid but revoked before cache expire', function()
        it('respond with 401', function()
          local token = fetch_token(is_jwt)

          for i = 1, 3 do
            local req = {headers = {['Host'] = host_introspected}}
            local r = proxy_client:get('/request', tokenize(req, token))
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
          local req = {headers = {['Host'] = host}}
          local r = proxy_client:get('/request', tokenize(req, token))
          assert.response(r).has.status(200)

          ngx.sleep(0.5)
          revoke(true, token)
        end

      end)
    end)

    describe('when anonymous is set and can\'t be authenticated via oauth2-audience ', function()
      it('authenticate as anonymous consumer', function()
        local req = {headers = {['Host'] = "anonymous.oauth2.com"}}
        local r = proxy_client:get('/request', req)
        assert.response(r).has.status(200)

        local h = assert.request(r).has.header('x-consumer-id')
        assert.equal(anonymous.id, h)
      end)
    end)

    describe('when anonymous is set and already authenticated by other plugin', function()
      it('authenticate as anonymous consumer', function()
        local req = {headers = {['Host'] = "authenticated.oauth2.com"}}
        local r = proxy_client:get('/request', req)
        assert.response(r).has.status(200)

        local h = assert.request(r).has.header('x-consumer-id')
        assert.equal(consumer.id, h)
      end)
    end)

    describe('when anonymous is not set despite already authenticated by other plugin', function()
      it('respond with 401', function()
        local req = {headers = {['Host'] = "multiple-auth.oauth2.com"}}
        local r = proxy_client:get('/request', req)
        assert.response(r).has.status(401)
        assert_www_authenticate_header(r, 'service')
      end)
    end)

  end)
end
