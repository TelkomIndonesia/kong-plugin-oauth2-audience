local os = require 'os'
local http = require 'resty.http'
local ngx = require 'ngx'
local cjson = require 'cjson'

local helpers = require 'spec.helpers'
local plugin_name = 'oauth2-token-audience'
local spec_nginx_conf = 'spec/fixtures/custom_nginx.template'

local env = {
  idp_opaque_issuer = os.getenv('IDP_OPAQUE_ISSUER'),
  idp_opaque_introspection_endpoint = os.getenv('IDP_OPAQUE_INTROSPECTION_ENDPOINT'),
  idp_opaque_token_endpoint = os.getenv('IDP_OPAQUE_TOKEN_ENDPOINT'),
  idp_jwt_issuer = os.getenv('IDP_JWT_ISSUER'),
  idp_jwt_introspection_endpoint = os.getenv('IDP_JWT_INTROSPECTION_ENDPOINT'),
  idp_jwt_token_endpoint = os.getenv('IDP_JWT_TOKEN_ENDPOINT'),
  idp_kong_audience_prefix = os.getenv('IDP_KONG_AUDIENCE_PREFIX'),
  oauth2_client_id = os.getenv('OAUTH2_CLIENT_ID'),
  oauth2_client_secret = os.getenv('OAUTH2_CLIENT_SECRET'),
  oauth2_client_audience = os.getenv('OAUTH2_CLIENT_AUDIENCE'),
  oauth2_jwt_client_audience = os.getenv('OAUTH2_JWT_CLIENT_AUDIENCE'),
  oauth2_client_scope = os.getenv('OAUTH2_CLIENT_SCOPE'),
  oauth2_client_audience_unregisted = os.getenv('OAUTH2_CLIENT_AUDIENCE_UNREGISTED'),
  oauth2_client_audience_invalid_iss = os.getenv('OAUTH2_CLIENT_AUDIENCE_INVALID_ISS'),
  oauth2_client_audience_invalid_client_id = os.getenv('OAUTH2_CLIENT_AUDIENCE_INVALID_CLIENT_ID'),
  oauth2_client_scope_unrequired = os.getenv('OAUTH2_CLIENT_SCOPE_UNREQUIRED'),
  oauth2_malclient_id = os.getenv('OAUTH2_MALCLIENT_ID'),
  oauth2_malclient_secret = os.getenv('OAUTH2_MALCLIENT_SECRET')
}

local function split(inputstr, sep)
  sep = sep or '%s'
  local t = {}
  for str in string.gmatch(inputstr, '([^' .. sep .. ']+)') do
    table.insert(t, str)
  end
  return t
end

local function merge(t1, t2)
  local res = {}
  for k, v in pairs(t1 or {}) do
    res[k] = v
  end
  for k, v in pairs(t2 or {}) do
    res[k] = v
  end
  return res
end

local function get_plugin_config(is_jwt)
  local conf = {
    required_scope = split(env.oauth2_client_scope, ' '),
    issuer = is_jwt and env.idp_jwt_issuer or env.idp_opaque_issuer,
    introspection_endpoint = is_jwt and env.idp_jwt_introspection_endpoint or env.idp_opaque_introspection_endpoint,
    introspection_client_id = env.oauth2_client_id,
    introspection_client_secret = env.oauth2_client_secret,
    ssl_verify = false
  }
  return conf
end

local function get_audience_credential(is_jwt)
  return {
    audience = is_jwt and env.oauth2_jwt_client_audience or env.oauth2_client_audience,
    issuer = is_jwt and env.idp_jwt_issuer or env.idp_opaque_issuer,
    client_id = env.oauth2_client_id
  }
end

local function fetch_token(is_jwt, id, secret, scope, audience)
  id = id or env.oauth2_client_id
  secret = secret or env.oauth2_client_secret

  local httpc = http.new()
  local uri = is_jwt and env.idp_jwt_token_endpoint or env.idp_opaque_token_endpoint
  local req = {
    method = 'POST',
    body = ngx.encode_args({
      grant_type = 'client_credentials',
      scope = scope or env.oauth2_client_scope,
      audience = audience or (is_jwt and env.oauth2_jwt_client_audience or env.oauth2_client_audience)
    }),
    headers = {
      ['Authorization'] = 'basic ' .. ngx.encode_base64(id .. ':' .. secret),
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
  describe('Plugin: ' .. plugin_name .. ' [#' .. strategy .. ']', function()
    local proxy_client

    setup(function()
      local bp, db = helpers.get_db_utils(strategy, nil, {plugin_name})

      local route = bp.routes:insert({hosts = {'oauth2.com'}})
      bp.plugins:insert({name = plugin_name, route = {id = route.id}, config = get_plugin_config()})

      local route1 = bp.routes:insert({hosts = {'issuer-not-match.oauth2.com'}})
      bp.plugins:insert({
        name = plugin_name,
        route = {id = route1.id},
        config = merge(get_plugin_config(), {issuer = get_plugin_config(true).issuer})
      })

      local route2 = bp.routes:insert({hosts = {'oauth2-jwt.com'}})
      bp.plugins:insert({name = plugin_name, route = {id = route2.id}, config = get_plugin_config(true)})

      local consumer = db.consumers:insert({username = "client"})
      db.oauth2_token_audiences:insert(merge(get_audience_credential(), {consumer = {id = consumer.id}}))

      local jwt_consumer = db.consumers:insert({username = "jwt-client"})
      db.oauth2_token_audiences:insert(merge(get_audience_credential(true), {consumer = {id = jwt_consumer.id}}))

      local consumer_inviss = db.consumers:insert({username = "client-inviss"})
      db.oauth2_token_audiences:insert({
        consumer = {id = consumer_inviss.id},
        audience = env.oauth2_client_audience_invalid_iss,
        issuer = "https://invalid.tld/",
        client_id = env.oauth2_client_id
      })

      local consumer_invid = db.consumers:insert({username = "client-invid"})
      db.oauth2_token_audiences:insert(merge(get_audience_credential(), {
        consumer = {id = consumer_invid.id},
        audience = env.oauth2_client_audience_invalid_client_id,
        issuer = env.idp_opaque_issuer,
        client_id = 'invalid'
      }))

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

    describe('when no access token is given', function()
      it('respond with 400', function()
        local r = proxy_client:get('/request', {headers = {['Host'] = 'oauth2.com'}})
        assert.response(r).has.status(400)
      end)
    end)

    describe('when access token is invalid', function()
      it('respond with 401', function()
        local r = proxy_client:get('/request', {headers = {['Host'] = 'oauth2.com', ['authorization'] = 'bearer 12345'}})
        assert.response(r).has.status(401)
      end)
    end)

    describe('when access token valid but plugin\'s issuer did not match', function()
      it('respond with 401', function()
        local token, err = fetch_token()
        assert.is_nil(err)
        assert.is_not_nil(token)

        local r = proxy_client:get('/request', {
          headers = {['Host'] = 'issuer-not-match.oauth2.com', ['Authorization'] = 'bearer ' .. token}
        })
        assert.response(r).has.status(401)
      end)
    end)

    describe('when access token valid but unregistered audience', function()
      it('respond with 401', function()
        local token, err = fetch_token(false, nil, nil, nil, env.oauth2_client_audience_unregisted)
        assert.is_nil(err)
        assert.is_not_nil(token)

        local r = proxy_client:get('/request', {headers = {['Host'] = 'oauth2.com', ['Authorization'] = 'bearer ' .. token}})
        assert.response(r).has.status(401)
      end)
    end)

    describe('when access token valid but client_id did not match', function()
      it('respond with 401', function()
        local token, err = fetch_token(false, nil, nil, nil, env.oauth2_client_audience_invalid_client_id)
        assert.is_nil(err)
        assert.is_not_nil(token)

        local r = proxy_client:get('/request', {headers = {['Host'] = 'oauth2.com', ['Authorization'] = 'bearer ' .. token}})
        assert.response(r).has.status(401)
      end)
    end)

    describe('when access token valid but issuer did not match', function()
      it('respond with 401', function()
        local token, err = fetch_token(false, nil, nil, nil, env.oauth2_client_audience_invalid_iss)
        assert.is_nil(err)
        assert.is_not_nil(token)

        local r = proxy_client:get('/request', {headers = {['Host'] = 'oauth2.com', ['Authorization'] = 'bearer ' .. token}})
        assert.response(r).has.status(401)
      end)
    end)

    describe('when access token valid and credential match but scope insuficient', function()
      it('respond with 403', function()
        local token, err = fetch_token(false, nil, nil, env.oauth2_client_scope_unrequired, nil)
        assert.is_nil(err)
        assert.is_not_nil(token)

        local r = proxy_client:get('/request', {headers = {['Host'] = 'oauth2.com', ['Authorization'] = 'bearer ' .. token}})
        assert.response(r).has.status(403)
      end)
    end)

    describe('when access token valid and audience match but client_id not match', function()
      it('respond with 401', function()
        local token, err = fetch_token(false, env.oauth2_malclient_id, env.oauth2_malclient_secret, nil, nil)
        assert.is_nil(err)
        assert.is_not_nil(token)

        local r = proxy_client:get('/request', {headers = {['Host'] = 'oauth2.com', ['Authorization'] = 'bearer ' .. token}})
        assert.response(r).has.status(401)
      end)
    end)

    for _, is_jwt in ipairs({false, true}) do
      describe('when ' .. (is_jwt and 'jwt' or '') .. ' access token valid and credential match', function()
        it('respond with 200', function()
          local token, err = fetch_token(is_jwt)
          assert.is_nil(err)
          assert.is_not_nil(token)

          local r = proxy_client:get('/request', {
            headers = {['Host'] = is_jwt and 'oauth2-jwt.com' or 'oauth2.com', ['Authorization'] = 'bearer ' .. token}
          })
          assert.response(r).has.status(200)
        end)
      end)
    end

  end)
end
