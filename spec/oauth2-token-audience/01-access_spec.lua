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
    required_scope = split(os.getenv('OAUTH2_CLIENT_SCOPE'), ' '),
    issuer = os.getenv(is_jwt and 'IDP_JWT_ISSUER' or 'IDP_OPAQUE_ISSUER'),
    introspection_endpoint = os.getenv(is_jwt and 'IDP_JWT_INTROSPECTION_ENDPOINT' or 'IDP_OPAQUE_INTROSPECTION_ENDPOINT'),
    introspection_client_id = os.getenv('OAUTH2_CLIENT_ID'),
    introspection_client_secret = os.getenv('OAUTH2_CLIENT_SECRET'),
    ssl_verify = false
  }
  return conf
end

local function get_audience_credential(is_jwt)
  return {
    audience = os.getenv("OAUTH2_CLIENT_AUDIENCE"),
    issuer = os.getenv(is_jwt and 'IDP_JWT_ISSUER' or 'IDP_OPAQUE_ISSUER'),
    client_id = os.getenv("OAUTH2_CLIENT_ID")
  }
end

local function get_token(is_jwt, id, secret, scope, audience)
  id = id or os.getenv('OAUTH2_CLIENT_ID')
  secret = secret or os.getenv('OAUTH2_CLIENT_SECRET')

  local httpc = http.new()
  local uri = os.getenv(is_jwt and 'IDP_JWT_TOKEN_ENDPOINT' or 'IDP_OPAQUE_TOKEN_ENDPOINT')
  local req = {
    method = 'POST',
    body = ngx.encode_args({
      grant_type = 'client_credentials',
      scope = scope or os.getenv('OAUTH2_CLIENT_SCOPE'),
      audience = audience or os.getenv('OAUTH2_CLIENT_AUDIENCE')
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

    describe('when access token valid but configured issuer did not match', function()
      it('respond with 401', function()
        local token, err = get_token()
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
        local token, err = get_token(false, nil, nil, nil, os.getenv('OAUTH2_CLIENT_AUDIENCE_UNREGISTED'))
        assert.is_nil(err)
        assert.is_not_nil(token)

        local r = proxy_client:get('/request', {headers = {['Host'] = 'oauth2.com', ['Authorization'] = 'bearer ' .. token}})
        assert.response(r).has.status(401)
      end)
    end)

    describe('when access token valid and credential match but scope inssuficient', function()
      it('respond with 403', function()
        local token, err = get_token(false, nil, nil, os.getenv('OAUTH2_CLIENT_SCOPE_UNREQUIRED'), nil)
        assert.is_nil(err)
        assert.is_not_nil(token)

        local r = proxy_client:get('/request', {headers = {['Host'] = 'oauth2.com', ['Authorization'] = 'bearer ' .. token}})
        assert.response(r).has.status(403)
      end)
    end)

    describe('when access token valid and audience match but client_id not match', function()
      it('respond with 401', function()
        local token, err = get_token(false, os.getenv('OAUTH2_MALCLIENT_ID'), os.getenv('OAUTH2_MALCLIENT_SECRET'), nil, nil)
        assert.is_nil(err)
        assert.is_not_nil(token)

        local r = proxy_client:get('/request', {headers = {['Host'] = 'oauth2.com', ['Authorization'] = 'bearer ' .. token}})
        assert.response(r).has.status(401)
      end)
    end)

    for _, is_jwt in ipairs({false, true}) do
      describe('when ' .. (is_jwt and 'jwt' or '') .. ' access token valid and credential match', function()
        it('respond with 200', function()
          local token, err = get_token(is_jwt)
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
