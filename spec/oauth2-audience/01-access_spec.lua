local os = require 'os'
local http = require 'resty.http'
local ngx = require 'ngx'
local cjson = require 'cjson'

local helpers = require 'spec.helpers'
local plugin_name = 'oauth2-audience'
local spec_nginx_conf = 'spec/fixtures/custom_nginx.template'

local env = {
  idp_opaque_issuer = os.getenv('IDP_OPAQUE_ISSUER'),
  idp_opaque_issuer_alias = os.getenv('IDP_OPAQUE_ISSUER_ALIAS'),
  idp_opaque_introspection_endpoint = os.getenv('IDP_OPAQUE_INTROSPECTION_ENDPOINT'),
  idp_opaque_token_endpoint = os.getenv('IDP_OPAQUE_TOKEN_ENDPOINT'),
  idp_opaque_revoke_endpoint = os.getenv('IDP_OPAQUE_REVOKE_ENDPOINT'),
  idp_jwt_issuer = os.getenv('IDP_JWT_ISSUER'),
  idp_jwt_issuer_alias = os.getenv('IDP_JWT_ISSUER_ALIAS'),
  idp_jwt_introspection_endpoint = os.getenv('IDP_JWT_INTROSPECTION_ENDPOINT'),
  idp_jwt_token_endpoint = os.getenv('IDP_JWT_TOKEN_ENDPOINT'),
  idp_jwt_revoke_endpoint = os.getenv('IDP_JWT_REVOKE_ENDPOINT'),
  idp_kong_audience_prefix = os.getenv('IDP_KONG_AUDIENCE_PREFIX'),
  oauth2_client_id = os.getenv('OAUTH2_CLIENT_ID'),
  oauth2_client_secret = os.getenv('OAUTH2_CLIENT_SECRET'),
  oauth2_client_audience = os.getenv('OAUTH2_CLIENT_AUDIENCE'),
  oauth2_jwt_client_audience = os.getenv('OAUTH2_JWT_CLIENT_AUDIENCE'),
  oauth2_client_scope = os.getenv('OAUTH2_CLIENT_SCOPE'),
  oauth2_client_audience_existing = os.getenv('OAUTH2_CLIENT_AUDIENCE_EXISTING'),
  oauth2_client_audience_unregisted = os.getenv('OAUTH2_CLIENT_AUDIENCE_UNREGISTED'),
  oauth2_client_audience_invalid_iss = os.getenv('OAUTH2_CLIENT_AUDIENCE_INVALID_ISS'),
  oauth2_client_audience_invalid_client_id = os.getenv('OAUTH2_CLIENT_AUDIENCE_INVALID_CLIENT_ID'),
  oauth2_client_scope_unrequired = os.getenv('OAUTH2_CLIENT_SCOPE_UNREQUIRED')
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

local function get_plugin_config(is_jwt, replace)
  return merge({
    required_scope = split(env.oauth2_client_scope, ' '),
    issuer = is_jwt and env.idp_jwt_issuer or env.idp_opaque_issuer,
    introspection_endpoint = is_jwt and env.idp_jwt_introspection_endpoint or env.idp_opaque_introspection_endpoint,
    introspection_client_id = env.oauth2_client_id,
    introspection_client_secret = env.oauth2_client_secret,
    ssl_verify = false
  }, replace)
end

local function get_audience_credential(is_jwt, replace)
  return merge({
    audience = is_jwt and env.oauth2_jwt_client_audience or env.oauth2_client_audience,
    issuer = is_jwt and env.idp_jwt_issuer or env.idp_opaque_issuer,
    client_id = env.oauth2_client_id
  }, replace)
end

local function fetch_token(is_jwt, audience, scope)
  local id = env.oauth2_client_id
  local secret = env.oauth2_client_secret
  audience = audience or {(is_jwt and env.oauth2_jwt_client_audience or env.oauth2_client_audience)}
  audience = type(audience) == 'string' and {audience} or audience
  table.insert(audience, env.oauth2_client_audience_existing)

  local httpc = http.new()
  local uri = is_jwt and env.idp_jwt_token_endpoint or env.idp_opaque_token_endpoint
  local req = {
    method = 'POST',
    body = ngx.encode_args({
      grant_type = 'client_credentials',
      scope = scope or env.oauth2_client_scope,
      audience = table.concat(audience, ' ')
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
  assert.is_nil(err)
  local j = cjson.decode(res.body)
  return assert.is_not_nil(j.access_token)
end

local function revoke(is_jwt, token)
  local id = env.oauth2_client_id
  local secret = env.oauth2_client_secret

  local httpc = http.new()
  local uri = is_jwt and env.idp_jwt_revoke_endpoint or env.idp_opaque_revoke_endpoint
  local req = {
    method = 'POST',
    body = ngx.encode_args({token = token}),
    headers = {
      ['Authorization'] = 'basic ' .. ngx.encode_base64(id .. ':' .. secret),
      ['Content-Type'] = 'application/x-www-form-urlencoded'
    }
  }
  local res, err = httpc:request_uri(uri, req)
  if res and res.status ~= 200 then
    err = res.status .. ':' .. res.body
  end
  return assert.is_nil(err)
end

for _, strategy in helpers.each_strategy() do
  describe('Plugin: ' .. plugin_name .. ' [#' .. strategy .. ']', function()
    local proxy_client

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

      local route6 = bp.routes:insert({hosts = {'oauth2-jwt-introspect.com'}})
      bp.plugins:insert({
        name = plugin_name,
        route = {id = route6.id},
        config = get_plugin_config(true, {jwt_introspection = true, introspection_cache_max_ttl = 0.001})
      })

      local consumer = db.consumers:insert({username = "client"})
      db.oauth2_audiences:insert(get_audience_credential(false, {consumer = {id = consumer.id}}))
      db.oauth2_audiences:insert(get_audience_credential(true, {consumer = {id = consumer.id}}))
      db.oauth2_audiences:insert({
        consumer = {id = consumer.id},
        audience = env.oauth2_client_audience_invalid_iss,
        issuer = "https://other.idp.tld/",
        client_id = env.oauth2_client_id
      })
      db.oauth2_audiences:insert({
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

      describe('when no access token is given', function()
        it('respond with 401', function()
          local r = proxy_client:get('/request', {headers = {['Host'] = host}})
          assert.response(r).has.status(401)
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt' or '') .. ' access token is invalid', function()
        it('respond with 401', function()
          local r = proxy_client:get('/request', {headers = {['Host'] = host, ['authorization'] = 'bearer 12345'}})
          assert.response(r).has.status(401)
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt' or '') .. ' access token valid but plugin\'s issuer did not match', function()
        it('respond with 401', function()
          local token = fetch_token()
          local r = proxy_client:get('/request', {headers = {['Host'] = host_alias, ['Authorization'] = 'bearer ' .. token}})
          assert.response(r).has.status(401)
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt' or '') .. ' access token valid but unregistered audience', function()
        it('respond with 401', function()
          local token = fetch_token(is_jwt, env.oauth2_client_audience_unregisted)
          local r = proxy_client:get('/request', {headers = {['Host'] = host, ['Authorization'] = 'bearer ' .. token}})
          assert.response(r).has.status(401)
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt' or '') .. ' access token valid but client_id did not match', function()
        it('respond with 401', function()
          local token = fetch_token(is_jwt, env.oauth2_client_audience_invalid_client_id)
          local r = proxy_client:get('/request', {headers = {['Host'] = host, ['Authorization'] = 'bearer ' .. token}})
          assert.response(r).has.status(401)
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt' or '') .. ' access token valid but issuer did not match', function()
        it('respond with 401', function()
          local token = fetch_token(is_jwt, env.oauth2_client_audience_invalid_iss)
          local r = proxy_client:get('/request', {headers = {['Host'] = host, ['Authorization'] = 'bearer ' .. token}})
          assert.response(r).has.status(401)
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt' or '') .. ' access token match credential', function()
        it('respond with 200', function()
          local token = fetch_token(is_jwt)
          local r = proxy_client:get('/request', {headers = {['Host'] = host, ['Authorization'] = 'bearer ' .. token}})
          assert.response(r).has.status(200)
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt' or '') .. ' access token not match prefixed credential', function()
        it('respond with 200', function()
          local token = fetch_token(is_jwt)
          local r = proxy_client:get('/request', {headers = {['Host'] = host_prefixed, ['Authorization'] = 'bearer ' .. token}})
          assert.response(r).has.status(401)
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt' or '') .. ' access token match prefixed credential', function()
        it('respond with 200', function()
          local audience = env.idp_kong_audience_prefix ..
                             (is_jwt and env.oauth2_jwt_client_audience or env.oauth2_client_audience)
          local token = fetch_token(is_jwt, audience)
          local r = proxy_client:get('/request', {headers = {['Host'] = host_prefixed, ['Authorization'] = 'bearer ' .. token}})
          assert.response(r).has.status(200)
        end)
      end)

      describe('when ' .. (is_jwt and 'jwt' or '') .. ' access token match credential but scope insuficient', function()
        it('respond with 403', function()
          local token = fetch_token(is_jwt, nil, env.oauth2_client_scope_unrequired)
          local r = proxy_client:get('/request', {headers = {['Host'] = host, ['Authorization'] = 'bearer ' .. token}})
          assert.response(r).has.status(403)
        end)
      end)
    end

    describe('when jwt access token valid but jwt_introspection=true', function()
      it('use introspection response', function()
        local token = fetch_token(true)
        local r = proxy_client:get('/request',
                                   {headers = {['Host'] = 'oauth2-jwt-introspect.com', ['Authorization'] = 'bearer ' .. token}})
        assert.response(r).has.status(200)
        ngx.sleep(0.001) -- exhaust the cache

        revoke(true, token)
        r = proxy_client:get('/request',
                             {headers = {['Host'] = 'oauth2-jwt-introspect.com', ['Authorization'] = 'bearer ' .. token}})
        assert.response(r).has.status(401)
      end)
    end)

  end)
end
