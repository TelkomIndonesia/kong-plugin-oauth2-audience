local os = require 'os'
local http = require 'resty.http'
local ngx = require 'ngx'
local cjson = require 'cjson'

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

local _M = {}

_M.env = env

function _M.get_plugin_config(is_jwt, replace)
  return merge({
    required_scope = split(env.oauth2_client_scope, ' '),
    required_audiences = {env.oauth2_client_audience_existing},
    issuer = is_jwt and env.idp_jwt_issuer or env.idp_opaque_issuer,
    introspection_endpoint = is_jwt and env.idp_jwt_introspection_endpoint or env.idp_opaque_introspection_endpoint,
    introspection_client_id = env.oauth2_client_id,
    introspection_client_secret = env.oauth2_client_secret,
    ssl_verify = false
  }, replace)
end

function _M.get_audience_credential(is_jwt, replace)
  return merge({
    audience = is_jwt and env.oauth2_jwt_client_audience or env.oauth2_client_audience,
    issuer = is_jwt and env.idp_jwt_issuer or env.idp_opaque_issuer,
    client_id = env.oauth2_client_id
  }, replace)
end

function _M.fetch_token(is_jwt, audience, scope)
  local id = env.oauth2_client_id
  local secret = env.oauth2_client_secret
  audience = audience or (is_jwt and env.oauth2_jwt_client_audience or env.oauth2_client_audience)
  audience = type(audience) == 'string' and {audience, env.oauth2_client_audience_existing} or audience

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
  assert(not err)
  local j = cjson.decode(res.body)
  return assert(j.access_token)
end

function _M.revoke(is_jwt, token)
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
  return assert(not err)
end

return _M
