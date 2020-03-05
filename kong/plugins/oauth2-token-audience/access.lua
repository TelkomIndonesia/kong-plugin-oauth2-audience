local ngx = require('ngx')
local oidc = require('resty.openidc')

local _EMPTY = {}
local OIDC_CONFIG_PATH = '/.well-known/openid-configuration'
local ACCESS_TOKEN = 'access_token'
local ACCESS_TOKEN_MISSING = {status = 400, headers = {['WWW-Authenticate'] = 'Bearer realm="service"'}}
local ACCESS_TOKEN_INVALID = {
  status = 401,
  body = {error = 'invalid_token', error_description = 'The access token is invalid or has expired'},
  headers = {
    ['WWW-Authenticate'] = 'Bearer realm="service" ' .. 'error="invalid_token" ' ..
      'error_description="The access token is invalid or has expired"'
  }
}

local CREDENTIAL_INVALID = {
  status = 401,
  body = {error = 'invalid_token', error_description = 'Invalid audience, issuer, or client_id'},
  headers = {
    ['WWW-Authenticate'] = 'Bearer realm="service" ' .. 'error="invalid_token" ' ..
      'error_description="Invalid audience, issuer, or client_id"'
  }
}

local INSUFFICIENT_SCOPE = {
  status = 403,
  body = {error = 'insufficient_scope', error_description = 'Missing required audience or scope'},
  headers = {
    ['WWW-Authenticate'] = 'Bearer realm="service" ' .. 'error="insufficient_scope" ' ..
      'error_description="Missing required audience or scope"'
  }
}
local INTERNAL_SERVER_ERROR = {status = 500, body = {message = 'An unexpected error occurred'}, headers = {}}

local function get_access_token_from_header(conf)
  local value = kong.request.get_header(conf.auth_header_name)
  if not value then
    return
  end

  local parts = {}
  for v in value:gmatch('%S+') do
    table.insert(parts, v)
  end
  if #parts == 2 and (parts[1]:lower() == 'token' or parts[1]:lower() == 'bearer') then
    return parts[2]
  end
end

local function get_access_token_from_parameters()
  -- from url
  local token = kong.request.get_query()[ACCESS_TOKEN]
  if type(token) == 'string' then
    return token
  end

  -- from body
  local method = kong.request.get_method()
  if method ~= 'POST' and method ~= 'PUT' and method ~= 'PATCH' then
    return
  end
  token = kong.request.get_body()[ACCESS_TOKEN]
  return type(token) == 'string' and token
end

local function get_access_token(conf)
  local access_token = get_access_token_from_header(conf)
  if access_token then
    return access_token, conf.auth_header_name
  end

  access_token = get_access_token_from_parameters()
  return access_token
end

local function oidc_conf_cache_key(issuer)
  local prefix = 'oauth2_token_audience:oidc_conf:'
  if not issuer then
    return prefix
  end
  return prefix .. (issuer and issuer or '')
end

local function fetch_oidc_conf(conf)
  if not conf.issuer or conf.issuer == '' then
    return nil, 'no issuer specified'
  end

  local url = conf.issuer .. (conf.issuer:sub(-1) == '/' and '' or '/') .. OIDC_CONFIG_PATH
  local doc, err = oidc.get_discovery_doc({discovery = url, ssl_verify = conf.ssl_verify or 'no'})

  -- try our best to populate doc from conf so that resty.openidc do not try discovery again
  if err then
    doc = {issuer = conf.issuer}
  end

  return doc
end

local function introspect_cache_key(access_token)
  local prefix = 'oauth2_token_audience:access_token:'
  if not access_token then
    return prefix
  end
  return prefix .. access_token
end

-- based on:
-- https://github.com/zmartzone/lua-resty-openidc/blob/v1.7.2/lib/resty/openidc.lua#L1568
-- but without access_token parsing
local function introspect(opts, access_token)
  local token_param_name = opts.introspection_token_param_name or 'token'
  local body = {}
  body[token_param_name] = access_token
  body.client_id = opts.client_id
  body.client_secret = opts.client_secret
  for key, val in pairs(opts.introspection_params or _EMPTY) do
    body[key] = val
  end

  local discovery = opts.discovery or _EMPTY
  local introspection_endpoint = opts.introspection_endpoint or discovery.introspection_endpoint
  local json, err = oidc.call_token_endpoint(opts, introspection_endpoint, body, opts.introspection_endpoint_auth_method,
                                             'introspection')
  local ttl = opts.introspection_interval or 0
  if json and json.exp and (ttl < 0 or json.exp - ngx.time() < ttl) then
    ttl = json.exp - ngx.time()
  end
  return json, err, ttl
end

local function inquire(conf, access_token)
  local opts = {
    discovery = kong.cache:get(oidc_conf_cache_key(conf.issuer), nil, fetch_oidc_conf, conf),
    ssl_verify = conf.ssl_verify or 'no',
    -- jwt specific
    symmetric_key = conf.jwt_signature_secret,
    public_key = conf.jwt_signature_public_key,
    token_signing_alg_values_expected = conf.jwt_introspection,
    accept_none_alg = false,
    accept_unsupported_alg = false,
    -- introspection specific
    introspection_endpoint = conf.introspection_endpoint,
    client_id = conf.introspection_client_id,
    client_secret = conf.introspection_client_secret,
    client_rsa_private_key = conf.introspection_client_rsa_private_key,
    client_rsa_private_key_id = conf.introspection_client_rsa_private_key_id,
    introspection_endpoint_auth_method = conf.introspection_auth_method,
    introspection_token_param_name = conf.introspection_param_name_token,
    introspection_params = conf.introspection_params,
    introspection_expiry_claim = conf.introspection_claim_expiry,
    introspection_interval = conf.introspection_cache_max_ttl,
    introspection_cache_ignore = true -- do not use resty.openidc caching mechanism
  }

  local json, err = oidc.jwt_verify(access_token, opts)
  if (err and err:find('invalid jwt', 1, true) == 1) or (not err and conf.jwt_introspection) then
    return kong.cache:get(introspect_cache_key(access_token), nil, introspect, opts, access_token)
  end

  return json, err
end

local function load_credential(audience, issuer, client_id)
  local credential, err = kong.db.oauth2_token_audiences:select_by_audience(audience)
  if not credential then
    return nil, 'audience not found'
  end
  if err then
    return nil, err
  end
  if issuer ~= credential.issuer then
    return nil, 'invalid issuer'
  end
  if client_id ~= credential.client_id then
    return nil, 'invalid client_id'
  end
  return credential
end

local function get_credential(conf, access_token_info)
  if type(access_token_info) ~= 'table' then
    return nil, ACCESS_TOKEN_INVALID
  end
  local issuer = access_token_info.iss
  local client_id = access_token_info.client_id

  local auds = access_token_info.aud
  if type(auds) == 'string' then
    auds = {auds}
  end
  local audience = ''
  for _, v in ipairs(auds or _EMPTY) do
    local b, e = v:find(conf.audience_prefix or '', 1, true)
    if b == 1 then
      audience = v:sub(e + 1)
      break
    end
  end

  if audience == '' then
    return nil, 'invalid audience'
  end

  local key = kong.db.oauth2_token_audiences:cache_key(audience)
  local credential, err = kong.cache:get(key, nil, load_credential, audience, issuer, client_id)
  return credential, err
end

local function is_sufficient_scope(conf, access_token_info)
  local scope = {}
  for v in access_token_info.scope:gmatch('%S+') do
    scope[v] = true
  end
  for _, v in ipairs(conf.required_scope) do
    if scope[v] ~= true then
      return false
    end
  end
  return true
end

local function get_consumer(credential)
  local key = kong.db.consumers:cache_key(credential.consumer.id)
  return kong.cache:get(key, nil, kong.client.load_consumer, credential.consumer.id)
end

local function hide_credentials(header_name)
  -- hide in header
  if header_name then
    return kong.service.request.clear_header(header_name)
  end

  -- hide in url
  local query = kong.request.get_query()
  query[ACCESS_TOKEN] = nil
  kong.service.request.set_query(query)

  -- hide in body if present
  if kong.request.get_method() == 'GET' then
    return
  end
  local content_type = kong.request.get_header('content-type')
  local is_form_post = content_type and content_type:find('application/x-www-form-urlencoded', 1, true)
  if not is_form_post then
    return
  end
  local body = kong.request.get_body()
  if not body or body[ACCESS_TOKEN] == nil then
    return
  end
  body[ACCESS_TOKEN] = nil
  kong.service.request.set_body(body)
end

local function authenticate(conf)
  local token, auth_header_name = get_access_token(conf)
  if not token or token == '' then
    return ACCESS_TOKEN_MISSING
  end

  local token_info, err = inquire(conf, token)
  if err ~= nil then
    kong.log.err(err)
    return ACCESS_TOKEN_INVALID
  end
  if conf.issuer ~= token_info.iss then
    kong.log.err('invalid issuer: ', token_info.iss, '. expected: ', conf.issuer)
    return ACCESS_TOKEN_INVALID
  end
  if not is_sufficient_scope(conf, token_info) then
    return INSUFFICIENT_SCOPE
  end

  local cred
  cred, err = get_credential(conf, token_info)
  if err ~= nil then
    kong.log.err(err)
    return CREDENTIAL_INVALID
  end

  local cons
  cons, err = get_consumer(cred)
  if err ~= nil then
    kong.log.err(err)
    return INTERNAL_SERVER_ERROR
  end

  kong.client.authenticate(cons, cred)

  if conf.hide_credentials then
    hide_credentials(auth_header_name)
  end
end

local function authenticate_as_anonymous(conf)
  local consumer_cache_key = kong.db.consumers:cache_key(conf.anonymous)
  local consumer, err = kong.cache:get(consumer_cache_key, nil, kong.client.load_consumer, conf.anonymous, true)
  if err then
    return INTERNAL_SERVER_ERROR
  end

  kong.client.authenticate(consumer)
end

local _M = {}

function _M.execute(conf)
  if conf.anonymous and kong.client.get_credential() then
    return
  end

  local err = authenticate(conf)
  if err == nil then
    return
  end
  if not conf.anonymous then
    return kong.response.exit(err.status, err.body, err.headers)
  end

  err = authenticate_as_anonymous(conf)
  if err ~= nil then
    return kong.response.exit(err.status, err.body, err.headers)
  end
end

return _M
