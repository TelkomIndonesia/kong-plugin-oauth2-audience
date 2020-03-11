local ngx = require('ngx')
-- workaround for https://github.com/Kong/kong/issues/5549.
if kong.version_num >= 2000000 and kong.version_num <= 2000002 then
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
end
local oidc = require('resty.openidc')

local plugin_name = ({...})[1]:match('^kong%.plugins%.([^%.]+)')
local error = require('kong.plugins.' .. plugin_name .. '.error')
local errcode = error.code

-- const
local OIDC_CONFIG_PATH = '.well-known/openid-configuration'
local ACCESS_TOKEN = 'access_token'
local TAB_EMPTY = {}
local TAB_ADDR_IDX = string.find(tostring(TAB_EMPTY), ' ') + 1

local conf_cache_key_prefixes = setmetatable({}, {__mode = 'k'})
local function get_cache_key(conf, kind, key)
  local pref = conf_cache_key_prefixes[conf]
  if not pref then
    local random = string.sub(tostring({}), TAB_ADDR_IDX) -- for hopefully-sufficient randomness
    pref = plugin_name .. string.sub(tostring(conf), TAB_ADDR_IDX) .. random
    conf_cache_key_prefixes[conf] = pref
    kong.log.debug("done constructing cache_key_prefix")
  end
  return string.format("%s:%s:%s", pref, kind or '', key or '')
end

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

local function get_oidc_conf(conf)
  if not conf.issuer or conf.issuer == '' or not conf.oidc_conf_discovery then
    return nil
  end
  local url = conf.issuer .. (conf.issuer:sub(-1) == '/' and '' or '/') .. OIDC_CONFIG_PATH
  local opts = {discovery = url, ssl_verify = conf.ssl_verify or 'no'}
  local key = get_cache_key(conf, 'issuer', conf.issuer)
  local doc, err = kong.cache:get(key, nil, oidc.get_discovery_doc, opts)
  if err then
    err = error.new(errcode.INTERNAL_SERVER_ERROR, err or 'cannot fetch oidc configuration')
  end
  return doc, err
end

-- based on:
-- https://github.com/zmartzone/lua-resty-openidc/blob/v1.7.2/lib/resty/openidc.lua#L1568
-- but without access_token parsing and expiry validation
local function load_token_metadata(opts, access_token)
  local token_param_name = opts.introspection_token_param_name or 'token'
  local body = {}
  body[token_param_name] = access_token
  body.client_id = opts.client_id
  body.client_secret = opts.client_secret
  for key, val in pairs(opts.introspection_params or TAB_EMPTY) do
    body[key] = val
  end

  local discovery = opts.discovery or TAB_EMPTY
  local endpoint = opts.introspection_endpoint or discovery.introspection_endpoint
  local json, err = oidc.call_token_endpoint(opts, endpoint, body, opts.introspection_endpoint_auth_method, 'introspection')
  if err then
    err = error.new(errcode.INTERNAL_SERVER_ERROR, err)
  end
  if not json or not json.active then
    return nil
  end

  local introspection_interval = opts.introspection_interval or 0
  local exp = json[opts.introspection_expiry_claim or "exp"]
  if type(exp) ~= 'number' then
    return json, nil, introspection_interval or 60
  end
  local ttl = exp - ngx.time()
  if introspection_interval > 0 and introspection_interval < ttl then
    ttl = introspection_interval
  end
  return json, nil, ttl
end

local function inquire(conf, access_token)
  local opts = {
    discovery = get_oidc_conf(conf), -- avoid resty.openidc discovery cache
    ssl_verify = conf.ssl_verify or 'no',
    -- jwt specific
    symmetric_key = conf.jwt_signature_secret,
    public_key = conf.jwt_signature_public_key,
    token_signing_alg_values_expected = conf.jwt_signature_algorithm,
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

  local token_md, err = oidc.jwt_verify(access_token, opts)
  local invalid_jwt = err and err:find('invalid jwt', 1, true) == 1
  local need_introspect_jwt = (not err and conf.jwt_introspection)
  if not (invalid_jwt or need_introspect_jwt) then
    return token_md, err and error.new(errcode.INVALID_TOKEN, err) or err
  end

  local key = get_cache_key(conf, 'access_token', access_token)
  token_md, err = kong.cache:get(key, nil, load_token_metadata, opts, access_token)
  if err then
    return nil, err
  end
  local exp = token_md and token_md[opts.introspection_expiry_claim or "exp"] or 0
  if exp - ngx.time() <= 0 then
    err = error.new(errcode.INVALID_TOKEN, 'invalid or expired access token')
  end

  return token_md, err
end

local function load_credential(audience)
  local credential, err = kong.db.oauth2_audiences:select_by_audience(audience)
  if err then
    err = error.new(errcode.INTERNAL_SERVER_ERROR, err)
  end
  return credential, err
end

local function get_credential(conf, token_metadata)
  if type(token_metadata) ~= 'table' then
    return nil, error.new(errcode.INVALID_TOKEN, 'invalid access token metadata')
  end

  local audience = ''
  local auds = token_metadata.aud
  if type(auds) == 'string' then
    auds = {auds}
  end
  for _, v in ipairs(auds or TAB_EMPTY) do
    local b, e = v:find(conf.audience_prefix or '', 1, true)
    if b == 1 then
      audience = v:sub(e + 1)
      break
    end
  end
  if audience == '' then
    return nil, error.new(errcode.INVALID_TOKEN, 'missing suitable audience in access token metadata')
  end

  local key = kong.db.oauth2_audiences:cache_key(audience)
  local credential, err = kong.cache:get(key, nil, load_credential, audience)
  return credential, err
end

local function validate_credential(token_metadata, credential)
  if not credential then
    return error.new(errcode.INVALID_TOKEN, 'invalid audience')
  end
  if token_metadata.client_id ~= credential.client_id then
    return error.new(errcode.INVALID_TOKEN, 'invalid client_id for the given audience')
  end
  if token_metadata.iss ~= credential.issuer then
    return error.new(errcode.INVALID_TOKEN, 'invalid issuer for the given audience')
  end
end

local conf_required_scope_maps = setmetatable({}, {__mode = 'k'})
local function is_sufficient_scope(conf, token_metadata)
  local scope_map = conf_required_scope_maps[conf]
  if not scope_map then
    scope_map = {}
    for _, v in ipairs(conf.required_scope or TAB_EMPTY) do
      scope_map[v] = true
    end
    conf_required_scope_maps[conf] = scope_map
    kong.log.debug("done constructing required_scope_map")
  end

  local scope
  local found = 0
  if type(token_metadata.scope) == 'string' then
    scope = {}
    for v in token_metadata.scope:gmatch('%S+') do
      table.insert(scope, v)
      found = found + (scope_map[v] and 1 or 0)
    end
  elseif type(token_metadata.scp) == 'table' then
    scope = token_metadata.scp
    for _, v in ipairs(scope) do
      found = found + (scope_map[v] and 1 or 0)
    end
  end

  return found == #conf.required_scope and scope or nil
end

local function get_consumer(credential)
  local key = kong.db.consumers:cache_key(credential.consumer.id)
  local cons, err = kong.cache:get(key, nil, kong.client.load_consumer, credential.consumer.id)
  if err then
    err = error.new(errcode.INTERNAL_SERVER_ERROR, err)
  end
  return cons, err
end

local function hide_credentials(header_name)
  -- hide in header
  if header_name then
    return kong.service.request.clear_header(header_name)
  end

  -- hide in url if present
  local query = kong.request.get_query()
  if query and query[ACCESS_TOKEN] ~= nil then
    query[ACCESS_TOKEN] = nil
    kong.service.request.set_query(query)
  end

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
  if body and body[ACCESS_TOKEN] ~= nil then
    body[ACCESS_TOKEN] = nil
    kong.service.request.set_body(body)
  end
end

local function authenticate(conf)
  local token, auth_header_name = get_access_token(conf)
  if not token or token == '' then
    return error.new(errcode.MISSING_AUTHENTICATION)
  end

  local token_metadata, err = inquire(conf, token)
  if err then
    return err
  end
  if conf.issuer ~= token_metadata.iss then
    return error.new(errcode.INVALID_TOKEN, 'invalid issuer')
  end
  local scope = is_sufficient_scope(conf, token_metadata)
  if not scope then
    return error.new(errcode.INSUFFICIENT_SCOPE, 'missing one or more required scope')
  end

  local cred
  cred, err = get_credential(conf, token_metadata)
  if err then
    return err
  end
  err = validate_credential(token_metadata, cred)
  if err then
    return err
  end
  cred.scope = scope

  local cons
  cons, err = get_consumer(cred)
  if not cons then
    return err and err or error.new(errcode.INTERNAL_SERVER_ERROR, 'can not find consumer ')
  end

  kong.client.authenticate(cons, cred)

  if conf.hide_credentials then
    hide_credentials(auth_header_name)
  end
end

local function authenticate_as_anonymous(conf)
  local consumer_cache_key = kong.db.consumers:cache_key(conf.anonymous)
  local consumer, err = kong.cache:get(consumer_cache_key, nil, kong.client.load_consumer, conf.anonymous, true)
  if not consumer or err then
    return error.new(errcode.INTERNAL_SERVER_ERROR, err or 'can not find anonymous consumer')
  end

  kong.client.authenticate(consumer)
end

local _M = {}

function _M.execute(conf)
  if conf.anonymous and kong.client.get_credential() then
    return
  end

  local err = authenticate(conf)
  if not err then
    return
  end
  if not conf.anonymous then
    return kong.response.exit(err:to_status_code(), err:to_body(), {['WWW-Authenticate'] = err:to_www_authenticate('service')})
  end

  err = authenticate_as_anonymous(conf)
  if err then
    return kong.response.exit(err:to_status_code(), err:to_body(), {['WWW-Authenticate'] = err:to_www_authenticate('service')})
  end
end

return _M
