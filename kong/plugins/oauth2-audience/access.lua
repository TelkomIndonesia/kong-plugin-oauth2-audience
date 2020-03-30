local plugin_name = ({...})[1]:match('^kong%.plugins%.([^%.]+)')

local ngx = require 'ngx'
-- WARN: workaround for https://github.com/Kong/kong/issues/5549.
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
local oidc = require 'resty.openidc'
local kong_constants = require "kong.constants"
local error = require('kong.plugins.' .. plugin_name .. '.error')

-- redeclaration
local errcode = error.code
local get_req_header = kong.request.get_header
local get_req_query = kong.request.get_query
local get_req_method = kong.request.get_method
local get_req_body = kong.request.get_body
local set_req_header = kong.service.request.set_header
local set_req_headers = kong.service.request.set_headers
local set_req_query = kong.service.request.set_query
local set_req_body = kong.service.request.set_body
local clear_req_header = kong.service.request.clear_header
local log = kong.log
local load_consumer = kong.client.load_consumer

-- const
local OIDC_CONFIG_PATH = '.well-known/openid-configuration'
local ACCESS_TOKEN = 'access_token'
local TAB_EMPTY = {}
local TAB_ADDR_IDX = string.find(tostring(TAB_EMPTY), ' ') + 1

local function get_access_token_from_header(conf)
  local value = get_req_header(conf.auth_header_name)
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
  local token = get_req_query()[ACCESS_TOKEN]
  if type(token) == 'string' then
    return token
  end

  -- from body
  local method = get_req_method()
  if method ~= 'POST' and method ~= 'PUT' and method ~= 'PATCH' then
    return
  end
  token = get_req_body()[ACCESS_TOKEN]
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

local conf_cache_key_prefixes = setmetatable({}, {__mode = 'k'})

local function get_cache_key(conf, kind, key)
  local pref = conf_cache_key_prefixes[conf]
  if not pref then
    local random = string.sub(tostring({}), TAB_ADDR_IDX) -- for hopefully-sufficient randomness
    pref = plugin_name .. string.sub(tostring(conf), TAB_ADDR_IDX) .. random
    conf_cache_key_prefixes[conf] = pref
  end
  return string.format("%s:%s:%s", pref, kind or '', key or '')
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
    local desc = 'failed to fetch oidc configuration: ' .. (type(err) == 'string' and err or 'unexpected error')
    err = error.new(errcode.INTERNAL_SERVER_ERROR, desc)
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
    local desc = 'failed to introspect token: ' .. (type(err) == 'string' and err or 'unexpected error')
    return error.new(errcode.INTERNAL_SERVER_ERROR, desc)
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
  local discovery, err = get_oidc_conf(conf)
  if err then
    log.err(err.desc)
  end
  local opts = {
    discovery = discovery, -- avoid resty.openidc discovery cache
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

  local token_md
  token_md, err = oidc.jwt_verify(access_token, opts)
  local invalid_jwt = err and err:find('invalid jwt', 1, true) == 1
  local need_introspect_jwt = conf.jwt_introspection and (not conf.oidc_conf_discovery or not err) -- assume config error when oidc_conf_discovery is false
  if not (invalid_jwt or need_introspect_jwt) then
    local desc = err and 'failed to verify jwt: ' .. (type(err) == 'string' and err or 'unexpected error') -- err could be nil
    return token_md, err and error.new(errcode.INVALID_TOKEN, desc)
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
    err = error.new(errcode.INTERNAL_SERVER_ERROR, 'failed to load credential: ' .. err)
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

local function is_sufficient_scope(conf, token_metadata)
  local scope = {}
  if type(token_metadata.scope) == 'string' then
    for v in token_metadata.scope:gmatch('%S+') do
      scope[v] = true
    end
  elseif type(token_metadata.scp) == 'table' then
    -- for idp that implement the old https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-06
    for _, v in ipairs(token_metadata.scp) do
      scope[v] = true
    end
  end

  for _, v in ipairs(conf.required_scope) do
    if not scope[v] then
      return false
    end
  end
  return scope
end

local function is_required_audiences_present(conf, token_metadata)
  local auds = {}
  if type(token_metadata.aud) == 'string' then
    auds[token_metadata.aud] = true
  elseif type(token_metadata.aud) == 'table' then
    for _, v in ipairs(token_metadata.aud) do
      auds[v] = true
    end
  end

  for _, v in ipairs(conf.required_audiences) do
    if not auds[v] then
      return false
    end
  end
  return auds
end

local function get_consumer(credential)
  local key = kong.db.consumers:cache_key(credential.consumer.id)
  local cons, err = kong.cache:get(key, nil, load_consumer, credential.consumer.id)
  if err then
    err = error.new(errcode.INTERNAL_SERVER_ERROR, 'failed to load consumer: ' .. err)
  end
  return cons, err
end

local function set_upstream_headers(conf, consumer, credential, token_metadata)
  local header_consumer_id = conf.auth_headers_name.consumer_id
  local header_consumer_custom_id = conf.auth_headers_name.consumer_custom_id
  local header_consumer_username = conf.auth_headers_name.consumer_username
  local header_credential_id = conf.auth_headers_name.credential_id
  local header_anonymous = conf.auth_headers_name.anonymous

  if header_consumer_id ~= ":" then
    if consumer and consumer.id then
      set_req_header(header_consumer_id, consumer.id)
    else
      clear_req_header(header_consumer_id)
    end
  end

  if header_consumer_custom_id ~= ":" then
    if consumer and consumer.custom_id then
      set_req_header(header_consumer_custom_id, consumer.custom_id)
    else
      clear_req_header(header_consumer_custom_id)
    end
  end

  if header_consumer_username ~= ":" then
    if consumer and consumer.username then
      set_req_header(header_consumer_username, consumer.username)
    else
      clear_req_header(header_consumer_username)
    end
  end

  if header_credential_id ~= ":" then
    if credential and credential.audience then
      set_req_header(header_credential_id, credential.audience)
    else
      clear_req_header(header_credential_id)
    end
  end

  if header_anonymous ~= ":" then
    if not credential then
      set_req_header(header_anonymous, true)
    else
      clear_req_header(header_anonymous)
    end
  end

  for n, h in pairs(conf.claim_header_map) do
    local v = token_metadata and token_metadata[n]
    if v then
      set_req_headers({[h] = v})
    else
      clear_req_header(h)
    end
  end
end

local function hide_credentials(header_name)
  -- hide in header
  if header_name then
    return clear_req_header(header_name)
  end

  -- hide in url if present
  local query = get_req_query()
  if query and query[ACCESS_TOKEN] ~= nil then
    query[ACCESS_TOKEN] = nil
    set_req_query(query)
  end

  -- hide in body if present
  if get_req_method() == 'GET' then
    return
  end
  local content_type = get_req_header('content-type')
  local is_form_post = content_type and content_type:find('application/x-www-form-urlencoded', 1, true)
  if not is_form_post then
    return
  end
  local body = get_req_body()
  if body and body[ACCESS_TOKEN] ~= nil then
    body[ACCESS_TOKEN] = nil
    set_req_body(body)
  end
end

local function authenticate(conf)
  local token, auth_header_name = get_access_token(conf)
  if not token or token == '' then
    return error.new(errcode.MISSING_AUTHENTICATION, '')
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
  local auds = is_required_audiences_present(conf, token_metadata)
  if not auds then
    return error.new(errcode.INSUFFICIENT_SCOPE, 'missing one or more required audiences')
  end

  local cred
  cred, err = get_credential(conf, token_metadata)
  err = err or validate_credential(token_metadata, cred)
  if err then
    return err
  end
  cred.scope = scope
  cred.audiences = auds

  local cons
  cons, err = get_consumer(cred)
  if not cons then
    return err and err or error.new(errcode.INTERNAL_SERVER_ERROR, 'failed to load anonymous consumer: not found')
  end

  kong.client.authenticate(cons, cred)
  set_upstream_headers(conf, cons, cred, token_metadata)
  if conf.hide_credentials then
    hide_credentials(auth_header_name)
  end
end

local function authenticate_as_anonymous(conf)
  local consumer_cache_key = kong.db.consumers:cache_key(conf.anonymous)
  local consumer, err = kong.cache:get(consumer_cache_key, nil, load_consumer, conf.anonymous, true)
  if not consumer or err then
    return error.new(errcode.INTERNAL_SERVER_ERROR, 'failed to load anonymous consumer: ' .. (err or 'not found'))
  end

  kong.client.authenticate(consumer)
  set_upstream_headers(conf, consumer)
end

local _M = {}

function _M.execute(conf)
  if conf.anonymous and kong.client.get_credential() then
    return
  end

  local err = authenticate(conf)
  if err and conf.anonymous then
    err = authenticate_as_anonymous(conf)
  end
  if err then
    return kong.response.exit(err:to_status_code(), err:to_body(), {['WWW-Authenticate'] = err:to_www_authenticate('service')})
  end
end

return _M
