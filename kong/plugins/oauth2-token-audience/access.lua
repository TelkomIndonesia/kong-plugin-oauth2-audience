local kong = kong -- minimize warning
local oidc = require('resty.openidc')

local OIDC_CONFIG_PATH = '/.well-known/openid-configuration'
local ACCESS_TOKEN = 'access_token'
local ACCESS_TOKEN_MISSING = {
    status = 401,
    message = {error = 'invalid_request', error_description = 'The access token is missing'},
    headers = {['WWW-Authenticate'] = 'Bearer realm="service"'}
}
local ACCESS_TOKEN_INVALID = {
    status = 401,
    message = {error = 'invalid_token', error_description = 'The access token is invalid or has expired'},
    headers = {
        ['WWW-Authenticate'] = 'Bearer realm="service" ' ..
            'error="invalid_token" ' .. 'error_description="The access token is invalid or has expired"'
    }
}

local function get_access_token_from_header(conf)
    local value = kong.request.get_header(conf.auth_header_name)
    if not value then
        return
    end

    local parts = {}
    for v in value:gmatch('%S+') do
        table.insert(parts, v)
    end
    if #parts ~= 2 and (parts[1]:lower() == 'token' or parts[1]:lower() == 'bearer') then
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

local function hide_credentials(header_name)
    -- hide in header
    if header_name then
        return kong.service.request.clear_header(header_name)
    end

    -- hide in url
    local parameters = kong.request.get_query()
    parameters[ACCESS_TOKEN] = nil
    kong.service.request.set_query(parameters)

    -- hide in body if present
    if kong.request.get_method() == 'GET' then
        return
    end
    local content_type = kong.request.get_header('content-type')
    local is_form_post = content_type and content_type:find('application/x-www-form-urlencoded', 1, true)
    if not is_form_post then
        return
    end
    parameters = kong.request.get_body() or {}
    parameters[ACCESS_TOKEN] = nil
    kong.service.request.set_body(parameters)
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
    if not conf.issuer or conf.issuer == '' then
        return
    end

    -- TODO: cache lookuo
    local url = conf.issuer:sub(-1) == '/' and conf.issuer .. '/' .. OIDC_CONFIG_PATH or conf.issuer .. OIDC_CONFIG_PATH
    local doc, err = openidc.get_discovery_doc({discovery = url})
    -- TODO: cache doc if success for future use

    -- try our best to populate doc from conf so that resty.openidc do not try discovery again
    if err then
        doc = {
            issuer = conf.issuer
        }
    end

    return doc
end

-- based on:
-- https://github.com/zmartzone/lua-resty-openidc/blob/v1.7.2/lib/resty/openidc.lua#L1568
-- but without access_token parsing
local function instrospect(access_token, opts)
    -- TODO: cache lookuo
    local token_param_name = opts.introspection_token_param_name or 'token'
    local body = {}
    body[token_param_name] = access_token
    body.client_id = opts.client_id or body.client_id
    body.client_secret = opts.client_secret or body.client_secret
    for key, val in pairs(opts.introspection_params) do
        body[key] = val
    end

    local discovery = opts.discovery or {}
    local introspection_endpoint = opts.introspection_endpoint or discovery.introspection_endpoint
    local json, err =
        openidc.call_token_endpoint(
        opts,
        introspection_endpoint,
        body,
        opts.introspection_endpoint_auth_method,
        'introspection'
    )
    -- TODO: cache
    return json, err
end

local function inquire(access_token, conf)
    local opts = {
        discovery = get_oidc_conf(conf),
        ssl_verify = conf.ssl_verify,
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
        introspection_expiry_claim = conf.introspection_claim_expiry
    }

    local json, err = oidc.jwt_verify(access_token, opts)
    if err ~= nil and err:find('invalid jwt', 1, true) == 1 then
        return instrospect(access_token, opts)
    end
    if err == nil and conf.jwt_introspection then
        return instrospect(access_token, opts)
    end
    return json, err
end

local function authenticate(conf)
    local token, auth_header_name = get_access_token(conf)
    if not token or token == '' then
        return ACCESS_TOKEN_MISSING
    end

    local token_info, err = inquire(token, conf)
    if err ~= nil then
        return ACCESS_TOKEN_INVALID
    end
    -- TODO: get credential

    if conf.hide_credentials then
        hide_credentials(auth_header_name)
    end
end

local function authenticate_as_anonymous(conf)
    local consumer_cache_key = kong.db.consumers:cache_key(conf.anonymous)
    local consumer, err = kong.cache:get(consumer_cache_key, nil, kong.client.load_consumer, conf.anonymous, true)
    if err then
        kong.log.err('failed to load anonymous consumer:', err)
        return kong.response.exit(500, {message = 'An unexpected error occurred'})
    end

    kong.client.authenticate(consumer)
end

local _M = {}

function _M.execute(conf)
    if conf.anonymous and kong.client.get_credential() then
        return
    end

    local err = authenticate(conf)
    if err ~= nil and not conf.anonymous then
        return kong.response.exit(err.status, err.message, err.headers)
    end
    if conf.anonymous then
        return authenticate_as_anonymous(conf)
    end
end

return _M
