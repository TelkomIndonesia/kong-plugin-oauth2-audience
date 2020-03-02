local kong = kong -- minimize warning

local ACCESS_TOKEN = 'access_token'
local access_token_missing = {error = 'invalid_request', error_description = 'The access token is missing'}

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
        return access_token, true
    end

    access_token = get_access_token_from_parameters()
    return access_token, false
end

local _M = {}

function _M.execute(conf)
    if conf.anonymous and kong.client.get_credential() then
        return
    end

    local access_token, access_token_in_header = get_access_token(conf)
    if not access_token or access_token == '' then
        return kong.response.exit(401, access_token_missing, {['WWW-Authenticate'] = 'Bearer realm="service"'})
    end

    -- TODO: get audience, then get credential

    if conf.hide_credentials then
        hide_credentials(access_token_in_header and conf.auth_header_name)
    end
end

return _M
