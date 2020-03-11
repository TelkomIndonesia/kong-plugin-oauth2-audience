local code = {INTERNAL_SERVER_ERROR = 0, MISSING_AUTHENTICATION = 1, BAD_REQUEST = 2, INVALID_TOKEN = 3, INSUFFICIENT_SCOPE = 4}
local code_max = code.INSUFFICIENT_SCOPE -- for validation, update this accordingly

local function code_to_www_authenticate_error(c)
  if c == code.BAD_REQUEST then
    return 'bad_request'
  end
  if c == code.INVALID_TOKEN then
    return 'invalid_token'
  end
  if c == code.INSUFFICIENT_SCOPE then
    return 'insufficient_scope'
  end

  return ''
end

local internal_server_error_body = {message = 'An unexpected error occurred'}

local Error = {code = code.INTERNAL_SERVER_ERROR, description = "internal server error"}

function Error:new(o)
  o = o or {}
  setmetatable(o, self)
  self.__index = self

  if type(o.code) ~= 'number' or o.code < 0 or o.code > code_max then
    o.code = code.INTERNAL_SERVER_ERROR
  end

  return o
end

function Error:to_status_code()
  if self.code == code.BAD_REQUEST then
    return 400
  end
  if self.code == code.INVALID_TOKEN then
    return 401
  end
  if self.code == code.MISSING_AUTHENTICATION then
    return 401
  end
  if self.code == code.INSUFFICIENT_SCOPE then
    return 403
  end
  return 500
end

function Error:to_www_authenticate(realm)
  if self.code == code.INTERNAL_SERVER_ERROR or self.code == code.MISSING_AUTHENTICATION then
    return string.format('Bearer realm="%s"', realm:gsub('"', '\\"'))
  end

  local desc = self.description
  if not desc or type(desc) ~= 'string' then
    return string.format('Bearer realm="%s", error="%s"', realm:gsub('"', '\\"'), code_to_www_authenticate_error(self.code))
  end
  return string.format('Bearer realm="%s", error="%s", error_description="%s"', realm:gsub('"', '\\"'),
                       code_to_www_authenticate_error(self.code), desc:gsub('"', '\\"'))
end

function Error:to_body()
  if self.code == code.INTERNAL_SERVER_ERROR then
    return internal_server_error_body
  end

  if self.code == code.MISSING_AUTHENTICATION then
    return
  end

  return {error = code_to_www_authenticate_error(self.code), error_description = self.description}
end

local _M_ = {
  new = function(code, description)
    return Error:new({code = code, description = description})
  end,

  code = code
}
return _M_
