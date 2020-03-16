local typedefs = require 'kong.db.schema.typedefs'
local plugin_name = ({...})[1]:match('^kong%.plugins%.([^%.]+)')

local auth_method = {'client_secret_basic', 'client_secret_post', 'private_key_jwt', 'client_secret_jwt'}
local sign_algorithm = {'HS256', 'HS512', 'RS256'}
local claim_header_map = {iss = 'x-oauth2-issuer', client_id = 'x-oauth2-client', sub = 'x-oauth2-subject'}

return {
  name = plugin_name,
  fields = {
    {consumer = typedefs.no_consumer},
    {protocols = typedefs.protocols_http},
    {
      config = {
        type = 'record',
        fields = {
          {hide_credentials = {type = 'boolean', default = false}},
          {anonymous = {type = 'string', uuid = true, legacy = true}},
          {run_on_preflight = {type = 'boolean', default = true}},
          {auth_header_name = {type = 'string', default = 'authorization'}},

          {ssl_verify = {type = 'boolean', default = true}},

          {issuer = typedefs.url({required = true})},
          {oidc_conf_discovery = {type = 'boolean', default = true}},
          {required_scope = {type = 'array', elements = {type = 'string'}, default = {}}},
          {required_audiences = {type = 'array', elements = {type = 'string'}, default = {}}},
          {audience_prefix = {type = 'string'}},

          {jwt_signature_secret = {type = 'string'}},
          {jwt_signature_public_key = typedefs.certificate},
          {
            jwt_signature_algorithm = {
              type = 'array',
              elements = {type = 'string', one_of = sign_algorithm},
              default = sign_algorithm
            }
          },
          {jwt_introspection = {type = 'boolean', default = false}},

          {introspection_endpoint = typedefs.url},
          {introspection_auth_method = {type = 'string', default = auth_method[1], one_of = auth_method}},
          {introspection_client_id = {type = 'string'}},
          {introspection_client_secret = {type = 'string'}},
          {introspection_client_rsa_private_key = typedefs.certificate},
          {introspection_auth_method = {type = 'string', default = auth_method[1], one_of = auth_method}},
          {introspection_client_rsa_private_key_id = {type = 'string'}},
          {introspection_param_name_token = {type = 'string', default = 'token'}},
          {introspection_params = {type = 'map', keys = {type = 'string'}, values = {type = 'string'}}},
          {introspection_claim_expiry = {type = 'string', default = 'exp'}},
          {introspection_cache_max_ttl = {type = 'number', default = 900}},

          {
            claim_header_map = {
              type = 'map',
              keys = {type = 'string'},
              values = typedefs.header_name,
              default = claim_header_map
            }
          }
        }
      }
    }
  }
}
