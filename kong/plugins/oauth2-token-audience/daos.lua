local typedefs = require 'kong.db.schema.typedefs'

return {
    oauth2_token_audiences = {
        name = 'oauth2_token_audiences',
        primary_key = {'id'},
        endpoint_key = 'aud',
        cache_key = {'aud'},
        generate_admin_api = true,
        admin_api_name = 'oauth2-auds',
        admin_api_nested_name = 'oauth2-aud',
        fields = {
            {id = typedefs.uuid},
            {created_at = typedefs.auto_timestamp_s},
            {consumer = {type = 'foreign', reference = 'consumers', required = true, on_delete = 'cascade'}},
            {tags = typedefs.tags},
            -- the ones that should be associated to the access token
            {aud = {type = 'string', required = false, unique = true, auto = true}},
            {iss = {type = 'string', required = true}},
            {client_id = {type = 'string', required = true}}
        }
    }
}
