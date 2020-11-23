# Kong Plugin OAuth2 Audience

Validate access tokens from a third-party OAuth 2.0 Authorization Server (including OpenID Connect)
by leveraging JWT verification ([RFC 7519](https://tools.ietf.org/html/rfc7519)) and/or OAuth2 Introspection ([RFC 7662](https://tools.ietf.org/html/rfc7662))
and associate the external OAuth2 client with an existing Kong consumer based on the [audience parameter](https://tools.ietf.org/html/rfc7519#section-4.1.3).

Each consumer can have multiple audiences. At the same time, each registered audience can only be associated with a specific issuer (`iss` claim) and client id (`client_id` claim). This allow for complete control over the list of extenal OAuth2 Client that can be associated with the consumer.

## Installation

From Luarocks:

```bash
luarocks install kong-plugin-oauth2-audience
```

From source:

```bash
git clone https://github.com/TelkomIndonesia/kong-plugin-oauth2-audience
cd kong-plugin-oauth2-audience
luarocks make *.rockspec
```

## Configuration Reference

This plugin is compatible with requests with the following protocols:

- `http`
- `https`

This plugin is **partially** compatible with DB-less mode.

In DB-less mode, Kong does not have an Admin API. If using this mode, configure the plugin using declarative configuration.

Consumers and Credentials can be created with declarative configuration.

Admin API endpoints which do POST, PUT, PATCH or DELETE on Credentials are not available on DB-less mode.

### Enabling the plugin on a Service

For example, configure this plugin on a Service by making the following request:

```bash
$ curl -X POST http://<admin-hostname>:8001/services/<service>/plugins \
    --data "name=oauth2-audience"  \
    --data "config.issuer=https://issuer.tld"
```

`<service>` is the `id` or `name` of the Service that this plugin configuration will target.

### Enabling the plugin on a Route

For example, configure this plugin on a Route with:

```bash
$ curl -X POST http://<admin-hostname>:8001/routes/<route>/plugins \
    --data "name=oauth2-audience"  \
    --data "config.issuer=https://issuer.tld"
```

`<route>` is the `id` or `name` of the Route that this plugin configuration will target.

### Enabling the plugin globally

A plugin which is not associated to any Service, Route, or Consumer is considered *global*, and will be run on every request. Read the Plugin Reference and the Plugin Precedence sections for more information.

```bash
$ curl -X POST http://<admin-hostname>:8001/routes/<route>/plugins \
    --data "name=oauth2-audience"  \
    --data "config.issuer=https://issuer.tld"
```

`<route>` is the `id` or `name` of the Route that this plugin configuration will target.

### Parameters

Here's a list of all the parameters which can be used in this plugin's configuration:

| Form Parameter | Description |
|---------------- | -------------|
| `name`<br><br>Type: string | The name of the plugin to use, in this case `oauth2-audience`. |
| `service.id`<br><br>Type: string | The ID of the Service the plugin targets. |
| `route.id`<br><br>Type: string | The ID of the Route the plugin targets.|
| `enabled`<br><br>Type: boolean<br><br>**Default value:** `true` | Whether this plugin will be applied.|
| `config.issuer`<br>*required* | OAuth2 issuer identifier that needs to be present in iss claim on the OAuth2 token.|
| `config.oidc_conf_discovery`<br>*optional*<br><br>**Default value:** `true` | A boolean value that indicates whether the plugin should send [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig) request to obtain information regarding JWT Verfication or OAuth2 Token Instropection. If set to false then appropriate `jwt_*` or `introspection_*` settings are required.|
| `config.required_scope`<br>*optional* | Describes an array of scope names that must be available on the OAuth2 token.|
| `config.required_audiences`<br>*optional* | Describes an array of audience value that must be available in the OAuth2 token aud claim.|
| `config.audience_prefix`<br>*optional* | Prefix string that must be added in the aud claim to be recognized as kong credential. For example if the audience associated with a consumer is `nCztu5Jrz18YAWmkwOGJkQe9T8lB99l4` and the prefix is kong:, then aud claim should contains `kong:nCztu5Jrz18YAWmkwOGJkQe9T8lB99l4`|
| `config.jwt_signature_secret`<br>*semi-optional* | Secret key used in Symmetric JWT verification.|
| `config.jwt_signature_public_key`<br>*semi-optional* | Public key used in Asymmetric JWT verification. If left empty and `oidc_conf_discovery` is not false, then this plugin will try to extract it from endpoint specified in `jwks_uri` metadata in OpenID Connect Discovery response.|
| `config.jwt_signature_algorithm`<br>*optional*<br><br>**Default value:** ["HS256", "HS512", "RS256"] | A list of allowed JWT signature algorithm. This plugin only support `HS256`, `HS512`, and `RS256` algorithm.|
| `config.jwt_introspection`<br>*optional*<br><br>**Default value:** `false` | If `true` and `introspection_endpoint` is available, then verified JWT will also be introspected.|
| `config.introspection_endpoint`<br>*semi-optional* | Oauth2 Instrospection Endpoint for introspecting non-JWT token or if `jwt_introspection` is set to `true`. If left empty and `oidc_conf_discovery` is not false, then this plugin will use `introspection_endpoint` metadata in OpenID Connect Discovery response.|
| `config.introspection_auth_method`<br>*semi-optional*<br><br>**Default value:** `client_secret_basic` | Authentication method used to contact the introspection endpoint. The valid value is one of (1) `client_secret_basic` for basic auth, (2) `client_secret_post` for using credential in URL-Encoded body, (3) `private_key_jwt` for using Asymetric JWT or (4) `client_secret_jwt` for using Symetric JWT.|
| `config.introspection_client_id`<br>*semi-optional* | Client ID information to be used in introspection request. Depending on `introspection_auth_method`, it will be used as basic auth username, `client_id` form param, or `iss` JWT claim.|
| `config.introspection_client_secret`<br>*semi-optional* | Client Secret information to be used in introspection request when using `client_secret_basic`, `client_secret_post`, or `client_secret_jwt` authentication method.|
| `config.introspection_client_rsa_private_key`<br>*semi-optional* | Client Secret information to be used in introspection request when using `private_key_jwt` authentication method.|
| `config.introspection_client_rsa_private_key_id`<br>*semi-optional* | The value of `kid` JWT Header when using `private_key_jwt` authentication method.|
| `config.introspection_param_name_token`<br>*optional*<br><br>**Default value:** `token` | URL-Encoded Form parameter name to contain the OAuth2 token to be introspected.|
| `config.introspection_params`<br>*optional* | Additional parameter to be included in OAuth2 Token Introspection request.|
| `config.introspection_claim_expiry`<br>*optional*<br><br>**Default value:** `exp` | OAuth2 Token expiry claim. The value will be used in caching mechanism.|
| `config.introspection_cache_max_ttl`<br>*optional*<br><br>**Default value:** `900` | Maximum TTL to cache introspection result.|
| `config.auth_header_map`<br>*optional*<br><br>**Default value:** {"consumer_id":"X-Consumer-ID","consumer_custom_id":"X-Consumer-Custom-ID","consumer_username":"X-Consumer-Username","credential":"x-authenticated-audience","anonymous":"X-Anonymous-Consumer"} | Map containing upstream header name to be passed to upstream server.|
| `config.claim_header_map`<br>*optional*<br><br>**Default value**: `{"iss":"x-oauth2-issuer","client_id":"x-oauth2-client","sub":"x-oauth2-subject"}` | Mapping of OAuth2 Token claim to upstream header.|
| `config.auth_header_name`<br>*optional*<br><br>**Default value**: `authorization` | The name of the header supposed to carry the access token.|
| `config.hide_credentials`<br>*optional*<br><br>**Default value**: `false` | An optional boolean value telling the plugin to show or hide the credential from the upstream service. If `true`, the plugin will strip the credential from the request (i.e. the header or querystring containing the key) before proxying it. |
| `config.anonymous`<br>*optional* | An optional string (consumer uuid) value to use as an “anonymous” consumer if authentication fails. If empty (default), the request will fail with an authentication failure `4xx`. Please note that this value must refer to the Consumer `id` attribute which is internal to Kong, and not its `custom_id`. |
| `config.run_on_preflight`<br>*optional*<br><br>**Default value**: `true` | A boolean value that indicates whether the plugin should run (and try to authenticate) on `OPTIONS` preflight requests, if set to `false` then `OPTIONS` requests will always be allowed. |
| `config.ssl_verify`<br>*optional*<br><br>**Default value**: `true` | A boolean value that indicates whether the plugin should do SSL/TLS verification when sending OAuth2 Token Instrospection or OpenID Connect Discovery request |

Once applied, any user with a valid credential can access the Service. To restrict usage to only some of the authenticated users, also add the [ACL][acl-associating] plugin (not covered here) and create allowed or denied groups of users.

## Usage

### Create a Consumer

You need to associate an audience to an existing [Consumer][consumer-object] object.
A Consumer can have many audiences.

#### With a Database

To create a Consumer, you can execute the following request:

```bash
curl -d "username=user123&custom_id=SOME_CUSTOM_ID" http://kong:8001/consumers/
```

#### Without a Database

Your declarative configuration file will need to have one or more Consumers. You can create them
on the `consumers:` yaml section:

``` yaml
consumers:
- username: user123
  custom_id: SOME_CUSTOM_ID
```

In both cases, the parameters are as described below:

parameter                       | description
---                             | ---
`username`<br>*semi-optional*   | The username of the consumer. Either this field or `custom_id` must be specified.
`custom_id`<br>*semi-optional*  | A custom identifier used to map the consumer to another database. Either this field or `username` must be specified.

If you are also using the [ACL](/plugins/acl/) plugin and allow lists with this
service, you must add the new consumer to the allowed group. See
[ACL: Associating Consumers][acl-associating] for details.

### Create an OAuth2 Audience

#### With Database

You can provision new audience by making the following HTTP request:

```bash
$ curl -X POST http://kong:8001/consumers/{consumer}/oauth2-audiences \
  --data  "audience=62eb165c070a41d5c1b58d9d3d725ca1" \
  --data  "issuer=https://issuer.in.iss.claim.tld" \
  --data  "client_id=value-of-client-id-claim"

HTTP/1.1 201 Created

{
    "consumer": { "id": "876bf719-8f18-4ce5-cc9f-5b5af6c36007" },
    "created_at": 1443371053000,
    "id": "62a7d3b7-b995-49f9-c9c8-bac4d781fb59",
    "audience": "62eb165c070a41d5c1b58d9d3d725ca1",
    "issuer": "https://issuer.in.iss.claim.tld",
    "client_id": "value-of-client-id-claim"
}
```

#### Without Database

You can add audience on your declarative config file on the `oauth2_audiences` yaml entry:

``` yaml
oauth2_audiences:
- consumer: {consumer}
  audience: "62eb165c070a41d5c1b58d9d3d725ca1"
  issuer: "https://issuer.in.iss.claim.tld"
  client_id: "value-of-client-id-claim
```

<div class="alert alert-warning">
  <strong>Note:</strong> It is recommended to let Kong auto-generate the audience.
</div>

In both cases the fields/parameters work as follows:

field/parameter     | description
---                 | ---
`{consumer}`        | The `id` or `username` property of the [Consumer][consumer-object] entity to associate the audience to.
`audience`<br>*optional* | This value that must be available in `aud` claim of the OAuth2 token. You can optionally set your own unique `audience` to associate the external OAuth2 client. If missing, the plugin will generate one.
`issuer`            | The issuer identifier that must be available in `iss` claim of the OAuth2 token.
`client_id`         | The client id that must be available in `client_id` claim of the OAuth2 token.

### Delete an OAuth2 Audience

You can delete an OAuth2 Audience by making the following HTTP request:

```bash
$ curl -X DELETE http://kong:8001/consumers/{consumer}/oauth2-audiences/{id}
HTTP/1.1 204 No Content
```

- `consumer`: The `id` or `username` property of the [Consumer][consumer-object] entity to associate the credentials to.
- `id`: The `id` attribute of the OAuth2 Audience object.

### Upstream Headers

When a client has been authenticated, the plugin will append some headers to the request before proxying it to the upstream service, so that you can identify the Consumer in your code:

- `X-Consumer-ID`, the ID of the Consumer on Kong
- `X-Consumer-Custom-ID`, the `custom_id` of the Consumer (if set)
- `X-Consumer-Username`, the `username` of the Consumer (if set)
- `x-authenticated-audience`, the identifier of the Credential (only if the consumer is not the 'anonymous' consumer)
- `X-Anonymous-Consumer`, will be set to `true` when authentication failed, and the 'anonymous' consumer was set instead.
- `x-oauth2-issuer`, the value of `iss` claim from the OAauth2 Token.
- `x-oauth2-client`, the value of `client_id` claim from the OAauth2 Token.

You can use this information on your side to implement additional logic. You can use the `X-Consumer-ID` value to query the Kong Admin API and retrieve more information about the Consumer. Additonally you can control the name of headers used and additional claims to be forwarded via `auth_header_map` and `claim_header_map` configuration.

### Paginate through OAuth2 Audiences

<div class="alert alert-warning">
  <strong>Note:</strong> This endpoint was introduced in Kong 0.11.2.
</div>

You can paginate through the OAuth2 Audiences for all Consumers using the following
request:

```bash
$ curl -X GET http://kong:8001/oauth2-audiences

{
   "data":[
      {
         "id":"17ab4e95-9598-424f-a99a-ffa9f413a821",
         "created_at":1507941267000,
         "audience":"Qslaip2ruiwcusuSUdhXPv4SORZrfj4L",
         "issuer": "https://issuer.in.iss.claim.tld",
         "client_id": "value-of-client-id-claim",
         "consumer": { "id": "c0d92ba9-8306-482a-b60d-0cfdd2f0e880" }
      },
      {
         "id":"6cb76501-c970-4e12-97c6-3afbbba3b454",
         "created_at":1507936652000,
         "audience":"nCztu5Jrz18YAWmkwOGJkQe9T8lB99l4",
         "issuer": "https://issuer.in.iss.claim.tld",
         "client_id": "value-of-client-id-claim",
         "consumer": { "id": "c0d92ba9-8306-482a-b60d-0cfdd2f0e880" }
      },
      {
         "id":"b1d87b08-7eb6-4320-8069-efd85a4a8d89",
         "created_at":1507941307000,
         "audience":"26WUW1VEsmwT1ORBFsJmLHZLDNAxh09l",
         "issuer": "https://issuer.in.iss.claim.tld",
         "client_id": "value-of-client-id-claim",
         "consumer": { "id": "3c2c8fc1-7245-4fbb-b48b-e5947e1ce941" }
      }
   ]
   "next":null,
}
```

You can filter the list by consumer by using this other path:

```bash
$ curl -X GET http://kong:8001/consumers/{username or id}/oauth2-audiences

{
    "data": [
       {
         "id":"6cb76501-c970-4e12-97c6-3afbbba3b454",
         "created_at":1507936652000,
         "audience":"nCztu5Jrz18YAWmkwOGJkQe9T8lB99l4",
         "issuer": "https://issuer.in.iss.claim.tld",
         "client_id": "value-of-client-id-claim",
         "consumer": { "id": "c0d92ba9-8306-482a-b60d-0cfdd2f0e880" }
       }
    ]
    "next":null,
}
```

`username or id`: The username or id of the consumer whose credentials need to be listed

### Retrieve the Consumer associated with an OAuth2 Audience

<div class="alert alert-warning">
  <strong>Note:</strong> This endpoint was introduced in Kong 0.11.2.
</div>

It is possible to retrieve a [Consumer][consumer-object] associated with an API
Key using the following request:

```bash
curl -X GET http://kong:8001/oauth2-audiences/{audience or id}/consumer

{
   "created_at":1507936639000,
   "username":"foo",
   "id":"c0d92ba9-8306-482a-b60d-0cfdd2f0e880"
}
```

- `audience or id`: The `id` or `audience` property of the OAuth2 Audience for which to get the
associated Consumer.

[configuration]: https://docs.konghq.com/latest/configuration
[consumer-object]: https://docs.konghq.com/latest/admin-api/#consumer-object
[acl-associating]: https://docs.konghq.com/plugins/acl/#associating-consumers
[faq-authentication]: https://docs.konghq.com/about/faq/#how-can-i-add-an-authentication-layer-on-a-microservice/api?

## Development

### Change the plugin version

To change the current plugin version, use the rename.sh script.

```bash
chmod +x ./rename.sh && ./rename.sh oauth2-audience oauth2-audience <new_plugin_version>
```

If you are not on linux or somehow not able to run this script, utilize docker and run this script:

```bash
docker run \
    -it \
    --rm \
    -v $PWD:/tmp/rename \
    -w /tmp/rename \
    --entrypoint /bin/bash \
    debian:stretch-slim \
    -c "chmod +x ./rename.sh && ./rename.sh oauth2-audience oauth2-audience <new_plugin_version>"
```

### Build

```bash
docker-compose build
```

### Run

```bash
docker-compose up kong
```

### Test

```bash
docker-compose up busted
```

### Debugging via zerobrane

*Assuming you mount **./volumes/kong/usr/local/share/lua/5.1** into **$KONG_LUA_PATH/$KONG_LUA_VERSION** container path*

1. Click "Project" > "Project Directory" > "choose" and poin the project directory to ***./volumes/kong/usr/local/share/lua/5.1***.

1. Click "Project" > "Start Debugger Server"

1. Invoke the mockbin API
