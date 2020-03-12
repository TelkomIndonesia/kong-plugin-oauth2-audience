local cjson = require "cjson"
local helpers = require "spec.helpers"
local utils = require "kong.tools.utils"
local plugin_name = 'oauth2-audience'
local schema_name = 'oauth2_audiences'
local api_name = 'oauth2-audiences'
local spec_nginx_conf = 'spec/fixtures/custom_nginx.template'
local ngx = require('ngx')

for _, strategy in helpers.each_strategy() do
  describe("Plugin: oauth2-audience (API) [#" .. strategy .. "]", function()
    local consumer
    local admin_client
    local bp
    local db
    local route1
    local route2
    setup(function()
      bp, db = helpers.get_db_utils(strategy, {"routes", "services", "plugins", "consumers", schema_name}, {plugin_name})

      route1 = bp.routes:insert{hosts = {"1.oauth2-audience.test"}}
      route2 = bp.routes:insert{hosts = {"2.oauth2-audience.test"}}

      consumer = bp.consumers:insert({username = "bob"}, {nulls = true})

      assert(helpers.start_kong({database = strategy, plugins = 'bundled,' .. plugin_name, nginx_conf = spec_nginx_conf}))
      admin_client = helpers.admin_client()
    end)

    teardown(function()
      if admin_client then
        admin_client:close()
      end

      helpers.stop_kong()
    end)

    describe("/consumers/:consumer/" .. api_name, function()
      describe("POST", function()
        local path = string.format("/consumers/%s/%s", consumer.username, api_name)
        after_each(function()
          db:truncate(schema_name)
        end)

        it("creates a oauth2-audience", function()
          local req_body = {issuer = "https://idp.jwt", client_id = 'client', audience = '12345'}
          local res = assert(admin_client:send{
            method = "POST",
            path = path,
            headers = {["Content-Type"] = "application/json"},
            body = req_body
          })
          local body = assert.res_status(201, res)
          local json = cjson.decode(body)
          assert.equal(consumer.id, json.consumer.id)
          assert.equal(req_body.audience, json.audience)
          assert.equal(req_body.client_id, json.client_id)
          assert.equal(req_body.issuer, json.issuer)
        end)

        it("creates a oauth2-audience auto-generating a unique key", function()
          local req_body = {issuer = "https://idp.jwt", client_id = 'client'}
          local res = assert(admin_client:send{
            method = "POST",
            path = path,
            headers = {["Content-Type"] = "application/json"},
            body = req_body
          })
          local body = assert.res_status(201, res)
          local json = cjson.decode(body)
          assert.equal(consumer.id, json.consumer.id)
          assert.is_string(json.audience)
          assert.equal(req_body.client_id, json.client_id)
          assert.equal(req_body.issuer, json.issuer)

          local first_aud = json.audience
          db:truncate(schema_name)

          res = assert(admin_client:send{
            method = "POST",
            path = path,
            headers = {["Content-Type"] = "application/json"},
            body = req_body
          })
          body = assert.res_status(201, res)
          json = cjson.decode(body)
          assert.equal(consumer.id, json.consumer.id)
          assert.is_string(json.audience)
          assert.not_equal(first_aud, json.audience)
          assert.equal(req_body.client_id, json.client_id)
          assert.equal(req_body.issuer, json.issuer)
        end)

        it("creates a oauth2-audience with tags", function()
          local res = assert(admin_client:send{
            method = "POST",
            path = path,
            body = {issuer = "https://idp.jwt", client_id = 'client', audience = '12345', tags = {"tag1", "tag2"}},
            headers = {["Content-Type"] = "application/json"}
          })
          local body = assert.res_status(201, res)
          local json = cjson.decode(body)
          assert.equal(consumer.id, json.consumer.id)
          assert.equal("tag1", json.tags[1])
          assert.equal("tag2", json.tags[2])
        end)

        it("creates a oauth2-audience credential with a ttl", function()
          local res = assert(admin_client:send{
            method = "POST",
            path = path,
            body = {issuer = "https://idp.jwt", client_id = 'client', ttl = 1},
            headers = {["Content-Type"] = "application/json"}
          })
          local body = assert.res_status(201, res)
          local json = cjson.decode(body)
          assert.equal(consumer.id, json.consumer.id)
          assert.is_string(json.audience)

          ngx.sleep(3)

          local id = json.consumer.id
          res = assert(admin_client:send{method = "GET", path = path .. '/' .. id})
          assert.res_status(404, res)
        end)

        it("reject oauth2-audience creation without issuer or client_id", function()
          local res = assert(admin_client:send{
            method = "POST",
            path = path,
            headers = {["Content-Type"] = "application/json"},
            body = {issuer = "https://idp.jwt"}
          })
          assert.res_status(400, res)
          res = assert(admin_client:send{
            method = "POST",
            path = path,
            headers = {["Content-Type"] = "application/json"},
            body = {client_id = 'client'}
          })
          assert.res_status(400, res)
          res = assert(admin_client:send{
            method = "POST",
            path = path,
            headers = {["Content-Type"] = "application/json"},
            body = {}
          })
          assert.res_status(400, res)
        end)

        describe("GET", function()
          setup(function()
            for i = 1, 3 do
              assert(db.oauth2_audiences:insert{consumer = {id = consumer.id}, issuer = "https://idp.jwt", client_id = 'client'})
            end
          end)
          teardown(function()
            db:truncate(schema_name)
          end)

          it("retrieves the first page", function()
            local res = assert(admin_client:send{method = "GET", path = path})
            local body = assert.res_status(200, res)
            local json = cjson.decode(body)
            assert.is_table(json.data)
            assert.equal(3, #json.data)
          end)
        end)

        describe("GET #ttl", function()
          setup(function()
            for i = 1, 3 do
              assert(db.oauth2_audiences:insert({
                consumer = {id = consumer.id},
                issuer = "https://idp.jwt",
                client_id = 'client'
              }, {ttl = 10}))
            end
          end)
          teardown(function()
            db:truncate(schema_name)
          end)

          it("entries contain ttl when specified", function()
            local res = assert(admin_client:send{method = "GET", path = path})
            local body = assert.res_status(200, res)
            local json = cjson.decode(body)
            assert.is_table(json.data)
            for _, credential in ipairs(json.data) do
              assert.not_nil(credential.ttl)
            end
          end)
        end)

      end)

    end)

    describe("/consumers/:consumer/" .. api_name .. '/:id', function()
      local path = string.format("/consumers/%s/%s/", consumer.username, api_name)

      local credential
      before_each(function()
        db:truncate(schema_name)
        credential = db.oauth2_audiences:insert{consumer = {id = consumer.id}, issuer = "https://idp.jwt", client_id = 'client'}
      end)

      describe("GET", function()
        it("retrieves oauth2-audience by id", function()
          local res = assert(admin_client:send{method = "GET", path = path .. credential.id})
          local body = assert.res_status(200, res)
          local json = cjson.decode(body)
          assert.equal(credential.id, json.id)
        end)

        it("retrieves oauth2-audience by audience", function()
          local res = assert(admin_client:send{method = "GET", path = path .. credential.audience})
          local body = assert.res_status(200, res)
          local json = cjson.decode(body)
          assert.equal(credential.id, json.id)
        end)

        it("retrieves credential by id only if the credential belongs to the specified consumer", function()
          local other = assert(bp.consumers:insert{username = "alice"})

          local res = assert(admin_client:send{method = "GET", path = path .. credential.id})
          assert.res_status(200, res)

          res = assert(admin_client:send{
            method = "GET",
            path = string.format("/consumers/%s/%s/%s", other.username, api_name, credential.id)
          })
          assert.res_status(404, res)
        end)

        it("oauth2-audience contains #ttl", function()
          local credential = db.oauth2_audiences:insert({
            consumer = {id = consumer.id},
            issuer = "https://idp.jwt",
            client_id = 'client'
          }, {ttl = 10})

          local res = assert(admin_client:send{method = "GET", path = path .. credential.id})
          local body = assert.res_status(200, res)
          local json = cjson.decode(body)
          assert.equal(credential.id, json.id)
          assert.not_nil(json.ttl)
        end)
      end)
    end)
  end)
end
