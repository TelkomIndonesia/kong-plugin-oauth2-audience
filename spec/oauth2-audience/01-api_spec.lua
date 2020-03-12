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
    setup(function()
      bp, db = helpers.get_db_utils(strategy, {"routes", "services", "plugins", "consumers", schema_name}, {plugin_name})

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

      describe("PUT", function()
        after_each(function()
          db:truncate(schema_name)
        end)

        it("creates a oauth2-audience with extracted from the path", function()
          local res = assert(admin_client:send{
            method = "PUT",
            path = path .. "12345",
            body = {issuer = "https://idp.jwt", client_id = 'client'},
            headers = {["Content-Type"] = "application/json"}
          })
          local body = assert.res_status(200, res)
          local json = cjson.decode(body)
          assert.equal(consumer.id, json.consumer.id)
          assert.equal("12345", json.audience)
        end)

        it("auto-generate a oauth2-audience if the path is uuid", function()
          local res = assert(admin_client:send{
            method = "PUT",
            path = path .. "c16bbff7-5d0d-4a28-8127-1ee581898f11",
            body = {issuer = "https://idp.jwt", client_id = 'client'},
            headers = {["Content-Type"] = "application/json"}
          })
          local body = assert.res_status(200, res)
          local json = cjson.decode(body)
          assert.equal(consumer.id, json.consumer.id)
          assert.is_string(json.audience)
        end)

      end)

      describe("PATCH", function()
        it("updates a credential by id", function()
          local res = assert(admin_client:send{
            method = "PATCH",
            path = path .. credential.id,
            body = {audience = "4321"},
            headers = {["Content-Type"] = "application/json"}
          })
          local body = assert.res_status(200, res)
          local json = cjson.decode(body)
          assert.equal("4321", json.audience)
        end)

        it("updates a credential by key", function()
          local res = assert(admin_client:send{
            method = "PATCH",
            path = path .. credential.audience,
            body = {audience = "4321UPD"},
            headers = {["Content-Type"] = "application/json"}
          })
          local body = assert.res_status(200, res)
          local json = cjson.decode(body)
          assert.equal("4321UPD", json.audience)
        end)

        describe("errors", function()
          it("handles invalid input", function()
            local res = assert(admin_client:send{
              method = "PATCH",
              path = path .. credential.id,
              body = {audience = 123},
              headers = {["Content-Type"] = "application/json"}
            })
            local body = assert.res_status(400, res)
            local json = cjson.decode(body)
            assert.same({audience = "expected a string"}, json.fields)
          end)
        end)
      end)

      describe("DELETE", function()
        it("deletes a credential", function()
          local res = assert(admin_client:send{method = "DELETE", path = path .. credential.id})
          assert.res_status(204, res)
        end)

        describe("errors", function()
          it("returns 400 on invalid input", function()
            local res = assert(admin_client:send{method = "DELETE", path = path .. "blah"})
            assert.res_status(404, res)
          end)

          it("returns 404 if not found", function()
            local res = assert(admin_client:send{method = "DELETE", path = path .. "00000000-0000-0000-0000-000000000000"})
            assert.res_status(404, res)
          end)
        end)
      end)

    end)

    describe("/" .. api_name, function()
      local consumer2
      describe("GET", function()
        setup(function()
          db:truncate(schema_name)

          for i = 1, 3 do
            db.oauth2_audiences:insert{consumer = {id = consumer.id}, issuer = "https://idp.jwt", client_id = 'client'}
          end

          consumer2 = db.consumers:insert{username = "bob-the-buidler"}
          for i = 1, 3 do
            db.oauth2_audiences:insert{consumer = {id = consumer2.id}, issuer = "https://idp.jwt", client_id = 'client2'}
          end
        end)

        it("retrieves all the oauth2-audiences with trailing slash", function()
          local res = assert(admin_client:send{method = "GET", path = string.format("/%s/", api_name)})
          local body = assert.res_status(200, res)
          local json = cjson.decode(body)
          assert.is_table(json.data)
          assert.equal(6, #json.data)
        end)

        it("retrieves all the oauth2-audiences without trailing slash", function()
          local res = assert(admin_client:send{method = "GET", path = "/" .. api_name})
          local body = assert.res_status(200, res)
          local json = cjson.decode(body)
          assert.is_table(json.data)
          assert.equal(6, #json.data)
        end)

        it("paginates through the oauth2-audiences", function()
          local res = assert(admin_client:send{method = "GET", path = string.format("/%s?size=3", api_name)})
          local body = assert.res_status(200, res)
          local json_1 = cjson.decode(body)
          assert.is_table(json_1.data)
          assert.equal(3, #json_1.data)

          res = assert(admin_client:send{method = "GET", path = "/" .. api_name, query = {size = 3, offset = json_1.offset}})
          body = assert.res_status(200, res)
          local json_2 = cjson.decode(body)
          assert.is_table(json_2.data)
          assert.equal(3, #json_2.data)

          assert.not_same(json_1.data, json_2.data)
        end)

      end)

      describe("POST", function()
        setup(function()
          db:truncate(schema_name)
        end)

        it("does not create oauth2-audience credential when missing consumer", function()
          local res = assert(admin_client:send{
            method = "POST",
            path = "/" .. api_name,
            body = {audience = "1234", issuer = "https://idp.jwt", client_id = 'client'},
            headers = {["Content-Type"] = "application/json"}
          })
          local body = assert.res_status(400, res)
          local json = cjson.decode(body)
          assert.same("schema violation (consumer: required field missing)", json.message)
        end)

        it("creates oauth2-audience credential", function()
          local res = assert(admin_client:send{
            method = "POST",
            path = "/" .. api_name,
            body = {audience = "1234", issuer = "https://idp.jwt", client_id = 'client', consumer = {id = consumer.id}},
            headers = {["Content-Type"] = "application/json"}
          })
          local body = assert.res_status(201, res)
          local json = cjson.decode(body)
          assert.equal("1234", json.audience)
        end)

      end)
    end)

    describe("/" .. plugin_name .. "/:audience_or_id", function()
      local path = string.format("/%s/", api_name)

      describe("PUT", function()
        setup(function()
          db:truncate(plugin_name)
        end)

        it("does not create oauth2-audience when missing consumer", function()
          local res = assert(admin_client:send{
            method = "PUT",
            path = path .. "1234",
            body = {issuer = "https://idp.jwt", client_id = 'client'},
            headers = {["Content-Type"] = "application/json"}
          })
          local body = assert.res_status(400, res)
          local json = cjson.decode(body)
          assert.same("schema violation (consumer: required field missing)", json.message)
        end)

        it("creates oauth2-audience ", function()
          local res = assert(admin_client:send{
            method = "PUT",
            path = path .. "1234",
            body = {consumer = {id = consumer.id}, issuer = "https://idp.jwt", client_id = 'client'},
            headers = {["Content-Type"] = "application/json"}
          })
          local body = assert.res_status(200, res)
          local json = cjson.decode(body)
          assert.equal("1234", json.audience)
        end)
      end)
    end)

    describe("/" .. plugin_name .. "/:audience_or_id/consumer", function()
      local path = string.format("/%s/", api_name)

      describe("GET", function()
        local credential
        setup(function()
          db:truncate(schema_name)
          credential = db.oauth2_audiences:insert{
            consumer = {id = consumer.id},
            issuer = "https://idp.jwt",
            client_id = 'client'
          }
        end)

        it("retrieve Consumer from a credential's id", function()
          local res = assert(admin_client:send{method = "GET", path = path .. credential.id .. "/consumer"})
          local body = assert.res_status(200, res)
          local json = cjson.decode(body)
          assert.same(consumer, json)
        end)

        it("retrieve a Consumer from a credential's key", function()
          local res = assert(admin_client:send{method = "GET", path = path .. credential.audience .. "/consumer"})
          local body = assert.res_status(200, res)
          local json = cjson.decode(body)
          assert.same(consumer, json)
        end)

        it("returns 404 for a random non-existing id", function()
          local res = assert(admin_client:send{method = "GET", path = path .. utils.uuid() .. "/consumer"})
          assert.res_status(404, res)
        end)

        it("returns 404 for a random non-existing key", function()
          local res = assert(admin_client:send{method = "GET", path = path .. utils.random_string() .. "/consumer"})
          assert.res_status(404, res)
        end)

      end)
    end)

  end)

end
