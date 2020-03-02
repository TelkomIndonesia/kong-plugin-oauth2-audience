local oidc = require('resty.openidc')
describe(
    'resty.openidc',
    function()
        describe(
            'given invalid jwt',
            function()
                it(
                    'should return error "invalid jwt:" ',
                    function()
                        local token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
                        local res, err =
                            oidc.jwt_verify(
                            token,
                            {
                                symmetric_key = 'f4844a7d18ed62f49f23112c92eb9513',
                                token_signing_alg_values_expected = {'HS256'}
                            }
                        )
                        -- a hacky way
                        -- https://github.com/zmartzone/lua-resty-openidc/blob/master/lib/resty/openidc.lua#L947
                        assert.equal(1, err:find('invalid jwt', 1, true))
                        assert.is_nil(res)
                    end
                )
            end
        )
    end
)
