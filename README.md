# Kong Plugin OAuth2 Audience

Oauth2 authentication using external oauth2 server which is able to associate external oauth2 client with kong's consumer by using audience claim.

## Development

### Change the plugin name or version

To change the current plugin name or version, use the rename.sh script.

```bash
chmod +x ./rename.sh && ./rename.sh <current_plugin_name> <new_plugin_name> [<new_plugin_version>]
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
    -c "chmod +x ./rename.sh && ./rename.sh oauth2-audience <new_plugin_name> [<new_plugin_version>]"
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
