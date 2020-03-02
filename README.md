# Kong plugin template

_Forked from *[kong-plugin github repository](https://github.com/Kong/kong-plugin)*_

This repository contains a very simple Kong plugin template to get you
up and running quickly using **Docker** for developing your own plugins.

## Renaming the plugin

To change the current plugin name, use the rename.sh script. Note that the default current plugin name of this repository is `myplugin`

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
    -c "chmod +x ./rename.sh && ./rename.sh <current_plugin_name> <new_plugin_name> [<new_plugin_version>]"
```

## Preparation

The following command should be run manually once before using `kong` or `kong_busted` service. Note that after `postgres` service have been started successfuly (by examining the output of *docker-compose logs postgres*), press **ctrl+c** to exit from *docker-compose logs postgres* and start the `migrator`

```bash
docker-compose up -d postgres && \
docker-compose logs -f postgres; \
docker-compose up migrator
```

## Runing kong service

the following is an example how to run the `kong` service, add an api that point to mockbin.org, and invoke the api

```bash
docker-compose up --build -d kong && docker-compose logs -f kong

# add mockbin API
curl -i -X PUT \
  --url http://localhost:8001/services/18f68371-726a-4e25-a7c9-bf012d096d85 \
  --data "protocol=http" \
  --data "host=mockbin.org" \
  --data "port=80" \
  --data "path=/request"

curl -i -X PUT \
  --url http://localhost:8001/routes/1a5cc9b8-046a-4b47-a2a3-d0614004fc73 \
  --data "paths[]=/" \
  --data "service.id=18f68371-726a-4e25-a7c9-bf012d096d85"


# add mobdebug plugin
curl -i -X POST \
  --url http://localhost:8001/plugins/ \
  --data "name=mobdebug" \
  --data "route_id=1a5cc9b8-046a-4b47-a2a3-d0614004fc73"

# add your plugin
curl -i -X POST \
  --url http://localhost:8001/plugins/ \
  --data 'name=myplugin'

# try the mockbin API
curl -i http://localhost:8000
```

## Debugging via zerobrane

*Assuming you mount **./volumes/kong/usr/local/share/lua/5.1** into **$KONG_LUA_PATH/$KONG_LUA_VERSION** container path*

1. Click "Project" > "Project Directory" > "choose" and poin the project directory to ***./volumes/kong/usr/local/share/lua/5.1***.

1. Click "Project" > "Start Debugger Server"

1. Invoke the mockbin API

## Testing with busted

1. to start your plugin test after completing the step from [Preparation](#preparation), run:

    ```bash
    docker-compose up kong_busted
    ```
