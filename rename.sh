#/bin/bash
set -e

if [[ $# -lt 2 ]] ; then
    echo 
    echo "=================================================================================================="
    echo "Usage: $0 current_plugin_name new_plugin_name [new_plugin_version]"
    echo 
    echo "Example (only name change): $0 myplugin mynewplugin" 
    echo "Example (only version change): $0 myplugin myplugin 0.1.1-1" 
    echo "Example (with name and version change): $0 myplugin mynewplugin 0.1.1-1" 
    echo
    echo "=================================================================================================="
    echo "If you are not on linux or somehow not able to run this script, utilize docker to run this script:"
    echo 
    cat <<EOF
    $ docker run \\
        -it \\
        --rm \\
        -v \$PWD:/tmp/rename \\
        -w /tmp/rename \\
        --entrypoint /bin/bash \\
        debian:stretch-slim \\
        -c "chmod +x ./rename.sh && ./rename.sh current_plugin_name new_plugin_name [new_plugin_version]"
EOF
    echo
    echo "=================================================================================================="
    echo 
    exit 0
fi

old_name=$1
new_name=$2
new_version=$3

# no rename needed
if [ "$old_name" == "$new_name" ] && [ -z "$new_version" ] ; then
    echo "old and new name are identical"
    exit 0
fi

# rename folder
if [ "$old_name" != "$new_name" ]; then
    echo "== renaming directory"
    mv ./kong/plugins/$old_name ./kong/plugins/$new_name
    mv ./spec/$old_name ./spec/$new_name
    echo "== renaming directory success"
fi

# rename rockspec
echo "== modifying and renaming rockspec file"
f=`ls | grep $old_name | head -n 1`
sed -i "s/package = \"kong-plugin-$old_name\"/package = \"kong-plugin-$new_name\"/" $f

if [ -z "$new_version" ]; then
    # no change on version
    mv $f `echo $f | sed "s/kong-plugin-$old_name/kong-plugin-$new_name/"`
else
    # change on version
    sed -i "s/version = \".*\"/version = \"$new_version\"/" $f
    mv $f kong-plugin-$new_name-$new_version.rockspec
fi
echo "== modifying and renaming rockspec file success"

# rename docker-compose.yml
echo "== modifyning docker-compose.yml"
sed -i "s/$old_name/$new_name/g" docker-compose.yml
echo "== modifyning docker-compose.yml success "

# rename .drone.yml
echo "== modifyning docker-compose.yml"
sed -i "s/$old_name/$new_name/g" .drone.yml
echo "== modifyning docker-compose.yml success "