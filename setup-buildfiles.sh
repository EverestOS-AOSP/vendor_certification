#!/bin/bash

if [[ $run_from_vendorsetup = true ]]; then
certif_root="vendor/certification"
else
certif_root=$(pwd)
fi
configs_dir="$certif_root/configs"
service_file="$certif_root/system.prop"
service_java_file="$certif_root/libs/src/com/android/internal/util/custom/certification/Keybox.java"
fields_file="$configs_dir/pif.json"
fields_file_public="$configs_dir/pif_public.json"
fields_java_file="$configs_dir/Keybox.java"
fields_java_file_public="$configs_dir/Keybox_public.java"

if [ ! -f $fields_file ]; then
  fields_file=$fields_file_public
fi

if [ ! -f $fields_java_file ]; then
  fields_java_file=$fields_java_file_public
fi

get_field() {
  echo `cat "$fields_file" | jq -r ".$1"`
}

generate_file() {
  cat <<EOF >"${service_file}"
persist.sys.pihooks.device=$(get_field DEVICE)
persist.sys.pihooks.fingerprint=$(get_field FINGERPRINT)
persist.sys.pihooks.model=$(get_field MODEL)
persist.sys.pihooks.security_patch=$(get_field SECURITY_PATCH)
persist.sys.pihooks.manufacturer=$(get_field MANUFACTURER)
persist.sys.pihooks.api_level=$(get_field DEVICE_INITIAL_SDK_INT)
EOF

cp -rf $fields_java_file $service_java_file
}

generate_file
