#!/bin/bash

if [[ $run_from_vendorsetup = true ]]; then
certif_root="vendor/certification"
else
certif_root=$(pwd)
fi
configs_dir="$certif_root/configs"
service_file="$certif_root/system.prop"
fields_file="$configs_dir/pif.json"
fields_file_public="$configs_dir/pif_public.json"

if [ ! -f $fields_file ]; then
  fields_file=$fields_file_public
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
}

generate_file
