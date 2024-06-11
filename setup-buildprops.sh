#!/bin/bash

service_file="system.prop"
fields_file="pif.json"
fields_file_public="pif_public.json"

if [ ! -f $fields_file ]; then
  fields_file=$fields_file_public
fi

get_field() {
  echo `cat "$fields_file" | jq -r ".$1"`
}

generate_file() {
  local cert_fp=$(get_field FINGERPRINT)
  IFS='/' read -r -a sections <<< "$cert_fp"
  cat <<EOF >"${service_file}"
persist.sys.pihooks.manufacturer=$(get_field MANUFACTURER)
persist.sys.pihooks.model=$(get_field MODEL)
persist.sys.pihooks.fingerprint=$cert_fp
persist.sys.pihooks.brand=${sections[0]}
persist.sys.pihooks.product=${sections[1]}
persist.sys.pihooks.device=$(get_field DEVICE)
persist.sys.pihooks.release=${sections[2]##*:}
persist.sys.pihooks.id=${sections[3]}
persist.sys.pihooks.incremental=${sections[4]%%:*}
persist.sys.pihooks.type=${sections[4]##*:}
persist.sys.pihooks.tags=${sections[5]}
persist.sys.pihooks.security_patch=$(get_field SECURITY_PATCH)
persist.sys.pihooks.api_level=$(get_field DEVICE_INITIAL_SDK_INT)
persist.sys.pihooks.lockstate=locked
persist.sys.pihooks.device_state=locked
persist.sys.pihooks.description=${sections[1]}-${sections[4]##*:} ${sections[2]##*:} ${sections[3]} ${sections[4]%%:*} ${sections[5]}
persist.sys.pihooks.verifiedbootstate=green
persist.sys.pihooks.flash.locked=1
EOF
}

generate_file
