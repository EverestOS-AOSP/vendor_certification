#!/bin/bash

if [ -d "vendor/certification" ]; then
	certif_root="vendor/certification"
else
	certif_root=$(pwd)
fi
service_file="$certif_root/system.prop"
fields_file="$certif_root/gms_certified_props.json"

get_field() {
	echo $(cat "$fields_file" | jq -r ".$1")
}

generate_file() {
	cat <<EOF >"${service_file}"
persist.sys.pihooks.device=$(get_field DEVICE)
persist.sys.pihooks.fingerprint=$(get_field FINGERPRINT)
persist.sys.pihooks.product=$(get_field PRODUCT)
persist.sys.pihooks.model=$(get_field MODEL)
persist.sys.pihooks.brand=$(get_field BRAND)
persist.sys.pihooks.security_patch=$(get_field VERSION.SECURITY_PATCH)
persist.sys.pihooks.manufacturer=$(get_field MANUFACTURER)
persist.sys.pihooks.board=$(get_field BOARD)
persist.sys.pihooks.hardware=$(get_field HARDWARE)
persist.sys.pihooks.device_initial_sdk_int=$(get_field VERSION.DEVICE_INITIAL_SDK_INT)
persist.sys.pihooks.release=$(get_field VERSION.RELEASE)
persist.sys.pihooks.id=$(get_field ID)
persist.sys.pihooks.incremental=$(get_field VERSION.INCREMENTAL)
persist.sys.pihooks.type=$(get_field TYPE)
persist.sys.pihooks.tags=$(get_field TAGS)
persist.sys.pihooks.device_for_attestation=$(get_field DEVICE)
persist.sys.pihooks.product_for_attestation=$(get_field PRODUCT)
persist.sys.pihooks.model_for_attestation=$(get_field MODEL)
persist.sys.pihooks.brand_for_attestation=$(get_field BRAND)
persist.sys.pihooks.manufacturer_for_attestation=$(get_field MANUFACTURER)
EOF

	sed -i '/null/d' $service_file
}

generate_file
