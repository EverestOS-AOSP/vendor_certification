#!/bin/bash

if [ -z $VENDOR_CERTIFICATION_SETUP_DONE ]; then

export run_from_vendorsetup=true
bash vendor/certification/setup-buildfiles.sh
unset run_from_vendorsetup

export VENDOR_CERTIFICATION_SETUP_DONE=true
fi
