#!/bin/bash

if [ -z $VENDOR_CERTIFICATION_SETUP_DONE ]; then

bash setup-buildprops.sh

export VENDOR_CERTIFICATION_SETUP_DONE=true
fi
