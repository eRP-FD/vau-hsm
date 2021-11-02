#!/bin/bash

mkdir cryptoserversdk
cp -r /opt/cryptoserversdk/SDK/cs2/include/*.* cryptoserversdk
make CFG=rel50 COMPILE_DEFS="-DERP_MDL_VERSION=0x00000500 -DBLOB_DOMAIN=\\\"REFZ\\\" -DDISABLE_BLOB_EXPIRY"
