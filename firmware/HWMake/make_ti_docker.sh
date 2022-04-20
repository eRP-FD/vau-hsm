#!/bin/bash
. .env
mkdir cryptoserversdk
cp -r /opt/cryptoserversdk/SDK/cs2/include/*.* cryptoserversdk
make CFG=${CFG} COMPILE_DEFS="-DERP_MDL_VERSION=${ERP_MDL_VERSION} -DBLOB_DOMAIN=\\\"${BLOB_DOMAIN}\\\" -DDISABLE_BLOB_EXPIRY"
