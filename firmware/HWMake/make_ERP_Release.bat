mkdir cryptoserversdk
copy D:\work\IBM\Doc\Utimaco\CryptoServer-SDK-V4.40.0.2\SDK\cs2\include\*.* cryptoserversdk
make CFG=rel50 COMPILE_DEFS="-DERP_MDL_VERSION=0x00000500 -DBLOB_DOMAIN=\\\"REFZ\\\" -DDISABLE_BLOB_EXPIRY" %1
