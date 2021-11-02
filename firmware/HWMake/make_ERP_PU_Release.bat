mkdir cryptoserversdk
copy D:\work\IBM\Doc\Utimaco\CryptoServer-SDK-V4.40.0.2\SDK\cs2\include\*.* cryptoserversdk
make CFG=rel50 COMPILE_DEFS="-DERP_MDL_VERSION=0x01000002 -DBLOB_DOMAIN=\\\"PROD\\\" %1
