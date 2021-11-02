make CFG=rel50 clean
mkdir cryptoserversdk
copy D:\work\IBM\Doc\Utimaco\CryptoServer-SDK-V4.40.0.2\SDK\cs2\include\*.* cryptoserversdk
rem add this to disable blob expiry: -DDISABLE_BLOB_EXPIRY" %1
make CFG=rel50 COMPILE_DEFS="-DERP_MDL_VERSION=0x00000700 -DBLOB_DOMAIN=\\\"REFZ\\\""
mkdir RUTUBuild
copy ..\hwmake50\*.* RUTUBuild