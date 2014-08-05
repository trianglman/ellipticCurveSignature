PHP_ARG_ENABLE(ellipticCurveSignature, whether to enable Elliptic Curve Signature support,[ --enable-elliptic-curve-signature Enable Elliptic Curve Signature support])

if test "$PHP_ELLIPTICCURVESIGNATURE" = "yes"; then
    AC_DEFINE(HAVE_ELLIPTICCURVESIGNATURE, 1, [Whether you have Elliptic Curve Signature])
    PHP_CHECK_LIBRARY(openssl,SHA512,
        [
            PHP_ADD_LIBRARY(openssl, 1, ELLIPTICCURVESIGNATURE_SHARED_LIBADD)
            AC_DEFINE(HAVE_OPENSSL,1,[])
        ],
        [
            AC_DEFINE(ED25519_REFHASH,1,[])
            AC_MSG_WARNING([openssl sha hash not found using custom])
        ],
        [
            -ldl -lssl -lcrypto
        ])
    PHP_NEW_EXTENSION(ellipticCurveSignature, src/ecsig.c src/ed25519.c, $ext_shared)
    PHP_SUBST(SQRL_SHARED_LIBADD)
fi
