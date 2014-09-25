#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ellipticCurveSignature.h"
#include "ed25519.h"

ZEND_BEGIN_ARG_INFO_EX(arginfo_ellipticCurveSignature_ec_generate_pk,0,0,1)
    ZEND_ARG_INFO(0,secretKey)
    ZEND_ARG_INFO(0,curveType)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(arginfo_ellipticCurveSignature_ec_sign,0,0,3)
    ZEND_ARG_INFO(0,secretKey)
    ZEND_ARG_INFO(0,publicKey)
    ZEND_ARG_INFO(0,message)
    ZEND_ARG_INFO(0,curveType)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(arginfo_ellipticCurveSignature_ec_verify,0,0,3)
    ZEND_ARG_INFO(0,signature)
    ZEND_ARG_INFO(0,original)
    ZEND_ARG_INFO(0,publicKey)
    ZEND_ARG_INFO(0,curveType)
ZEND_END_ARG_INFO();

static zend_function_entry ellipticCurveSignature_functions[] = {
    ZEND_FE(ec_generate_pk,arginfo_ellipticCurveSignature_ec_generate_pk)
    ZEND_FE(ec_sign,arginfo_ellipticCurveSignature_ec_sign)
    ZEND_FE(ec_verify,arginfo_ellipticCurveSignature_ec_verify)
    {NULL,NULL,NULL}
};

zend_module_entry ellipticCurveSignature_module_entry = {
    STANDARD_MODULE_HEADER,
    PHP_ELLIPTIC_CURVE_EXTNAME,
    ellipticCurveSignature_functions,
    ZEND_MINIT(ellipticCurveSignature),
    NULL,
    NULL,
    NULL,
    NULL,
    PHP_ELLIPTIC_CURVE_VERSION,
    STANDARD_MODULE_PROPERTIES
};

#if COMPILE_DL_ELLIPTICCURVESIGNATURE
    ZEND_GET_MODULE(ellipticCurveSignature)
#endif

ZEND_MINIT_FUNCTION(ellipticCurveSignature)
{
    //register supported elliptic curve options
    REGISTER_LONG_CONSTANT("EC_ED25519",1,CONST_CS|CONST_PERSISTENT);
}

ZEND_FUNCTION(ec_generate_pk)
{
    const char *skin;
    int skLen;
    long curveType = 1;//EC_ED25519

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l", &skin, &skLen, &curveType) == FAILURE) {
        RETURN_NULL();
    }

    switch (curveType) {
        case 1: //EC_ED25519
            if (skLen != 32) {
                zend_error(E_WARNING, "Invalid secret key.");
                RETURN_NULL();
            }
            ed25519_public_key pk;
            ed25519_secret_key sk;
            memcpy(sk,skin,32);
            ed25519_publickey(sk,pk);
            RETURN_STRINGL(pk,32,1);
        default:
            zend_error(E_WARNING, "Invalid curve type.");
            RETURN_NULL();
    }

}

ZEND_FUNCTION(ec_sign)
{
    const char *skin;
    int skLen;
    const char *pkin;
    int pkLen;
    const char *msgin;
    int msgLen;
    long curveType = 1;//EC_ED25519

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss|l", &skin, &skLen, &pkin, &pkLen, &msgin, &msgLen, &curveType) == FAILURE) {
        RETURN_NULL();
    }

    switch (curveType) {
        case 1: //EC_ED25519
            if (skLen != 32) {
                zend_error(E_WARNING, "Invalid secret key.");
                RETURN_NULL();
            }
            if (pkLen != 32) {
                zend_error(E_WARNING, "Invalid public key.");
                RETURN_NULL();
            }
            ed25519_secret_key sk;
            ed25519_public_key pk;
            ed25519_signature sig;
            memcpy(sk,skin,32);
            memcpy(pk,pkin,32);
            ed25519_sign(msgin, msgLen, sk, pk, sig);
            RETURN_STRINGL(sig,64,1);
        default:
            zend_error(E_WARNING, "Invalid curve type.");
            RETURN_NULL();
    }

}

ZEND_FUNCTION(ec_verify)
{
    const char *pkin;
    int pkLen;
    const char *orig;
    int origLen;
    const char *sigin;
    int sigLen;
    long curveType = 1;//EC_ED25519

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss|l", &sigin, &sigLen, &orig, &origLen, &pkin, &pkLen, &curveType) == FAILURE) {
        RETURN_NULL();
    }
    
    switch (curveType) {
        case 1: //EC_ED25519
            if (pkLen != 32) {
                zend_error(E_WARNING, "Invalid public key.");
                RETURN_NULL();
            }
            if (sigLen !=64) {
                zend_error(E_WARNING, "Invalid signature.");
                RETURN_NULL();
            }
            ed25519_signature sig;
            ed25519_public_key pk;
            memcpy(pk,pkin,32);
            memcpy(sig,sigin,64);
            int valid = ed25519_sign_open(orig, origLen, pk, sig);
            if (valid == 0) {
                RETURN_TRUE;
            } else {
                RETURN_FALSE;
            }
        default:
            zend_error(E_WARNING, "Invalid curve type.");
            RETURN_NULL();
    }

}
