#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ellipticCurveSignature.h"
#include "ed25519.h"


static zend_function_entry ellipticCurveSignature_functions[] = {
    ZEND_FE(ec_generate_pk,NULL)
    ZEND_FE(ec_sign,NULL)
    ZEND_FE(ec_verify,NULL)
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
    const unsigned char *sk;
    int skLen;
    int curveType = 1;//EC_ED25519

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l", &sk, &skLen, &curveType) == FAILURE) {
        RETURN_NULL();
    }

    switch (curveType) {
        case 1: //EC_ED25519
            if (skLen != 32) {
                zend_error(E_ERROR, "Invalid secret key.");
            }
            ed25519_public_key pk;
            ed25519_publickey(sk,pk);
            RETURN_STRINGL(pk,32,1);
        default:
            zend_error(E_ERROR, "Invalid curve type.");
    }

}

ZEND_FUNCTION(ec_sign)
{
    const unsigned char *sk;
    int skLen;
    const unsigned char *pk;
    int pkLen;
    const unsigned char *msg;
    int msgLen;
    int curveType = 1;//EC_ED25519

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss|l", &sk, &skLen, &pk, &pkLen, &msg, &msgLen, &curveType) == FAILURE) {
        RETURN_NULL();
    }

    switch (curveType) {
        case 1: //EC_ED25519
            if (skLen != 32) {
                zend_error(E_ERROR, "Invalid secret key.");
            }
            if (pkLen != 32) {
                zend_error(E_ERROR, "Invalid public key.");
            }
            ed25519_signature sig;
            ed25519_sign(msg, msgLen, sk, pk, sig);
            RETURN_STRINGL(sig,64,1);
        default:
            zend_error(E_ERROR, "Invalid curve type.");
    }

}

ZEND_FUNCTION(ec_verify)
{
    const unsigned char *pk;
    int pkLen;
    const unsigned char *orig;
    int origLen;
    const unsigned char *sig;
    int sigLen;
    int curveType = 1;//EC_ED25519

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss|l", &sig, &sigLen, &orig, &origLen, &pk, &pkLen, &curveType) == FAILURE) {
        RETURN_NULL();
    }
    
    switch (curveType) {
        case 1: //EC_ED25519
            if (pkLen != 32) {
                zend_error(E_ERROR, "Invalid public key.");
            }
            if (sigLen !=64) {
                zend_error(E_ERROR, "Invalid signature.");
            }
            int valid = ed25519_sign_open(orig, origLen, pk, sig);
            if (valid == 0) {
                RETURN_TRUE;
            } else {
                RETURN_FALSE;
            }
        default:
            zend_error(E_ERROR, "Invalid curve type.");
    }

}
