#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "ecsig.h"
#include "ed25519.h"


static zend_function_entry ellipticCurveSignature_functions[] = {
    ZEND_FE(ec_generate_pk,NULL),
    ZEND_FE(ec_sign,NULL),
    ZEND_FE(ec_verify,NULL),
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
    STANDARD_MODULE_PROPERTIES_EX
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

}

ZEND_FUNCTION(ec_sign)
{

}

ZEND_FUNCTION(ec_verify)
{

}
