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
    NULL,
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

PHP_FUNCTION(ec_generate_pk)
{

}

PHP_FUNCTION(ec_sign)
{

}

PHP_FUNCTION(ec_verify)
{

}
