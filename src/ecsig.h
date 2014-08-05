#ifndef PHP_ECSIG_H
#define PHP_ECSIG_H

#define PHP_ELLIPTIC_CURVE_VERSION "1.0"
#define PHP_ELLIPTIC_CURVE_EXTNAME "ellipticCurveSignature"

ZEND_MINIT_FUNCTION(ellipticCurveSignature);

ZEND_FUNCTION(ec_generate_pk);
ZEND_FUNCTION(ec_sign);
ZEND_FUNCTION(ec_verify);

extern zend_module_entry ellipticCurveSignature_module_entry;
#define phpext_ellipticCurveSignature_ptr &ellipticCurveSignature_module_entry

#endif
