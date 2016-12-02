#ifndef VOMS_AC_H
#define VOMS_AC_H

#include <openssl/asn1.h>
// #include <openssl/x509.h>
#include <openssl/x509v3.h>
// #include <openssl/stack.h>
// #include <openssl/safestack.h>

#include <openssl/asn1t.h>

typedef struct ACDIGEST {
  ASN1_ENUMERATED *type;
  ASN1_OBJECT     *oid;
  X509_ALGOR      *algor;
  ASN1_BIT_STRING *digest;
} AC_DIGEST;

typedef struct ACIS {
  GENERAL_NAMES* issuer;
  ASN1_INTEGER  *serial;
  ASN1_BIT_STRING *uid;
} AC_IS;

typedef struct ACFORM {
  GENERAL_NAMES* names;
  AC_IS         *is;
  AC_DIGEST     *digest;
} AC_FORM;

typedef struct ACACI {
  GENERAL_NAMES *names;
  AC_FORM       *form;
} AC_ACI;

typedef struct ACHOLDER {
  AC_IS         *baseid;
  STACK_OF(GENERAL_NAMES) *name;
  AC_DIGEST     *digest;
} AC_HOLDER;

typedef struct ACVAL {
  ASN1_GENERALIZEDTIME *notBefore;
  ASN1_GENERALIZEDTIME *notAfter;
} AC_VAL;

typedef ASN1_STRING AC_IETFATTRVAL;

typedef struct ACIETFATTR {
  GENERAL_NAMES   *names;
  STACK_OF(AC_IETFATTRVAL) *values;
} AC_IETFATTR;

typedef struct ACTARGET {
  GENERAL_NAME *name;
  GENERAL_NAME *group;
  AC_IS        *cert;
} AC_TARGET;
 
typedef struct ACTARGETS {
  STACK_OF(AC_TARGET) *targets;
} AC_TARGETS;

typedef struct ACATTRIBUTE {
  ASN1_OCTET_STRING *name;
  ASN1_OCTET_STRING *qualifier;
  ASN1_OCTET_STRING *value;
} AC_ATTRIBUTE;

typedef struct ACATTHOLDER {
  GENERAL_NAMES *grantor;
  STACK_OF(AC_ATTRIBUTE) *attributes;
} AC_ATT_HOLDER;

typedef struct ACFULLATTRIBUTES {
  STACK_OF(AC_ATT_HOLDER) *providers;
} AC_FULL_ATTRIBUTES;

typedef struct ACATTR {
  ASN1_OBJECT * type;
  STACK_OF(AC_IETFATTR) *ietfattr;
  STACK_OF(AC_FULL_ATTRIBUTES) *fullattributes;
} AC_ATTR;

typedef struct ACINFO {
  ASN1_INTEGER             *version;
  AC_HOLDER                *holder;
  AC_FORM                  *form;
  X509_ALGOR               *alg;
  ASN1_INTEGER             *serial;
  AC_VAL                   *validity;
  STACK_OF(AC_ATTR)        *attrib;
  ASN1_BIT_STRING          *id;
  STACK_OF(X509_EXTENSION) *exts;
} AC_INFO;

typedef struct ACC {
  AC_INFO         *acinfo;
  X509_ALGOR      *sig_alg;
  ASN1_BIT_STRING *signature;
} AC;

typedef struct ACSEQ {
  STACK_OF(AC) *acs;
} AC_SEQ;

typedef struct ACCERTS {
  STACK_OF(X509) *stackcert;
} AC_CERTS;

DECLARE_ASN1_FUNCTIONS(AC_DIGEST)
DECLARE_ASN1_FUNCTIONS(AC_IS)
DECLARE_ASN1_FUNCTIONS(AC_FORM)
DECLARE_ASN1_FUNCTIONS(AC_ACI)
DECLARE_ASN1_FUNCTIONS(AC_HOLDER)
DECLARE_ASN1_FUNCTIONS(AC_VAL)
DECLARE_ASN1_FUNCTIONS_name(ASN1_STRING, AC_IETFATTRVAL)
DECLARE_ASN1_FUNCTIONS(AC_IETFATTR)
DECLARE_ASN1_FUNCTIONS(AC_TARGET)
DECLARE_ASN1_FUNCTIONS(AC_TARGETS)
DECLARE_ASN1_FUNCTIONS(AC_ATTRIBUTE)
DECLARE_ASN1_FUNCTIONS(AC_ATT_HOLDER)
DECLARE_ASN1_FUNCTIONS(AC_FULL_ATTRIBUTES)
DECLARE_ASN1_FUNCTIONS(AC_ATTR)
DECLARE_ASN1_FUNCTIONS(AC_INFO)
DECLARE_ASN1_FUNCTIONS(AC)
DECLARE_ASN1_FUNCTIONS(AC_SEQ)
DECLARE_ASN1_FUNCTIONS(AC_CERTS)

#endif
