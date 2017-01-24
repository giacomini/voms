#include "ac.h"
#include <openssl/asn1.h>
#include <cassert>

STACK_OF(CONF_VALUE)* i2v_targets(
    X509V3_EXT_METHOD const* method
  , void* ext
  , STACK_OF(CONF_VALUE)* extlist)
{
  // to be implemented
  return 0;
}

void* v2i_targets(
    X509V3_EXT_METHOD const* method
  , X509V3_CTX* ctx
  , STACK_OF(CONF_VALUE) *values)
{
  AC_TARGETS* result = AC_TARGETS_new();

  for (int i = 0; i != sk_CONF_VALUE_num(values); ++i)
  {
    CONF_VALUE* nv = sk_CONF_VALUE_value(values, i);
    AC_TARGET* target = AC_TARGET_new();
    GENERAL_NAME* name = target->name;
    name->type = GEN_URI;
    name->d.ia5 = ASN1_IA5STRING_new();
    ASN1_STRING_set(name->d.ia5, nv->name, -1);
    sk_AC_TARGET_push(result->targets, target);
  }

  return result;
}

X509V3_EXT_METHOD ac_targets_meth = {
  NID_target_information, 0, ASN1_ITEM_ref(AC_TARGETS),
  0, 0, 0, 0,
  NULL, NULL,
  (X509V3_EXT_I2V)i2v_targets,
  (X509V3_EXT_V2I)v2i_targets,
  NULL, NULL,
  NULL,
};

int main()
{
  X509V3_EXT_add(&ac_targets_meth);

  STACK_OF(X509_EXTENSION)* exts = sk_X509_EXTENSION_new_null();
  X509_EXTENSION* ext = X509V3_EXT_conf(0, 0, "targetInformation", "pippo, pluto");
  assert(ext && "X509V3_EXT_conf failed");
  int num = sk_X509_EXTENSION_push(exts, ext);
  assert(num && "sk_X509_EXTENSION_push");

  sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
  X509V3_EXT_cleanup();
}
