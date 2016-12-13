#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <iostream>
#include <cassert>
#include <vector>
#include <cstring>
#include <fstream>
#include <iterator>

struct O1
{
  ASN1_INTEGER* i;
  ASN1_INTEGER* j;
};

struct O2
{
  ASN1_INTEGER* i;
};

struct O3
{
  ASN1_INTEGER* i;
};

struct S
{
  O1* o1;
  O2* o2;
  O3* o3;
};

DECLARE_ASN1_FUNCTIONS(O1)
DECLARE_ASN1_FUNCTIONS(O2)
DECLARE_ASN1_FUNCTIONS(O3)
DECLARE_ASN1_FUNCTIONS(S)

ASN1_SEQUENCE(O1) = {
  ASN1_SIMPLE(O1, i, ASN1_INTEGER),
  ASN1_SIMPLE(O1, j, ASN1_INTEGER)
} ASN1_SEQUENCE_END(O1)

ASN1_SEQUENCE(O2) = {
  ASN1_SIMPLE(O2, i, ASN1_INTEGER)
} ASN1_SEQUENCE_END(O2)

ASN1_SEQUENCE(O3) = {
  ASN1_SIMPLE(O3, i, ASN1_INTEGER)
} ASN1_SEQUENCE_END(O3)

ASN1_SEQUENCE(S) = {
  ASN1_EXP_OPT(S, o1, O1, 0),
  ASN1_EXP_OPT(S, o2, O2, 1),
  ASN1_EXP_OPT(S, o3, O3, 2)
} ASN1_SEQUENCE_END(S)

IMPLEMENT_ASN1_FUNCTIONS(O1)
IMPLEMENT_ASN1_FUNCTIONS(O2)
IMPLEMENT_ASN1_FUNCTIONS(O3)
IMPLEMENT_ASN1_FUNCTIONS(S)

DEFINE_STACK_OF(ASN1_OCTET_STRING);
typedef STACK_OF(ASN1_OCTET_STRING) Strings;

// DECLARE_ASN1_FUNCTIONS(Strings);

// ASN1_ITEM_TEMPLATE(Strings) =
//     ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, Strings, ASN1_OCTET_STRING)
// ASN1_ITEM_TEMPLATE_END(Strings)

// IMPLEMENT_ASN1_FUNCTIONS(Strings);

// int i2d_Strings_fp(FILE *fp, Strings* o)
// {
//     return ASN1_item_i2d_fp(ASN1_ITEM_rptr(Strings), fp, o);
// }

int i2d_O1_fp(FILE *fp, O1* o)
{
    return ASN1_item_i2d_fp(ASN1_ITEM_rptr(O1), fp, o);
}

int i2d_S_fp(FILE *fp, S* s)
{
    return ASN1_item_i2d_fp(ASN1_ITEM_rptr(S), fp, s);
}

struct A
{
  GENERAL_NAMES* names;
  Strings* values;
};

DECLARE_ASN1_FUNCTIONS(A);

ASN1_SEQUENCE(A) = {
  ASN1_IMP_SEQUENCE_OF(A, names, GENERAL_NAME, 0),
  ASN1_SEQUENCE_OF(A, values, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(A)

  // ASN1_IMP(A, values, Strings, 0)
  // ASN1_IMP_OPT(A, names, GENERAL_NAMES, 0)//,

IMPLEMENT_ASN1_FUNCTIONS(A)

int i2d_A_fp(FILE *fp, A* s)
{
    return ASN1_item_i2d_fp(ASN1_ITEM_rptr(A), fp, s);
}

int main()
{
  FILE* f = fopen("s.der", "wb");
  assert(f);

  auto a = A_new();
  auto gens = sk_GENERAL_NAME_new_null();
  auto gen = GENERAL_NAME_new();
  auto ia5 = ASN1_IA5STRING_new();
  auto e = ASN1_STRING_set(ia5, "test.vo://vgrid02.cnaf.infn.it:15000", -1);
  assert(e);
  GENERAL_NAME_set0_value(gen, GEN_URI, ia5);
  sk_GENERAL_NAME_push(gens, gen);
  a->names = gens;

  // auto strings = Strings_new();
  auto strings = sk_ASN1_OCTET_STRING_new_null();
  {
    char const s[] = "/test.vo/Role=NULL/Capability=NULL";
    auto str = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(str, reinterpret_cast<unsigned char const*>(s), strlen(s));
    sk_ASN1_OCTET_STRING_push(strings, str);
  }
  {
    char const s[] = "/test.vo/G1/Role=NULL/Capability=NULL";
    auto str = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(str, reinterpret_cast<unsigned char const*>(s), strlen(s));
    sk_ASN1_OCTET_STRING_push(strings, str);
  }
  {
    char const s[] = "/test.vo/G2/Role=NULL/Capability=NULL";
    auto str = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(str, reinterpret_cast<unsigned char const*>(s), strlen(s));
    sk_ASN1_OCTET_STRING_push(strings, str);
  }
  {
    char const s[] = "/test.vo/G2/G3/Role=NULL/Capability=NULL";
    auto str = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(str, reinterpret_cast<unsigned char const*>(s), strlen(s));
    sk_ASN1_OCTET_STRING_push(strings, str);
  }
  a->values = strings;

  i2d_A_fp(f, a);

  fclose(f);

  {
    using octet = unsigned char;
    
    std::ifstream f("s.der", std::ios::binary);
    assert(f && "failed to open file");
    f.unsetf(std::ios::skipws);

    std::vector<octet> const data(
        (std::istream_iterator<octet>(f))
      , (std::istream_iterator<octet>())
    );
    
    auto p = data.data();
    auto l = 20200;
    auto o = d2i_A(0, &p, l);
    assert(o != nullptr);
  }
}

#if 0
{
  auto o = O1_new();
  assert(o);
  o->i = ASN1_INTEGER_new();
  assert(o->i);
  auto e = ASN1_INTEGER_set(o->i, 0x1234);
  assert(e);
  o->j = ASN1_INTEGER_new();
  assert(o->j);
  e = ASN1_INTEGER_set(o->j, 0x5678);
  assert(e);
  auto s = S_new();
  assert(s);
  s->o1 = o;
}
#endif
