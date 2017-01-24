#include "ac.h"
#include <openssl/asn1.h>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <cassert>
#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <iterator>
#include <iomanip>

typedef unsigned char octet;

struct octet_span
{
  octet const* p;
  int l;
};

std::ostream& operator<<(std::ostream& os, octet_span const& s)
{
  assert(s.p != nullptr && s.l >= 0);

  auto p = s.p;
  if (s.l > 0) {
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<int>(*p);
    ++p;
  }
  for ( ; p != s.p + s.l; ++p) {
    std::cout << ' ' << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<int>(*p);
  }

  return os;
}

int i2d_AC_fp(FILE *fp, AC* s)
{
    return ASN1_item_i2d_fp(ASN1_ITEM_rptr(AC), fp, s);
}

template<class T> struct TD;

IMPLEMENT_ASN1_PRINT_FUNCTION(AC)

int main()
{ 
  // auto n = ASN1_NULL_new();
  // std::cout << n << '\n';

  // auto ac = AC_new();
  // auto out = BIO_new_fp(stdout, BIO_NOCLOSE);

  std::ifstream f("ac.der", std::ios::binary);
  assert(f && "failed to open file");
  f.unsetf(std::ios::skipws);

  std::vector<octet> const data(
      (std::istream_iterator<octet>(f))
    , (std::istream_iterator<octet>())
  );
  assert(data.size() == 2272);
  // std::cout << data.size() << '\n';

#if 0  
  {
    auto p = data.data() + 236;
    auto l = 220;
    auto o = d2i_AC_ATTR(0, &p, l);
    assert(o != nullptr);
  }
  {
    auto p = data.data() + 233;
    auto l = 223;
    auto o = d2i_AC_ATTRS(0, &p, l);
    assert(o != nullptr);
  }
  {
    auto p = data.data() + 239;
    auto l = 12;
    auto o = d2i_ASN1_OBJECT(0, &p, l);
    assert(o != nullptr);
  }
  {
    auto p = data.data() + 259;
    auto l = 38;
    auto o = d2i_GENERAL_NAME(0, &p, l);
    assert(o != nullptr);
  }
  {
    auto p = data.data() + 300;
    auto l = 36;
    auto o = d2i_ASN1_OCTET_STRING(0, &p, l);
    assert(o != nullptr);
  }
  {
    auto p = data.data() + 254;
    auto l = 202;
    auto o = d2i_AC_IETFATTR(0, &p, l);
    assert(o != nullptr);
  }
  {
    auto p = data.data() + 4;
    auto l = 1992;
    auto o = d2i_AC_INFO(0, &p, l);
    assert(o != nullptr);
  }
  {
    auto p = data.data() + 8;
    auto l = 3;
    auto o = d2i_ASN1_INTEGER(0, &p, l);
    assert(o != nullptr);
  }
  {
    auto p = data.data() + 11;
    auto l = 56;
    auto o = d2i_AC_HOLDER(0, &p, l);
    assert(o != nullptr);
    assert(o->baseid != nullptr);
  }
  {
    auto p = data.data() + 13;
    auto l = 47;
    auto o = d2i_AC_IS(0, &p, l);  // cannot read due to tag?
    //    assert(o != nullptr);
  }
  {
    auto p = data.data() + 15;
    auto l = 49;
    auto o = d2i_GENERAL_NAMES(0, &p, l);
    assert(o != nullptr);
  }
  {
    auto p = data.data() + 67;
    auto l = 97;
    auto o = d2i_AC_FORM(0, &p, l);  // cannot read due to tag?
    //assert(o != nullptr);
  }
  {
    auto p = data.data() + 67;
    auto q = p;
    long l;
    int t, c;
    auto i = ASN1_get_object(&q, &l, &t, &c, 1000);
    // std::cout << i << ' ' << std::distance(p, q) << ' ' << l
    //           << ' ' << t << ' ' << c << '\n';
  }
  {
    auto p = data.data() + 69;
    auto l = 95;
    auto o = d2i_GENERAL_NAMES(0, &p, l);
    assert(o != nullptr);
  }
  {
    auto p = data.data() + 164;
    auto l = 15;
    auto o = d2i_X509_ALGOR(0, &p, l);
    assert(o != nullptr);
  }
  {
    auto p = data.data() + 179;
    auto l = 18;
    auto o = d2i_ASN1_INTEGER(0, &p, l);
    assert(o != nullptr);
  }
  {
    auto p = data.data() + 197;
    auto l = 36;
    auto o = d2i_AC_VAL(0, &p, l);
    assert(o != nullptr);
  }
  {
    auto p = data.data() + 1996;
    auto l = 15;
    auto o = d2i_X509_ALGOR(0, &p, l);
    assert(o != nullptr);
  }
  {
    auto p = data.data() + 2011;
    auto l = 261;
    auto o = d2i_ASN1_BIT_STRING(0, &p, l);
    assert(o != nullptr);
  }
  {
    auto p = data.data() + 456;
    auto l = 1540;
    auto o = d2i_X509_EXTENSIONS(0, &p, l);
    assert(o != nullptr);
  }
#endif
  {
    auto p = data.data();
    auto l = 2272;
    auto o = d2i_AC(0, &p, l);
    assert(o != nullptr);
    std::cout << o << '\n';
    AC_free(o);
    AC_free(o);
    // AC_print_ctx(out, o, 0, 0);
    
    // FILE* f = fopen("ac-out.der", "wb");
    // assert(f);
    // auto e = i2d_AC_fp(f, o);
    // assert(e);
  }
}
