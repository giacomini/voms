#include "ac.h"
#include <openssl/asn1.h>
#include <stdio.h>
#include <string.h>
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

int main()
{ 
  std::ifstream f("ac.der", std::ios::binary);
  assert(f && "failed to open file");
  f.unsetf(std::ios::skipws);

  std::vector<octet> const data(
      (std::istream_iterator<octet>(f))
    , (std::istream_iterator<octet>())
  );
  std::cout << data.size() << '\n';

  {
    auto p = data.data();
    auto l = data.size();
    AC* ac = d2i_AC(0, &p, l);
    std::cout << "AC: " << ac << '\n';
  }
  {
    auto p = data.data() + 199;
    auto l = 17;
    std::cout << "GENERALIZEDTIME at " << (void*)p
              << " [ " << octet_span{p, l} << " ]: ";
    auto o = d2i_ASN1_GENERALIZEDTIME(0, &p, l);
    std::cout << o << '\n';
  }
  {
    auto p = data.data() + 607;
    auto l = 15;
    std::cout << "UTCTIME at " << (void*)p
              << " [ " << octet_span{p, l} << " ]: ";
    auto o = d2i_ASN1_UTCTIME(0, &p, l);
    std::cout << o << '\n';
  }
  {
    auto p = data.data() + 8;
    auto l = 3;
    std::cout << "INTEGER at " << (void*)p
              << " [ " << octet_span{p, l} << " ]: ";
    auto o = d2i_ASN1_INTEGER(0, &p, l);
    std::cout << o << '\n';
  }
  {
    auto p = data.data() + 197;
    auto l = 36;
    std::cout << "AC_VAL at " << (void*)p
              << " [ " << octet_span{p, l} << " ]: ";
    auto o = d2i_AC_VAL(0, &p, l);
    std::cout << o << '\n';
  }
  {
    auto p = data.data() + 15;
    auto l = 49;
    std::cout << "GENERAL_NAMES at " << (void*)p
              << " [ " << octet_span{p, l} << " ]: ";
    auto o = d2i_GENERAL_NAMES(0, &p, l);
    std::cout << o << '\n';
  }
  {// ???
    auto p = data.data() + 11;
    auto l = 56;
    std::cout << "AC_HOLDER at " << (void*)p
              << " [ " << octet_span{p, l} << " ]: ";
    auto o = d2i_AC_HOLDER(0, &p, l);
    std::cout << o << '\n';
  }
}
