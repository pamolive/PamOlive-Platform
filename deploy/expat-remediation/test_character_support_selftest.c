/* Linux CI only, synthetic test of the ACTUAL header used by runtests. MIT. */
#if defined(NDEBUG)
#  error "helper self-test requires assertions"
#endif
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "test_character_support.h"

int main(void) {
  static const XML_Char literal[] = XCS("A\x00e9\xd83d\xde00");
  static const XML_Char concatenated[] = XCS("a") XCS("b");
  static const XML_Char expected[] = {0x41, 0xe9, 0xd83d, 0xde00, 0};
  _Static_assert(sizeof(XCS('x')) == sizeof(XML_Char), "typed character literal");
  _Static_assert(sizeof(literal) == sizeof(expected), "static UTF16 literal extent");
  assert(memcmp(literal, expected, sizeof(expected)) == 0);
  assert(concatenated[0] == 'a' && concatenated[1] == 'b' && concatenated[2] == 0);
  assert(XCS('\n') == 10);
  assert(test_lcscmp(XCLS("expat_2.10.0"), XCLS("expat_2.10.0")) == 0);
  assert(test_lcscmp(XCLS("a"), XCLS("b")) < 0);
  assert(test_lcscmp(XCLS("b"), XCLS("a")) > 0);
  struct { char before; char data[96]; char after; } area = {'x', {0}, 'y'};
  assert(strcmp(test_xmlchar_diagnostic(literal, area.data, sizeof(area.data)),
                "0041 00e9 d83d de00") == 0);
  assert(area.before == 'x' && area.after == 'y');
  assert(strcmp(test_xmlchar_diagnostic(NULL, area.data, sizeof(area.data)), "(null)") == 0);
  assert(strcmp(test_xmlchar_diagnostic(XCS(""), area.data, sizeof(area.data)), "") == 0);
  for (size_t cap = 0; cap <= sizeof(area.data); cap++) {
    memset(area.data, 'z', sizeof(area.data));
    const char *result = test_xmlchar_diagnostic(literal, area.data, cap);
    if (cap == 0)
      assert(area.data[0] == 'z' && result[0] == 0);
    else {
      assert(memchr(area.data, 0, cap));
      for (size_t i = cap; i < sizeof(area.data); i++)
        assert(area.data[i] == 'z');
    }
    assert(area.before == 'x' && area.after == 'y');
  }
  /* Exact 16-unit array has NO terminator: the bounded formatter must not
   * inspect a seventeenth unit. ASan may additionally check this in Linux. */
  const XML_Char bounded[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
  const char *text = test_xmlchar_diagnostic(bounded, area.data, sizeof(area.data));
  assert(strlen(text) < sizeof(area.data) && strstr(text, "...") != NULL);
  XML_CHAR_DIAG_BUFFER(first);
  XML_CHAR_DIAG_BUFFER(second);
  char both[256];
  const int count = snprintf(both, sizeof(both), "%" XML_FMT_STR "/%" XML_FMT_STR,
      XML_CHAR_DIAG(XCS("A"), first), XML_CHAR_DIAG(XCS("B"), second));
  assert(count > 0 && strcmp(both, "0041/0042") == 0);
  puts("{\"schema\":\"pamolive.expat-ushort-helper/1\",\"passed\":true,\"helper_uses_heap\":false}");
  return 0;
}
