/* Synthetic exported Linux ushort ABI smoke; not a full C++ Expat test corpus.
 * MIT license. Explicit XML_Char arrays, no char16_t cast, alias or temporary. */
#include <expat_config.h>
#include <expat.h>
#include <climits>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <type_traits>
#include <sys/resource.h>
#include <unistd.h>

#if !defined(XML_UNICODE) || defined(XML_UNICODE_WCHAR_T)
#error "this smoke requires the unchanged Linux unsigned-short ABI"
#endif
static_assert(CHAR_BIT == 8 && sizeof(XML_Char) == 2 && sizeof(XML_LChar) == 1, "XML widths");
static_assert(std::is_same<XML_Char, unsigned short>::value, "XML_Char identity");
static_assert(std::is_same<XML_LChar, char>::value, "XML_LChar identity");
static_assert(sizeof(wchar_t) == 4, "no short-wchar substitution on this Linux target");

#define REQUIRE(x) do { if (!(x)) { std::fprintf(stderr, "UTF16_ABI_%d\n", __LINE__); return 1; } } while (0)
struct State { unsigned starts = 0, ends = 0, count = 0; XML_Char text[2] = {}; bool valid = true; };
static const XML_Char name[] = {0x00e9, 0};
static const XML_Char attribute[] = {0x0061, 0};
static const XML_Char text[] = {0xd83d, 0xde00};
static bool equal(const XML_Char* a, const XML_Char* b) {
  if (!a || !b) return false;
  while (*a && *a == *b) { a++; b++; }
  return *a == *b;
}
extern "C" {
static void XMLCALL start(void* data, const XML_Char* element, const XML_Char** attributes) {
  State& state = *static_cast<State*>(data);
  state.valid = state.valid && equal(element, name) && attributes && attributes[0] &&
      equal(attributes[0], attribute) && attributes[1] && equal(attributes[1], name) && !attributes[2];
  state.starts++;
}
static void XMLCALL end(void* data, const XML_Char* element) {
  State& state = *static_cast<State*>(data);
  state.valid = state.valid && equal(element, name);
  state.ends++;
}
static void XMLCALL chars(void* data, const XML_Char* value, int length) {
  State& state = *static_cast<State*>(data);
  if (length < 0 || static_cast<unsigned>(length) > 2 - state.count) { state.valid = false; return; }
  for (int i = 0; i < length; i++) state.text[state.count++] = value[i];
}
}
static bool parse(const char* bytes, size_t size) {
  State state;
  XML_Parser parser = XML_ParserCreate(nullptr);
  if (!parser) return false;
  XML_SetUserData(parser, &state);
  XML_SetElementHandler(parser, start, end);
  XML_SetCharacterDataHandler(parser, chars);
  bool ok = true;
  for (size_t i = 0; i < size; i++) {
    if (XML_Parse(parser, bytes + i, 1, i + 1 == size ? XML_TRUE : XML_FALSE) != XML_STATUS_OK) {
      ok = false; break;
    }
  }
  XML_ParserFree(parser);
  return ok && state.valid && state.starts == 1 && state.ends == 1 && state.count == 2 &&
      state.text[0] == text[0] && state.text[1] == text[1];
}
int main() {
  const rlimit cpu = {3, 3}, memory = {128UL * 1024 * 1024, 128UL * 1024 * 1024};
  REQUIRE(setrlimit(RLIMIT_CPU, &cpu) == 0 && setrlimit(RLIMIT_AS, &memory) == 0);
  alarm(5);
  REQUIRE(std::strcmp(XML_ExpatVersion(), "expat_2.10.0") == 0);
  bool c2 = false, l1 = false, unicode = false, wchar = false;
  const XML_Feature* features = XML_GetFeatureList();
  REQUIRE(features);
  for (; features->feature != XML_FEATURE_END; features++) {
    if (features->feature == XML_FEATURE_SIZEOF_XML_CHAR) c2 = features->value == 2;
    if (features->feature == XML_FEATURE_SIZEOF_XML_LCHAR) l1 = features->value == 1;
    if (features->feature == XML_FEATURE_UNICODE) unicode = true;
    if (features->feature == XML_FEATURE_UNICODE_WCHAR_T) wchar = true;
  }
  REQUIRE(c2 && l1 && unicode && !wchar);
  static const char utf8[] = "<\xc3\xa9 a='\xc3\xa9'>\xf0\x9f\x98\x80</\xc3\xa9>";
  REQUIRE(parse(utf8, sizeof(utf8) - 1));
  static const XML_Char units[] = {'<',0xe9,' ','a','=','\'',0xe9,'\'','>',
      0xd83d,0xde00,'<','/',0xe9,'>'};
  char utf16le[2 + 2 * (sizeof(units) / sizeof(units[0]))] = {};
  utf16le[0] = static_cast<char>(0xff); utf16le[1] = static_cast<char>(0xfe);
  for (size_t i = 0; i < sizeof(units) / sizeof(units[0]); i++) {
    utf16le[2 + 2*i] = static_cast<char>(units[i] & 0xff);
    utf16le[3 + 2*i] = static_cast<char>(units[i] >> 8);
  }
  REQUIRE(parse(utf16le, sizeof(utf16le)));
  std::puts("{\"schema\":\"pamolive.expat-wide-exported-abi/1\",\"passed\":true,\"XML_Char\":2,\"XML_LChar\":1,\"wchar_t\":4,\"cpp_full_suite\":false}");
  return 0;
}
