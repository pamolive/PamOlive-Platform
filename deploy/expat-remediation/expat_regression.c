/* Synthetic bounded Linux test, MIT-licensed; reset case follows upstream acc_tests.c.
 * It does not reproduce the multi-gigabyte CVE-2026-118370 trigger. */
#include <expat_config.h>
#include <expat.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <sys/resource.h>


/* Guarded pre-fix witness: never perform the out-of-bounds callback read itself.
 * The after-build must never request such a read. Synthetic 10-byte upstream case. */
struct bounded_decoder {
  const char *buffer;
  size_t size;
  int unsafe_call;
};

static int guarded_convert(void *data, const char *s) {
  struct bounded_decoder *info = data;
  const uintptr_t start = (uintptr_t)info->buffer, position = (uintptr_t)s;
  if (position < start || position - start >= info->size) {
    info->unsafe_call = 1;
    return -1;
  }
  const unsigned char lead = (unsigned char)s[0];
  const size_t length = lead == 0xC3 ? 2 : (lead == 0xA9 ? 4 : 1);
  if (length > info->size - (position - start)) {
    info->unsafe_call = 1;
    return -1;
  }
  return lead == 0xC3 && (unsigned char)s[1] == 0xA9 ? 0x49 : -1;
}

static int guarded_encoding(void *data, const XML_Char *name, XML_Encoding *info) {
  const XML_Char expected[] = {'x', '-', 'q', '5', 0};
  for (size_t i = 0; i < sizeof(expected) / sizeof(expected[0]); ++i)
    assert(name[i] == expected[i]);
  for (int i = 0; i < 256; ++i)
    info->map[i] = i < 128 ? i : -1;
  info->map[0xC3] = -2;
  info->map[0xA9] = -4;
  info->convert = guarded_convert;
  info->data = data;
  info->release = NULL;
  return XML_STATUS_OK;
}

static void advisory_124317(int before) {
  const char doc[] = "<?xml \xC3\xA9?>";
  const size_t size = strlen(doc);
  const XML_Char encoding[] = {'x', '-', 'q', '5', 0};
  assert(size == 10);
  XML_Parser parser = XML_ParserCreate(encoding);
  assert(parser != NULL);
  char *buffer = XML_GetBuffer(parser, (int)size);
  assert(buffer != NULL);
  memcpy(buffer, doc, size);
  struct bounded_decoder info = {buffer, size, 0};
  XML_SetUnknownEncodingHandler(parser, guarded_encoding, &info);
  assert(XML_ParseBuffer(parser, (int)size, XML_TRUE) == XML_STATUS_ERROR);
  assert(info.unsafe_call == before);
  XML_ParserFree(parser);
}

int main(int argc, char **argv) {
  struct rlimit cpu = {3, 3}, mem = {128UL * 1024 * 1024, 128UL * 1024 * 1024};
  assert(setrlimit(RLIMIT_CPU, &cpu) == 0);
  assert(setrlimit(RLIMIT_AS, &mem) == 0);
  assert(strcmp(XML_ExpatVersion(), "expat_2.10.0") == 0);
  assert(XML_MAJOR_VERSION == 2 && XML_MINOR_VERSION == 10 && XML_MICRO_VERSION == 0);
  assert(argc == 1 || (argc == 2 && strcmp(argv[1], "--advisory-124317-before") == 0));
  if (argc == 2) {
    advisory_124317(1);
    return 0;
  }
  const char *doc = "<!DOCTYPE r [<!ENTITY e 'general entity'>]><r>&e;</r>";
  XML_Parser parser = XML_ParserCreate(NULL);
  assert(parser != NULL);
  assert(XML_SetPropertyDouble(parser, XML_PROP_BILLION_LAUGHS_MAXIMUM_AMPLIFICATION, 1.0) == XML_PROP_ERROR_NONE);
  assert(XML_SetPropertyUInt64(parser, XML_PROP_BILLION_LAUGHS_ACTIVATION_THRESHOLD, 0) == XML_PROP_ERROR_NONE);
  for (int i = 0; i < 32; ++i) {
    assert(XML_Parse(parser, doc, (int)strlen(doc), XML_TRUE) == XML_STATUS_ERROR);
    assert(XML_GetErrorCode(parser) == XML_ERROR_AMPLIFICATION_LIMIT_BREACH);
    assert(XML_ParserReset(parser, NULL) == XML_STATUS_OK);
  }
  XML_ParserFree(parser);
  /* CVE-2026-115506 char-ref/accounting paths, including CDATA/comment/PI follow-up. */
  const char *documents[] = {
    "<!DOCTYPE r [<!ENTITY e '&#x20ac;&#x20ac;&#x20ac;'>]><r>&e;</r>",
    "<!DOCTYPE r [<!ENTITY e '<![CDATA[xxxxxxxx]]>'>]><r>&e;</r>",
    "<!DOCTYPE r [<!ENTITY e '<!--xxxxxxxx--><?p xxxxxxxx?>'>]><r>&e;</r>"
  };
  for (unsigned i = 0; i < sizeof(documents)/sizeof(documents[0]); ++i) {
    parser = XML_ParserCreate(NULL);
    assert(parser != NULL);
    assert(XML_SetPropertyDouble(parser, XML_PROP_BILLION_LAUGHS_MAXIMUM_AMPLIFICATION, 1.0) == XML_PROP_ERROR_NONE);
    assert(XML_SetPropertyUInt64(parser, XML_PROP_BILLION_LAUGHS_ACTIVATION_THRESHOLD, 0) == XML_PROP_ERROR_NONE);
    assert(XML_Parse(parser, documents[i], (int)strlen(documents[i]), XML_TRUE) == XML_STATUS_ERROR);
    assert(XML_GetErrorCode(parser) == XML_ERROR_AMPLIFICATION_LIMIT_BREACH);
    XML_ParserFree(parser);
  }
  /* CVE-2026-117610: first empty nonfinal parse on external entity. */
  parser = XML_ParserCreate(NULL);
  XML_Parser external = XML_ExternalEntityParserCreate(parser, NULL, NULL);
  assert(external != NULL);
  assert(XML_Parse(external, "", 0, XML_FALSE) == XML_STATUS_OK);
  assert(XML_Parse(external, "<!ELEMENT r EMPTY>", 18, XML_TRUE) == XML_STATUS_OK);
  XML_ParserFree(external);
  XML_ParserFree(parser);
  advisory_124317(0);
  return 0;
}
