/* Synthetic bounded Linux test, MIT-licensed; reset case follows upstream acc_tests.c.
 * It does not reproduce the multi-gigabyte CVE-2026-118370 trigger. */
#include <expat_config.h>
#include <expat.h>
#include <assert.h>
#include <string.h>
#include <sys/resource.h>

int main(void) {
  struct rlimit cpu = {3, 3}, mem = {128UL * 1024 * 1024, 128UL * 1024 * 1024};
  assert(setrlimit(RLIMIT_CPU, &cpu) == 0);
  assert(setrlimit(RLIMIT_AS, &mem) == 0);
  assert(strcmp(XML_ExpatVersion(), "expat_2.10.0") == 0);
  assert(XML_MAJOR_VERSION == 2 && XML_MINOR_VERSION == 10 && XML_MICRO_VERSION == 0);
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
  return 0;
}
