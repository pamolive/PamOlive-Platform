/* Test-only character traits for the complete Expat C test runner.
 * MIT license. Not installed, not included by libexpat, no heap allocation. */
#ifndef PAMOLIVE_TEST_CHARACTER_SUPPORT_H
#define PAMOLIVE_TEST_CHARACTER_SUPPORT_H

#include <limits.h>
#include <stddef.h>
#include "expat.h"

#if defined(XML_UNICODE_WCHAR_T)
#  include <wchar.h>
#  define XML_FMT_STR "ls"
#  define XML_FMT_LSTR "ls"
#  define XCS(s) _XCS(s)
#  define _XCS(s) L##s
#  define XCLS(s) _XCLS(s)
#  define _XCLS(s) L##s
#  define XML_CHAR_DIAG_BUFFER(name)
#  define XML_CHAR_DIAG(value, buffer) (value)
#elif defined(XML_UNICODE)
#  if defined(__cplusplus)
#    error "ushort test port is C11 only: C++ char16_t is a distinct type"
#  elif !defined(__STDC_VERSION__) || (__STDC_VERSION__ < 201112L)
#    error "ushort test port requires a C11 compiler, never wchar substitution"
#  else
#    include <uchar.h>
_Static_assert(CHAR_BIT == 8, "8-bit bytes required by this UTF16 test port");
_Static_assert(sizeof(XML_Char) == 2, "XML_Char must remain UTF16/2");
_Static_assert(sizeof(XML_LChar) == 1, "XML_LChar must remain narrow/1");
_Static_assert(_Generic((XML_Char *)0, unsigned short *: 1, default: 0),
               "XML_Char must remain unsigned short");
_Static_assert(_Generic((XML_LChar *)0, char *: 1, default: 0),
               "XML_LChar must remain char");
_Static_assert(_Generic((char16_t *)0, XML_Char *: 1, default: 0),
               "C11 char16_t must be type-compatible, not merely the same width");
#    define XCS(s) _XCS(s)
#    define _XCS(s) u##s
#    define XCLS(s) s
#    define XML_FMT_STR "s"
#    define XML_FMT_LSTR "s"
#    define XML_CHAR_DIAG_BUFFER(name) char name[96]
#    define XML_CHAR_DIAG(value, buffer) \
       test_xmlchar_diagnostic((value), (buffer), sizeof(buffer))

/* Diagnostic code units, not a Unicode codec. At most 16 units are read;
 * output is bounded and NUL-terminated. Each call has its own caller buffer,
 * so evaluating two printf arguments cannot overwrite the other argument.
 * No malloc, printf, locale operation or OOM-hook counter is touched. */
static inline const char *
test_xmlchar_diagnostic(const XML_Char *value, char *buffer, size_t capacity) {
  static const char hex[] = "0123456789abcdef";
  size_t written = 0;
  size_t index = 0;
  if (!buffer || capacity == 0)
    return "";
  buffer[0] = 0;
  if (!value) {
    static const char absent[] = "(null)";
    while (written + 1 < capacity && absent[written]) {
      buffer[written] = absent[written];
      written++;
    }
    buffer[written] = 0;
    return buffer;
  }
  while (index < 16 && capacity - written >= (written ? 6u : 5u)
         && value[index]) {
    const unsigned int unit = value[index++];
    if (written)
      buffer[written++] = ' ';
    for (int shift = 12; shift >= 0; shift -= 4)
      buffer[written++] = hex[(unit >> shift) & 15u];
  }
  /* Mark truncation without reading a seventeenth unit. */
  if ((index == 16 || (index < 16 && value[index]))
      && capacity - written >= 4) {
    buffer[written++] = '.';
    buffer[written++] = '.';
    buffer[written++] = '.';
  }
  buffer[written] = 0;
  return buffer;
}
#  endif
#else
#  define XML_FMT_STR "s"
#  define XML_FMT_LSTR "s"
#  define XCS(s) s
#  define XCLS(s) s
#  define XML_CHAR_DIAG_BUFFER(name)
#  define XML_CHAR_DIAG(value, buffer) (value)
#endif

/* Version/error strings use XML_LChar, which differs from XML_Char for
 * Debian's UTF16 ushort ABI. Comparing them must never alias a Char string. */
static inline int
test_lcscmp(const XML_LChar *left, const XML_LChar *right) {
  while (*left && *left == *right) {
    left++;
    right++;
  }
  return (*left > *right) - (*left < *right);
}
#endif
