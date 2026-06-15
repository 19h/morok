// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — test support.  The single translation unit that provides doctest's
// implementation and `main()`.  Every test executable compiles exactly this
// file for its entry point; the test translation units only include the header
// for registration, avoiding duplicate-symbol clashes.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
