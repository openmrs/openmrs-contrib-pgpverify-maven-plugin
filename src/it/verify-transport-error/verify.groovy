/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */

// The build must fail because the .asc could not be resolved (a transport error),
// NOT because it was treated as a missing/unsigned artifact - failOnMissingSignature
// is false here, so a "missing" classification would have let the build pass.
String log = new File(basedir, "build.log").text
assert log.contains("could not resolve PGP signature") :
		"expected the build to fail on an unresolvable signature (transport error); build log:\n" + log
assert !log.contains("no PGP signature (.asc) found") :
		"transport error was misclassified as a missing signature and skipped; build log:\n" + log
return true