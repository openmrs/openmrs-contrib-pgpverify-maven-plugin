/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */

// The build must fail on the untrusted key even though failOnMissingSignature=false;
// a trust/verification failure must never be softened by the missing-signature opt-out.
String log = new File(basedir, "build.log").text
assert log.contains("untrusted key") :
		"expected the build to fail because of an untrusted signing key; build log:\n" + log
assert !log.contains("no PGP signature (.asc) found") :
		"a present-but-untrusted signature was misreported as missing; build log:\n" + log
return true
