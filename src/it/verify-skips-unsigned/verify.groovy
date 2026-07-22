/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */

// The build succeeded (invoker.buildResult=success); confirm it succeeded for the
// right reason: the unsigned whitelisted artifact was skipped, not silently ignored
// as non-whitelisted.
String log = new File(basedir, "build.log").text
assert log.contains("no PGP signature (.asc) found") :
		"expected the unsigned whitelisted artifact to be logged as skipped; build log:\n" + log
return true
