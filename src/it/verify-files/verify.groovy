/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */

// A successful build is not enough: assert the file handed to verify-files was actually
// verified, so a regression that silently skips verification cannot pass.
String log = new File(basedir, "build.log").text
assert log.contains("OK   org.openmrs.ittest:signed-dep:1.0.0 signed by") :
		"expected the signed artifact to be verified; build log:\n" + log
return true