/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */

// The non-whitelisted dependency was resolved (the build would have failed at
// dependency resolution otherwise) yet must be passed over: the plugin reports
// zero whitelisted artifacts checked, and the build succeeds despite the
// dependency being unsigned. A regression that started verifying every
// dependency - the treadmill this plugin exists to avoid - would fail here.
String log = new File(basedir, "build.log").text
assert log.contains("checked 0 whitelisted artifact(s)") :
		"expected the non-whitelisted dependency to be ignored; build log:\n" + log
return true
