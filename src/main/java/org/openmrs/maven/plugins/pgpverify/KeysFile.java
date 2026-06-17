/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.maven.plugins.pgpverify;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Loads the whitelisted groups and their allowed key fingerprints from an external file, so the
 * trusted code-signing key can be rotated by editing a file rather than recompiling the plugin.
 *
 * <p>This file is the plugin's trust anchor, so it is only loaded from a local path or an
 * {@code https} URL; plaintext {@code http} is rejected. Format - one mapping per line, blank lines
 * and {@code #} comments ignored:
 * <pre>
 * org.openmrs = 0xCA12619FDE8CD6A93FAFE458A6F9608DCC73473F
 * com.example = 0xAAAA..., 0xBBBB...   # multiple keys allowed
 * </pre>
 */
final class KeysFile {

	private KeysFile() {
	}

	static List<Group> load(String location) throws IOException {
		if (location.startsWith("http://")) {
			throw new IOException("Refusing to load the keys file over plaintext HTTP; "
					+ "use a local path or an https URL: " + location);
		}
		List<Group> groups = new ArrayList<>();
		try (BufferedReader reader = new BufferedReader(
				new InputStreamReader(Locations.open(location), StandardCharsets.UTF_8))) {
			String line;
			int number = 0;
			while ((line = reader.readLine()) != null) {
				number++;
				int comment = line.indexOf('#');
				if (comment >= 0) {
					line = line.substring(0, comment);
				}
				line = line.trim();
				if (line.isEmpty()) {
					continue;
				}
				int equals = line.indexOf('=');
				if (equals < 0) {
					throw new IOException("Invalid keys file at line " + number
							+ " (expected 'groupId = fingerprints'): " + line);
				}
				String groupId = line.substring(0, equals).trim();
				if (groupId.isEmpty()) {
					throw new IOException("Invalid keys file at line " + number + " (empty groupId): " + line);
				}
				Group group = new Group(groupId, line.substring(equals + 1).trim());
				if (group.normalizedFingerprints().isEmpty()) {
					throw new IOException("Invalid keys file at line " + number
							+ " (no key fingerprints for " + groupId + "): " + line);
				}
				groups.add(group);
			}
		}
		return groups;
	}
}