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

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * A whitelisted groupId and the PGP key fingerprints allowed to sign its artifacts. An artifact
 * matches this group when its groupId equals {@link #groupId} or is a subgroup of it.
 */
public class Group {

	private String groupId;

	/** One or more PGP key fingerprints, separated by commas or whitespace. */
	private String keys;

	public Group() {
	}

	public Group(String groupId, String keys) {
		this.groupId = groupId;
		this.keys = keys;
	}

	public String getGroupId() {
		return groupId;
	}

	public void setGroupId(String groupId) {
		this.groupId = groupId;
	}

	public String getKeys() {
		return keys;
	}

	public void setKeys(String keys) {
		this.keys = keys;
	}

	/** Returns the configured fingerprints, upper-cased and stripped of any {@code 0x} prefix and whitespace. */
	public Set<String> normalizedFingerprints() {
		if (keys == null || keys.trim().isEmpty()) {
			return Collections.emptySet();
		}
		Set<String> result = new LinkedHashSet<>();
		for (String key : keys.split("[,\\s]+")) {
			String normalized = key.trim().replaceAll("\\s", "");
			if (normalized.startsWith("0x") || normalized.startsWith("0X")) {
				normalized = normalized.substring(2);
			}
			normalized = normalized.toUpperCase();
			if (!normalized.isEmpty()) {
				result.add(normalized);
			}
		}
		return result;
	}
}
