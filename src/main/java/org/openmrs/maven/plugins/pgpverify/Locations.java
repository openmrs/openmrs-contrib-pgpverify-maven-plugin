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

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Opens a key-material location given as a local file path or an http(s) URL. HTTP(S) fetches use
 * connect/read timeouts and reject any non-200 response, so a slow or erroring host fails the build
 * instead of feeding an error-page body into a key/keys parser.
 */
final class Locations {

	private static final int TIMEOUT_MS = 15000;

	private Locations() {
	}

	static InputStream open(String location) throws IOException {
		if (location.startsWith("http://") || location.startsWith("https://")) {
			HttpURLConnection connection = (HttpURLConnection) new URL(location).openConnection();
			connection.setConnectTimeout(TIMEOUT_MS);
			connection.setReadTimeout(TIMEOUT_MS);
			int status = connection.getResponseCode();
			if (status != HttpURLConnection.HTTP_OK) {
				throw new IOException("HTTP " + status + " fetching " + location);
			}
			return connection.getInputStream();
		}
		return Files.newInputStream(Paths.get(location));
	}
}