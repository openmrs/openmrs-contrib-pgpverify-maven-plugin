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
import java.util.HashMap;
import java.util.Map;

import org.apache.maven.plugin.logging.Log;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

/**
 * Fetches PGP public keys by key id from an HKP-over-HTTPS key server, caching results for the
 * duration of the build. Returns {@code null} when the server has no such key.
 */
class KeyServerClient {

	private final String baseUrl;

	private final Log log;

	private final Map<Long, PGPPublicKeyRingCollection> cache = new HashMap<>();

	KeyServerClient(String baseUrl, Log log) {
		this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
		this.log = log;
	}

	PGPPublicKeyRingCollection fetchKey(long keyID) throws IOException, PGPException {
		if (cache.containsKey(keyID)) {
			return cache.get(keyID);
		}

		String hexId = String.format("0x%016X", keyID);
		URL url = new URL(baseUrl + "/pks/lookup?op=get&options=mr&search=" + hexId);
		log.debug("Fetching PGP key " + hexId + " from " + url);

		HttpURLConnection connection = (HttpURLConnection) url.openConnection();
		connection.setConnectTimeout(15000);
		connection.setReadTimeout(15000);
		connection.setRequestProperty("Accept", "application/pgp-keys, text/plain");

		int status = connection.getResponseCode();
		if (status == HttpURLConnection.HTTP_NOT_FOUND) {
			cache.put(keyID, null);
			return null;
		}
		if (status != HttpURLConnection.HTTP_OK) {
			throw new IOException("key server returned HTTP " + status + " for " + hexId);
		}

		PGPPublicKeyRingCollection keyRings;
		try (InputStream raw = connection.getInputStream();
				InputStream decoded = PGPUtil.getDecoderStream(raw)) {
			keyRings = new PGPPublicKeyRingCollection(decoded, new JcaKeyFingerprintCalculator());
		}
		cache.put(keyID, keyRings);
		return keyRings;
	}
}
