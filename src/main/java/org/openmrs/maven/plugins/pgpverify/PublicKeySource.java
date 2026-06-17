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
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.apache.maven.plugin.logging.Log;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

/**
 * Resolves PGP public keys by key id. Locally provided key rings are consulted first; if the key is
 * not found there and a key server is configured, it is fetched from the server. Supplying key rings
 * makes verification work offline. The key material returned here is untrusted - trust is enforced
 * by fingerprint pinning in {@link SignatureVerifier}.
 */
class PublicKeySource {

	private final PGPPublicKeyRingCollection localKeys;

	private final KeyServerClient keyServer;

	private final Log log;

	/**
	 * @param keyRingLocations file paths or http(s) URLs of armored or binary public key rings
	 * @param keyServer        key server client, or {@code null} to disable server lookups
	 */
	PublicKeySource(List<String> keyRingLocations, KeyServerClient keyServer, Log log)
			throws IOException, PGPException {
		this.keyServer = keyServer;
		this.log = log;
		this.localKeys = loadKeyRings(keyRingLocations);
	}

	/**
	 * @return a ring collection containing {@code keyID}, or {@code null} if it cannot be found in
	 *         the local key rings or on the key server
	 */
	PGPPublicKeyRingCollection resolve(long keyID) throws IOException, PGPException {
		if (localKeys != null && localKeys.getPublicKey(keyID) != null) {
			return localKeys;
		}
		if (keyServer != null) {
			return keyServer.fetchKey(keyID);
		}
		return null;
	}

	private PGPPublicKeyRingCollection loadKeyRings(List<String> locations) throws IOException, PGPException {
		if (locations == null || locations.isEmpty()) {
			return null;
		}
		List<PGPPublicKeyRing> rings = new ArrayList<>();
		for (String location : locations) {
			if (location == null || location.trim().isEmpty()) {
				continue;
			}
			log.debug("Loading PGP key ring from " + location);
			try (InputStream raw = Locations.open(location.trim());
					InputStream decoded = PGPUtil.getDecoderStream(raw)) {
				PGPPublicKeyRingCollection collection =
						new PGPPublicKeyRingCollection(decoded, new JcaKeyFingerprintCalculator());
				for (Iterator<PGPPublicKeyRing> it = collection.getKeyRings(); it.hasNext();) {
					rings.add(it.next());
				}
			}
		}
		return rings.isEmpty() ? null : new PGPPublicKeyRingCollection(rings);
	}
}