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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.util.Collections;

import org.apache.maven.plugin.logging.SystemStreamLog;
import org.junit.Test;

/**
 * Verifies the core signature-checking logic against hermetic fixtures in {@code src/test/resources}
 * (an exported public key, a signed file, and a tampered copy), with no key server or network.
 */
public class SignatureVerifierTest {

	/** Fingerprint of the fixture key that signed {@code artifact.txt.asc}. */
	private static final String TRUSTED_FINGERPRINT = "DF6D7BAB6A7678D1411222680E7B142EFF0239BC";

	private static final String UNTRUSTED_FINGERPRINT = "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF";

	private SignatureVerifier verifier() throws Exception {
		PublicKeySource source = new PublicKeySource(
				Collections.singletonList(resource("test-pubkey.asc").getAbsolutePath()), null, new SystemStreamLog());
		return new SignatureVerifier(source);
	}

	@Test
	public void verifiesSignatureFromTrustedKey() throws Exception {
		String signer = verifier().verify(resource("artifact.txt"), resource("artifact.txt.asc"),
				Collections.singleton(TRUSTED_FINGERPRINT));
		assertEquals(TRUSTED_FINGERPRINT, signer);
	}

	@Test
	public void rejectsSignatureFromUntrustedKey() throws Exception {
		try {
			verifier().verify(resource("artifact.txt"), resource("artifact.txt.asc"),
					Collections.singleton(UNTRUSTED_FINGERPRINT));
			fail("expected VerificationException for an untrusted key");
		}
		catch (VerificationException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("untrusted key"));
		}
	}

	@Test
	public void rejectsTamperedArtifact() throws Exception {
		// The signature was made over artifact.txt; verifying different bytes must fail.
		try {
			verifier().verify(resource("artifact-tampered.txt"), resource("artifact.txt.asc"),
					Collections.singleton(TRUSTED_FINGERPRINT));
			fail("expected VerificationException for a tampered artifact");
		}
		catch (VerificationException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("INVALID"));
		}
	}

	@Test
	public void reportsMissingKeyWhenNoSourceHasIt() throws Exception {
		// No key rings and no key server -> the signing key cannot be resolved.
		SignatureVerifier verifier = new SignatureVerifier(
				new PublicKeySource(Collections.<String>emptyList(), null, new SystemStreamLog()));
		try {
			verifier.verify(resource("artifact.txt"), resource("artifact.txt.asc"),
					Collections.singleton(TRUSTED_FINGERPRINT));
			fail("expected VerificationException when the key is not available");
		}
		catch (VerificationException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("not found"));
		}
	}

	private static File resource(String name) {
		return new File(SignatureVerifierTest.class.getResource("/" + name).getFile());
	}
}