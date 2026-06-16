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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.Iterator;
import java.util.Set;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.util.encoders.Hex;

/**
 * Verifies a detached PGP signature against an artifact and confirms the signing key is one of the
 * fingerprints trusted for the artifact's group. The public key material is fetched by key id from
 * a key server, then pinned: a fetched key is only trusted if its fingerprint (or that of its
 * master key) is in the allowed set, so the key server cannot substitute an unexpected key.
 */
class SignatureVerifier {

	static {
		java.security.Security.addProvider(new BouncyCastleProvider());
	}

	private final KeyServerClient keyServer;

	SignatureVerifier(KeyServerClient keyServer) {
		this.keyServer = keyServer;
	}

	/**
	 * @return the master key fingerprint that signed the artifact
	 * @throws VerificationException if the signature is missing, invalid, or made by an untrusted key
	 */
	String verify(File dataFile, File signatureFile, Set<String> allowedFingerprints) throws VerificationException {
		try {
			PGPSignature signature = readSignature(signatureFile);

			PGPPublicKeyRingCollection keyRings = keyServer.fetchKey(signature.getKeyID());
			if (keyRings == null) {
				throw new VerificationException("signing key 0x"
						+ String.format("%016X", signature.getKeyID()) + " not found on key server");
			}

			PGPPublicKey signingKey = keyRings.getPublicKey(signature.getKeyID());
			if (signingKey == null) {
				throw new VerificationException("public key for the signature was not found");
			}

			String signingFingerprint = fingerprint(signingKey);
			String masterFingerprint = masterFingerprint(keyRings, signature.getKeyID());
			if (!allowedFingerprints.contains(signingFingerprint)
					&& !allowedFingerprints.contains(masterFingerprint)) {
				throw new VerificationException("signed by untrusted key " + masterFingerprint
						+ " (allowed: " + allowedFingerprints + ")");
			}

			signature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), signingKey);
			try (InputStream in = Files.newInputStream(dataFile.toPath())) {
				byte[] buffer = new byte[8192];
				int read;
				while ((read = in.read(buffer)) > 0) {
					signature.update(buffer, 0, read);
				}
			}

			if (!signature.verify()) {
				throw new VerificationException("signature is INVALID");
			}
			return masterFingerprint;
		}
		catch (IOException | PGPException e) {
			throw new VerificationException("verification error: " + e.getMessage());
		}
	}

	private PGPSignature readSignature(File signatureFile) throws IOException, PGPException, VerificationException {
		try (InputStream in = PGPUtil.getDecoderStream(Files.newInputStream(signatureFile.toPath()))) {
			JcaPGPObjectFactory factory = new JcaPGPObjectFactory(in);
			Object object = factory.nextObject();
			if (object instanceof PGPCompressedData) {
				factory = new JcaPGPObjectFactory(((PGPCompressedData) object).getDataStream());
				object = factory.nextObject();
			}
			if (!(object instanceof PGPSignatureList)) {
				throw new VerificationException("no PGP signature found in .asc file");
			}
			PGPSignatureList signatures = (PGPSignatureList) object;
			if (signatures.isEmpty()) {
				throw new VerificationException("empty PGP signature list");
			}
			return signatures.get(0);
		}
	}

	private static String masterFingerprint(PGPPublicKeyRingCollection keyRings, long keyID) {
		Iterator<PGPPublicKeyRing> rings = keyRings.getKeyRings();
		while (rings.hasNext()) {
			PGPPublicKeyRing ring = rings.next();
			if (ring.getPublicKey(keyID) != null) {
				Iterator<PGPPublicKey> keys = ring.getPublicKeys();
				while (keys.hasNext()) {
					PGPPublicKey key = keys.next();
					if (key.isMasterKey()) {
						return fingerprint(key);
					}
				}
			}
		}
		return null;
	}

	private static String fingerprint(PGPPublicKey key) {
		return Hex.toHexString(key.getFingerprint()).toUpperCase();
	}
}
