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
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResolutionException;
import org.eclipse.aether.resolution.ArtifactResult;
import org.eclipse.aether.transfer.ArtifactNotFoundException;
import org.bouncycastle.openpgp.PGPException;

/**
 * Shared base for the PGP verification goals. Holds the key-source configuration and the
 * verification engine, and drives a common loop: for every {@link ArtifactRef} returned by the
 * concrete goal whose groupId matches a configured {@link Group}, the artifact's {@code .asc}
 * signature is resolved, verified cryptographically, and the signing key fingerprint is checked
 * against the keys allowed for that group. Artifacts outside the whitelist are ignored, never
 * failed.
 *
 * <p>Subclasses differ only in where the artifacts come from: {@link VerifyMojo} verifies the
 * resolved dependency tree, while {@link VerifyFilesMojo} verifies an explicit, caller-supplied
 * list of files.
 */
abstract class AbstractVerifyMojo extends AbstractMojo {

	static final String OPENMRS_GROUP = "org.openmrs";

	static final String OPENMRS_BOT_KEY = "0xCA12619FDE8CD6A93FAFE458A6F9608DCC73473F";

	@Parameter(defaultValue = "${project}", readonly = true, required = true)
	protected MavenProject project;

	@Parameter(defaultValue = "${repositorySystemSession}", readonly = true, required = true)
	protected RepositorySystemSession repoSession;

	@Component
	protected RepositorySystem repoSystem;

	/**
	 * Whitelisted groups and the PGP key fingerprints allowed to sign them. When omitted, defaults
	 * to {@code org.openmrs} signed by the OpenMRS Bot code-signing key.
	 */
	@Parameter
	protected List<Group> groups = new ArrayList<>();

	/**
	 * Location (file path or http(s) URL) of an external keys file mapping groupIds to allowed key
	 * fingerprints, so the trusted key can be rotated without recompiling. Format, one per line:
	 * {@code groupId = 0xFINGERPRINT[, 0xFINGERPRINT...]}. Merged with any inline {@link #groups}.
	 */
	@Parameter(property = "openmrs.pgpverify.keysFile")
	protected String keysFile;

	/**
	 * File paths or http(s) URLs of public key rings to verify against. Consulted before the key
	 * server, enabling offline verification. When a key is found here the key server is not used.
	 */
	@Parameter
	protected List<String> keyRings = new ArrayList<>();

	/** Verify SNAPSHOT artifacts too. Off by default - snapshots are typically unsigned. */
	@Parameter(property = "openmrs.pgpverify.verifySnapshots", defaultValue = "false")
	protected boolean verifySnapshots;

	/** Key server used to fetch public keys by id. */
	@Parameter(property = "openmrs.pgpverify.keyServer", defaultValue = "https://keyserver.ubuntu.com")
	protected String keyServer;

	/** Fail when a whitelisted artifact has no {@code .asc} signature. */
	@Parameter(property = "openmrs.pgpverify.failOnMissingSignature", defaultValue = "true")
	protected boolean failOnMissingSignature;

	/** Skip execution entirely. */
	@Parameter(property = "openmrs.pgpverify.skip", defaultValue = "false")
	protected boolean skip;

	public final void execute() throws MojoExecutionException, MojoFailureException {
		if (skip) {
			getLog().info("Skipping PGP verification (openmrs.pgpverify.skip=true)");
			return;
		}

		List<Group> effectiveGroups = effectiveGroups();
		SignatureVerifier verifier = buildVerifier();

		List<String> errors = new ArrayList<>();
		int checked = 0;

		for (ArtifactRef ref : collectArtifacts()) {
			Set<String> allowed = allowedFingerprintsFor(ref.groupId, effectiveGroups);
			if (allowed.isEmpty()) {
				continue; // not whitelisted -> ignored, never failed
			}
			if (!verifySnapshots && ref.snapshot) {
				continue; // snapshots are typically unsigned
			}

			checked++;
			verifyOne(ref, allowed, verifier, errors);
		}

		getLog().info("PGP verification checked " + checked + " whitelisted artifact(s)");

		if (!errors.isEmpty()) {
			for (String error : errors) {
				getLog().error(error);
			}
			throw new MojoFailureException("PGP signature verification failed for " + errors.size()
					+ " artifact(s)");
		}
	}

	/** The artifacts this goal should consider; filtering and verification are handled by the base. */
	protected abstract List<ArtifactRef> collectArtifacts() throws MojoExecutionException;

	private List<Group> effectiveGroups() throws MojoExecutionException {
		List<Group> effectiveGroups = new ArrayList<>(groups);
		if (keysFile != null && !keysFile.trim().isEmpty()) {
			try {
				effectiveGroups.addAll(KeysFile.load(keysFile.trim()));
			}
			catch (IOException e) {
				throw new MojoExecutionException("Failed to load keys file: " + keysFile, e);
			}
		}
		if (effectiveGroups.isEmpty()) {
			effectiveGroups = Collections.singletonList(new Group(OPENMRS_GROUP, OPENMRS_BOT_KEY));
		}
		return effectiveGroups;
	}

	private SignatureVerifier buildVerifier() throws MojoExecutionException {
		KeyServerClient keyServerClient = (keyServer == null || keyServer.trim().isEmpty())
				? null
				: new KeyServerClient(keyServer.trim(), getLog());

		boolean noKeyRings = keyRings == null
				|| keyRings.stream().allMatch(ring -> ring == null || ring.trim().isEmpty());
		if (noKeyRings && keyServerClient == null) {
			throw new MojoExecutionException(
					"No PGP key source configured: set the keyServer and/or keyRings parameters");
		}

		try {
			return new SignatureVerifier(new PublicKeySource(keyRings, keyServerClient, getLog()));
		}
		catch (IOException | PGPException e) {
			throw new MojoExecutionException("Failed to load PGP key rings", e);
		}
	}

	private void verifyOne(ArtifactRef ref, Set<String> allowed, SignatureVerifier verifier, List<String> errors) {
		File data = ref.file;
		if (data == null || !data.isFile()) {
			errors.add(ref.coords + " - artifact file was not resolved");
			return;
		}

		File asc;
		try {
			asc = resolveSignature(ref);
		}
		catch (ArtifactResolutionException e) {
			// Could not determine signature state (network, server error, ...); never treat this
			// as "unsigned" - that would let a transient failure pass verification silently.
			errors.add(ref.coords + " - could not resolve PGP signature: " + e.getMessage());
			return;
		}
		if (asc == null) {
			String message = ref.coords + " - no PGP signature (.asc) found";
			if (failOnMissingSignature) {
				errors.add(message);
			} else {
				getLog().warn(message);
			}
			return;
		}

		try {
			String signer = verifier.verify(data, asc, allowed);
			getLog().info("OK   " + ref.coords + " signed by " + signer);
		}
		catch (VerificationException e) {
			errors.add(ref.coords + " - " + e.getMessage());
		}
	}

	private Set<String> allowedFingerprintsFor(String groupId, List<Group> grps) {
		Set<String> result = new HashSet<>();
		for (Group group : grps) {
			String gid = group.getGroupId();
			if (gid != null && (groupId.equals(gid) || groupId.startsWith(gid + "."))) {
				result.addAll(group.normalizedFingerprints());
			}
		}
		return result;
	}

	/**
	 * @return the resolved {@code .asc} file, or {@code null} if the signature genuinely does not
	 *         exist in any repository
	 * @throws ArtifactResolutionException if resolution failed for any other reason (network, server
	 *         error, ...), which must not be mistaken for an absent signature
	 */
	private File resolveSignature(ArtifactRef ref) throws ArtifactResolutionException {
		String classifier = ref.classifier == null ? "" : ref.classifier;
		DefaultArtifact signatureArtifact = new DefaultArtifact(ref.groupId, ref.artifactId,
				classifier, ref.type + ".asc", ref.version);

		List<RemoteRepository> repositories = project.getRemoteProjectRepositories();
		ArtifactRequest request = new ArtifactRequest(signatureArtifact, repositories, null);
		try {
			ArtifactResult result = repoSystem.resolveArtifact(repoSession, request);
			return result.getArtifact().getFile();
		}
		catch (ArtifactResolutionException e) {
			if (isGenuinelyMissing(e)) {
				return null;
			}
			throw e;
		}
	}

	/** True only when every failure was an "artifact not found", i.e. the signature does not exist. */
	private static boolean isGenuinelyMissing(ArtifactResolutionException e) {
		if (e.getResults() == null) {
			return false;
		}
		for (ArtifactResult result : e.getResults()) {
			if (result.getExceptions().isEmpty()) {
				return false;
			}
			for (Throwable cause : result.getExceptions()) {
				if (!(cause instanceof ArtifactNotFoundException)) {
					return false;
				}
			}
		}
		return true;
	}

	/**
	 * An artifact to verify, decoupled from how it was discovered. Built from a resolved Maven
	 * {@link org.apache.maven.artifact.Artifact} by {@link VerifyMojo} or from an
	 * {@link ArtifactItem} by {@link VerifyFilesMojo}.
	 */
	protected static final class ArtifactRef {

		final String groupId;

		final String artifactId;

		final String version;

		final String classifier;

		final String type;

		final File file;

		final boolean snapshot;

		final String coords;

		ArtifactRef(String groupId, String artifactId, String version, String classifier, String type,
				File file, boolean snapshot) {
			this.groupId = groupId;
			this.artifactId = artifactId;
			this.version = version;
			this.classifier = classifier;
			this.type = type;
			this.file = file;
			this.snapshot = snapshot;
			this.coords = groupId + ":" + artifactId + ":" + version;
		}
	}
}