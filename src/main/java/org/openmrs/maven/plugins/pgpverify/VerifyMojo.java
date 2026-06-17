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

import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
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
 * Verifies PGP signatures of resolved dependencies for a whitelist of groupIds.
 *
 * <p>For every resolved artifact whose groupId matches a configured {@link Group}, the artifact's
 * {@code .asc} signature is resolved, verified cryptographically, and the signing key fingerprint
 * is checked against the keys allowed for that group. Artifacts outside the whitelist are ignored,
 * never failed - so the check stays version-independent and does not need to enumerate the
 * third-party dependency tree.
 */
@Mojo(name = "verify", defaultPhase = LifecyclePhase.VERIFY,
      requiresDependencyResolution = ResolutionScope.TEST, threadSafe = true)
public class VerifyMojo extends AbstractMojo {

	static final String OPENMRS_GROUP = "org.openmrs";

	static final String OPENMRS_BOT_KEY = "0xCA12619FDE8CD6A93FAFE458A6F9608DCC73473F";

	@Parameter(defaultValue = "${project}", readonly = true, required = true)
	private MavenProject project;

	@Parameter(defaultValue = "${repositorySystemSession}", readonly = true, required = true)
	private RepositorySystemSession repoSession;

	@Component
	private RepositorySystem repoSystem;

	/**
	 * Whitelisted groups and the PGP key fingerprints allowed to sign them. When omitted, defaults
	 * to {@code org.openmrs} signed by the OpenMRS Bot code-signing key.
	 */
	@Parameter
	private List<Group> groups = new ArrayList<>();

	/**
	 * Location (file path or http(s) URL) of an external keys file mapping groupIds to allowed key
	 * fingerprints, so the trusted key can be rotated without recompiling. Format, one per line:
	 * {@code groupId = 0xFINGERPRINT[, 0xFINGERPRINT...]}. Merged with any inline {@link #groups}.
	 */
	@Parameter(property = "openmrs.pgpverify.keysFile")
	private String keysFile;

	/**
	 * File paths or http(s) URLs of public key rings to verify against. Consulted before the key
	 * server, enabling offline verification. When a key is found here the key server is not used.
	 */
	@Parameter
	private List<String> keyRings = new ArrayList<>();

	/** Projects in the current reactor; their artifacts are never verified (not yet published). */
	@Parameter(defaultValue = "${reactorProjects}", readonly = true)
	private List<MavenProject> reactorProjects;

	/** Verify SNAPSHOT artifacts too. Off by default - snapshots are typically unsigned. */
	@Parameter(property = "openmrs.pgpverify.verifySnapshots", defaultValue = "false")
	private boolean verifySnapshots;

	/** Key server used to fetch public keys by id. */
	@Parameter(property = "openmrs.pgpverify.keyServer", defaultValue = "https://keyserver.ubuntu.com")
	private String keyServer;

	/** Fail when a whitelisted artifact has no {@code .asc} signature. */
	@Parameter(property = "openmrs.pgpverify.failOnMissingSignature", defaultValue = "true")
	private boolean failOnMissingSignature;

	/** Skip execution entirely. */
	@Parameter(property = "openmrs.pgpverify.skip", defaultValue = "false")
	private boolean skip;

	public void execute() throws MojoExecutionException, MojoFailureException {
		if (skip) {
			getLog().info("Skipping PGP verification (openmrs.pgpverify.skip=true)");
			return;
		}

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

		KeyServerClient keyServerClient = (keyServer == null || keyServer.trim().isEmpty())
				? null
				: new KeyServerClient(keyServer.trim(), getLog());

		boolean noKeyRings = keyRings == null
				|| keyRings.stream().allMatch(ring -> ring == null || ring.trim().isEmpty());
		if (noKeyRings && keyServerClient == null) {
			throw new MojoExecutionException(
					"No PGP key source configured: set the keyServer and/or keyRings parameters");
		}

		SignatureVerifier verifier;
		try {
			verifier = new SignatureVerifier(new PublicKeySource(keyRings, keyServerClient, getLog()));
		}
		catch (IOException | PGPException e) {
			throw new MojoExecutionException("Failed to load PGP key rings", e);
		}

		Set<String> reactorKeys = reactorKeys();

		List<String> errors = new ArrayList<>();
		int checked = 0;

		for (Artifact artifact : project.getArtifacts()) {
			Set<String> allowed = allowedFingerprintsFor(artifact.getGroupId(), effectiveGroups);
			if (allowed.isEmpty()) {
				continue; // not whitelisted -> ignored, never failed
			}
			if (!verifySnapshots && artifact.isSnapshot()) {
				continue; // snapshots are typically unsigned
			}
			if (reactorKeys.contains(reactorKey(artifact))) {
				continue; // sibling module built in this reactor, not a published artifact
			}

			checked++;
			String coords = artifact.getGroupId() + ":" + artifact.getArtifactId() + ":" + artifact.getVersion();

			File data = artifact.getFile();
			if (data == null || !data.isFile()) {
				errors.add(coords + " - artifact file was not resolved");
				continue;
			}

			File asc;
			try {
				asc = resolveSignature(artifact);
			}
			catch (ArtifactResolutionException e) {
				// Could not determine signature state (network, server error, ...); never treat this
				// as "unsigned" - that would let a transient failure pass verification silently.
				errors.add(coords + " - could not resolve PGP signature: " + e.getMessage());
				continue;
			}
			if (asc == null) {
				String message = coords + " - no PGP signature (.asc) found";
				if (failOnMissingSignature) {
					errors.add(message);
				} else {
					getLog().warn(message);
				}
				continue;
			}

			try {
				String signer = verifier.verify(data, asc, allowed);
				getLog().info("OK   " + coords + " signed by " + signer);
			}
			catch (VerificationException e) {
				errors.add(coords + " - " + e.getMessage());
			}
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

	private Set<String> reactorKeys() {
		Set<String> keys = new HashSet<>();
		if (reactorProjects != null) {
			for (MavenProject reactorProject : reactorProjects) {
				keys.add(reactorProject.getGroupId() + ":" + reactorProject.getArtifactId() + ":"
						+ reactorProject.getVersion());
			}
		}
		return keys;
	}

	private static String reactorKey(Artifact artifact) {
		return artifact.getGroupId() + ":" + artifact.getArtifactId() + ":" + artifact.getBaseVersion();
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
	private File resolveSignature(Artifact artifact) throws ArtifactResolutionException {
		String classifier = artifact.getClassifier() == null ? "" : artifact.getClassifier();
		DefaultArtifact signatureArtifact = new DefaultArtifact(artifact.getGroupId(), artifact.getArtifactId(),
				classifier, artifact.getType() + ".asc", artifact.getVersion());

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
}
