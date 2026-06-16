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

		List<Group> effectiveGroups = groups.isEmpty()
				? Collections.singletonList(new Group(OPENMRS_GROUP, OPENMRS_BOT_KEY))
				: groups;

		SignatureVerifier verifier = new SignatureVerifier(new KeyServerClient(keyServer, getLog()));

		List<String> errors = new ArrayList<>();
		int checked = 0;

		for (Artifact artifact : project.getArtifacts()) {
			Set<String> allowed = allowedFingerprintsFor(artifact.getGroupId(), effectiveGroups);
			if (allowed.isEmpty()) {
				continue; // not whitelisted -> ignored, never failed
			}

			checked++;
			String coords = artifact.getGroupId() + ":" + artifact.getArtifactId() + ":" + artifact.getVersion();

			File data = artifact.getFile();
			if (data == null || !data.isFile()) {
				errors.add(coords + " - artifact file was not resolved");
				continue;
			}

			File asc = resolveSignature(artifact);
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

	private File resolveSignature(Artifact artifact) {
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
			return null;
		}
	}
}
