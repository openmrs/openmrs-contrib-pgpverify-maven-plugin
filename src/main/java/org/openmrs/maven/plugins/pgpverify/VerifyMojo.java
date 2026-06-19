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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;

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
public class VerifyMojo extends AbstractVerifyMojo {

	/** Projects in the current reactor; their artifacts are never verified (not yet published). */
	@Parameter(defaultValue = "${reactorProjects}", readonly = true)
	private List<MavenProject> reactorProjects;

	@Override
	protected List<ArtifactRef> collectArtifacts() {
		Set<String> reactorKeys = reactorKeys();

		List<ArtifactRef> refs = new ArrayList<>();
		for (Artifact artifact : project.getArtifacts()) {
			if (reactorKeys.contains(reactorKey(artifact))) {
				continue; // sibling module built in this reactor, not a published artifact
			}
			refs.add(new ArtifactRef(artifact.getGroupId(), artifact.getArtifactId(), artifact.getVersion(),
					artifact.getClassifier(), artifact.getType(), artifact.getFile(), artifact.isSnapshot()));
		}
		return refs;
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
}