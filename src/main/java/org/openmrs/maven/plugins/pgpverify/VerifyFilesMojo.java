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
import java.util.List;

import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

/**
 * Verifies PGP signatures of an explicit, caller-supplied list of already-downloaded artifacts.
 *
 * <p>Unlike the {@code verify} goal - which inspects the resolved dependency tree - this goal
 * verifies the {@link #artifacts} it is handed, resolving each {@code .asc} signature from the
 * project's remote repositories. It is meant for tools that obtain artifacts outside Maven's
 * dependency resolution (for example the OpenMRS SDK, which downloads modules and WARs into a
 * distribution directory) and want to delegate the trust check rather than re-implement it. The
 * goal is not bound to a lifecycle phase; invoke it explicitly. All key-source configuration and
 * defaults are shared with {@code verify}.
 */
@Mojo(name = "verify-files", threadSafe = true)
public class VerifyFilesMojo extends AbstractVerifyMojo {

	/** The already-downloaded artifacts to verify, each with its file and Maven coordinates. */
	@Parameter
	private List<ArtifactItem> artifacts = new ArrayList<>();

	@Override
	protected List<ArtifactRef> collectArtifacts() throws MojoExecutionException {
		List<ArtifactRef> refs = new ArrayList<>();
		for (ArtifactItem item : artifacts) {
			requireCoordinates(item);
			boolean snapshot = item.getVersion().endsWith("-SNAPSHOT");
			refs.add(new ArtifactRef(item.getGroupId(), item.getArtifactId(), item.getVersion(),
					item.getClassifier(), item.getType(), item.getFile(), snapshot));
		}
		return refs;
	}

	private static void requireCoordinates(ArtifactItem item) throws MojoExecutionException {
		if (isBlank(item.getGroupId()) || isBlank(item.getArtifactId()) || isBlank(item.getVersion())
				|| isBlank(item.getType()) || item.getFile() == null) {
			throw new MojoExecutionException(
					"Each <artifact> requires file, groupId, artifactId, version and type; got: " + describe(item));
		}
	}

	private static boolean isBlank(String value) {
		return value == null || value.trim().isEmpty();
	}

	private static String describe(ArtifactItem item) {
		return "file=" + item.getFile() + ", groupId=" + item.getGroupId() + ", artifactId="
				+ item.getArtifactId() + ", version=" + item.getVersion() + ", type=" + item.getType();
	}
}