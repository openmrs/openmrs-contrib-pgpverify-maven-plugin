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

import org.apache.maven.plugins.annotations.Parameter;

/**
 * An already-downloaded artifact to verify with the {@code verify-files} goal: its local
 * {@link #file} plus the Maven coordinates used to resolve the matching {@code .asc} signature.
 * Shaped to mirror the {@code artifactItems} of the maven-dependency-plugin, so a tool that
 * downloads artifacts (e.g. the OpenMRS SDK) can hand the same coordinates to this goal.
 *
 * <p>The {@code @Parameter} annotations mirror that plugin's convention and document intent. Note
 * that Maven only enforces {@code required}/{@code defaultValue} for top-level mojo parameters, not
 * for fields of a nested configuration object, so {@code VerifyFilesMojo} still validates these
 * explicitly.
 */
public class ArtifactItem {

	/** The local artifact file to verify. */
	@Parameter(required = true)
	private File file;

	@Parameter(required = true)
	private String groupId;

	@Parameter(required = true)
	private String artifactId;

	@Parameter(required = true)
	private String version;

	/** Optional classifier; omit for the main artifact. */
	@Parameter
	private String classifier;

	/** Artifact type / packaging; defaults to {@code jar}. */
	@Parameter(defaultValue = "jar")
	private String type = "jar";

	public File getFile() {
		return file;
	}

	public void setFile(File file) {
		this.file = file;
	}

	public String getGroupId() {
		return groupId;
	}

	public void setGroupId(String groupId) {
		this.groupId = groupId;
	}

	public String getArtifactId() {
		return artifactId;
	}

	public void setArtifactId(String artifactId) {
		this.artifactId = artifactId;
	}

	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

	public String getClassifier() {
		return classifier;
	}

	public void setClassifier(String classifier) {
		this.classifier = classifier;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}
}