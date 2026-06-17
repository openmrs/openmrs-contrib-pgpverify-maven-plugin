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
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Collections;
import java.util.List;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class KeysFileTest {

	@Rule
	public TemporaryFolder folder = new TemporaryFolder();

	private String write(String content) throws IOException {
		File file = folder.newFile();
		Files.write(file.toPath(), content.getBytes(StandardCharsets.UTF_8));
		return file.getAbsolutePath();
	}

	@Test
	public void loadsSingleMapping() throws Exception {
		List<Group> groups = KeysFile.load(write("org.openmrs = 0xABCDEF\n"));
		assertEquals(1, groups.size());
		assertEquals("org.openmrs", groups.get(0).getGroupId());
		assertEquals(Collections.singleton("ABCDEF"), groups.get(0).normalizedFingerprints());
	}

	@Test
	public void ignoresCommentsAndBlankLinesAndStripsInlineComments() throws Exception {
		List<Group> groups = KeysFile.load(write("# header\n\norg.openmrs = 0xABCDEF # rotated 2026\n"));
		assertEquals(1, groups.size());
		assertEquals(Collections.singleton("ABCDEF"), groups.get(0).normalizedFingerprints());
	}

	@Test
	public void supportsMultipleKeysOnOneLine() throws Exception {
		List<Group> groups = KeysFile.load(write("com.example = 0xAAAA, 0xBBBB\n"));
		assertTrue(groups.get(0).normalizedFingerprints().contains("AAAA"));
		assertTrue(groups.get(0).normalizedFingerprints().contains("BBBB"));
	}

	@Test
	public void loadsMultipleMappings() throws Exception {
		List<Group> groups = KeysFile.load(write("org.openmrs = 0xAAAA\ncom.example = 0xBBBB\n"));
		assertEquals(2, groups.size());
	}

	@Test
	public void malformedLineThrowsWithLineNumber() throws Exception {
		try {
			KeysFile.load(write("# comment\n\norg.openmrs 0xAAAA\n"));
			fail("expected IOException for a line without '='");
		}
		catch (IOException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("line 3"));
		}
	}

	@Test
	public void emptyGroupIdThrows() throws Exception {
		try {
			KeysFile.load(write("= 0xAAAA\n"));
			fail("expected IOException for an empty groupId");
		}
		catch (IOException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("line 1"));
		}
	}

	@Test
	public void emptyFingerprintsThrows() throws Exception {
		try {
			KeysFile.load(write("org.openmrs =\n"));
			fail("expected IOException for a mapping with no fingerprints");
		}
		catch (IOException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("line 1"));
		}
	}

	@Test
	public void refusesPlaintextHttp() throws Exception {
		try {
			KeysFile.load("http://example.org/keys.list");
			fail("expected IOException refusing plaintext HTTP for the trust anchor");
		}
		catch (IOException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("HTTP"));
		}
	}
}