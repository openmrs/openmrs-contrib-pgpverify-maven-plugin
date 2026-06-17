/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */

// Whitelist test: a dependency in a group that is NOT whitelisted is laid out
// unsigned in a local repository. The plugin must ignore it - never resolve a
// signature, never fail - which is the whole point of the groupId whitelist.
// An ephemeral key is exported only to provide a valid key ring and satisfy the
// plugin's "a key source must be configured" precondition; it is never consulted.

import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

// gpg-agent's socket path (homedir + /S.gpg-agent...) must stay under the
// ~104 char AF_UNIX limit, so keep GNUPGHOME short by using the temp dir.
File gpgHome = new File(System.getProperty("java.io.tmpdir"), "omrs-pgpverify-it-ignore-gpg")
if (gpgHome.exists()) {
	gpgHome.deleteDir()
}
gpgHome.mkdirs()
gpgHome.setReadable(false, false); gpgHome.setReadable(true, true)
gpgHome.setExecutable(false, false); gpgHome.setExecutable(true, true)

def gpg = { List<String> args ->
	List<String> cmd = ["gpg", "--homedir", gpgHome.absolutePath, "--batch", "--yes"] + args
	Process p = cmd.execute()
	StringBuilder out = new StringBuilder(), err = new StringBuilder()
	p.consumeProcessOutput(out, err)
	p.waitFor()
	if (p.exitValue() != 0) {
		throw new RuntimeException("gpg " + args + " failed:\n" + err)
	}
	return out.toString()
}

// Fixtures live outside target/ so `mvn clean verify` does not delete them
// between this pre-build script and the verification.
File fixtures = new File(basedir, "it-fixtures")
fixtures.mkdirs()

// Ephemeral key (no passphrase) - only to provide a valid key ring.
File batch = new File(fixtures, "gen-key.batch")
batch.text = """%no-protection
Key-Type: RSA
Key-Length: 2048
Name-Real: OpenMRS PGPVerify Ignore IT
Name-Email: ignore-it@example.org
Expire-Date: 0
%commit
"""
gpg(["--generate-key", batch.absolutePath])

String fingerprint = null
gpg(["--with-colons", "--fingerprint"]).eachLine { line ->
	if (fingerprint == null && line.startsWith("fpr:")) {
		fingerprint = line.split(":")[9]
	}
}
if (fingerprint == null) {
	throw new RuntimeException("could not determine generated key fingerprint")
}

// Unsigned dummy artifact + pom in a NON-whitelisted group (deliberately no .asc).
File repoDir = new File(fixtures, "repo/com/thirdparty/unsigned-dep/1.0.0")
repoDir.mkdirs()
File jar = new File(repoDir, "unsigned-dep-1.0.0.jar")
new ZipOutputStream(new FileOutputStream(jar)).withCloseable { zos ->
	zos.putNextEntry(new ZipEntry("META-INF/MANIFEST.MF"))
	zos.write("Manifest-Version: 1.0\n".getBytes("UTF-8"))
	zos.closeEntry()
}
new File(repoDir, "unsigned-dep-1.0.0.pom").text = """<project>
	<modelVersion>4.0.0</modelVersion>
	<groupId>com.thirdparty</groupId>
	<artifactId>unsigned-dep</artifactId>
	<version>1.0.0</version>
	<packaging>jar</packaging>
</project>
"""

// Export the public key (key ring) and pin only the whitelisted OpenMRS group -
// which the dependency above is NOT in, so it must be ignored.
gpg(["--armor", "--export", "--output", new File(fixtures, "pubkey.asc").absolutePath, fingerprint])
new File(fixtures, "keys.list").text = "org.openmrs.ittest = 0x" + fingerprint + "\n"

return true
