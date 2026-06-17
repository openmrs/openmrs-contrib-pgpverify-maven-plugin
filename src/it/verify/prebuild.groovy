/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */

// Build the inputs for an offline end-to-end verification: an ephemeral GPG key
// signs a dummy dependency laid out in a local file repository, and its public
// key plus a keys file naming the fingerprint are exported for the IT to verify.

import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

// gpg-agent's socket path (homedir + /S.gpg-agent...) must stay under the
// ~104 char AF_UNIX limit, so keep GNUPGHOME short by using the temp dir.
File gpgHome = new File(System.getProperty("java.io.tmpdir"), "omrs-pgpverify-it-gpg")
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

// 1. ephemeral key (no passphrase)
File batch = new File(fixtures, "gen-key.batch")
batch.text = """%no-protection
Key-Type: RSA
Key-Length: 2048
Name-Real: OpenMRS PGPVerify IT
Name-Email: it@example.org
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
println "[pgpverify-it] ephemeral signing key: 0x" + fingerprint

// 2. dummy artifact + pom, detach-sign the jar
File repoDir = new File(fixtures, "repo/org/openmrs/ittest/signed-dep/1.0.0")
repoDir.mkdirs()
File jar = new File(repoDir, "signed-dep-1.0.0.jar")
new ZipOutputStream(new FileOutputStream(jar)).withCloseable { zos ->
	zos.putNextEntry(new ZipEntry("META-INF/MANIFEST.MF"))
	zos.write("Manifest-Version: 1.0\n".getBytes("UTF-8"))
	zos.closeEntry()
}
new File(repoDir, "signed-dep-1.0.0.pom").text = """<project>
	<modelVersion>4.0.0</modelVersion>
	<groupId>org.openmrs.ittest</groupId>
	<artifactId>signed-dep</artifactId>
	<version>1.0.0</version>
	<packaging>jar</packaging>
</project>
"""
gpg(["--local-user", fingerprint, "--armor", "--detach-sign",
     "--output", new File(repoDir, "signed-dep-1.0.0.jar.asc").absolutePath, jar.absolutePath])

// 3. export the public key and 4. write the keys file
gpg(["--armor", "--export", "--output", new File(fixtures, "pubkey.asc").absolutePath, fingerprint])
new File(fixtures, "keys.list").text = "org.openmrs.ittest = 0x" + fingerprint + "\n"

return true