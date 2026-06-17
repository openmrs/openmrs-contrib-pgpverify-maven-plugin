/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */

// Negative path: an ephemeral key signs the dependency and its real public key is
// supplied so the key resolves, but the keys file pins a DIFFERENT fingerprint, so
// verification must reject it as untrusted and fail the build.

import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

File gpgHome = new File(System.getProperty("java.io.tmpdir"), "omrs-pgpverify-it-untrusted-gpg")
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

File fixtures = new File(basedir, "it-fixtures")
fixtures.mkdirs()

File batch = new File(fixtures, "gen-key.batch")
batch.text = """%no-protection
Key-Type: RSA
Key-Length: 2048
Name-Real: OpenMRS PGPVerify Untrusted IT
Name-Email: untrusted-it@example.org
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

// The dependency is regenerated with a fresh key every run, so purge any copy a
// previous run cached in the isolated local repository - otherwise the resolver
// serves the stale .asc against this run's freshly exported key and the build
// could fail for the wrong reason. `clean verify` wipes target/ and hides this;
// an incremental `mvn verify` would not.
File cached = new File(localRepositoryPath, "org/openmrs/ittest/untrusted-dep")
if (cached.exists()) {
	cached.deleteDir()
}
File repoDir = new File(fixtures, "repo/org/openmrs/ittest/untrusted-dep/1.0.0")
repoDir.mkdirs()
File jar = new File(repoDir, "untrusted-dep-1.0.0.jar")
new ZipOutputStream(new FileOutputStream(jar)).withCloseable { zos ->
	zos.putNextEntry(new ZipEntry("META-INF/MANIFEST.MF"))
	zos.write("Manifest-Version: 1.0\n".getBytes("UTF-8"))
	zos.closeEntry()
}
new File(repoDir, "untrusted-dep-1.0.0.pom").text = """<project>
	<modelVersion>4.0.0</modelVersion>
	<groupId>org.openmrs.ittest</groupId>
	<artifactId>untrusted-dep</artifactId>
	<version>1.0.0</version>
	<packaging>jar</packaging>
</project>
"""
gpg(["--local-user", fingerprint, "--armor", "--detach-sign",
     "--output", new File(repoDir, "untrusted-dep-1.0.0.jar.asc").absolutePath, jar.absolutePath])

// Export the real key (so it resolves) but pin a different fingerprint (so it is untrusted).
gpg(["--armor", "--export", "--output", new File(fixtures, "pubkey.asc").absolutePath, fingerprint])
new File(fixtures, "keys.list").text = "org.openmrs.ittest = 0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF\n"

return true