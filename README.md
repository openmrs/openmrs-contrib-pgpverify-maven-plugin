# OpenMRS PGP Verify Maven Plugin

Verifies the PGP signatures of resolved dependencies — but only for a **whitelist of groupIds** —
against the keys allowed to sign them. Anything outside the whitelist is ignored.

This is deliberately narrower than [pgpverify-maven-plugin](https://www.simplify4u.org/pgpverify-maven-plugin/),
which verifies the *entire* dependency tree and therefore needs every third-party artifact (and
version) enumerated in a keys map. By scoping to the groups OpenMRS actually controls, this plugin:

- is **version-independent** — `org.openmrs.*` is signed by the OpenMRS Bot key regardless of which
  platform version a build resolves, so it works across platform versions with no per-version map;
- needs **no third-party signature coverage** — those artifacts are simply not checked here;
- can run **always** in a module or distribution build without breaking on dependency changes.

It answers the one question OpenMRS can attest to: *was this OpenMRS artifact signed by the OpenMRS
key?* Third-party integrity is left to repository trust + checksums, as everywhere else.

## Usage

```xml
<plugin>
    <groupId>org.openmrs.maven.plugins</groupId>
    <artifactId>openmrs-pgpverify-maven-plugin</artifactId>
    <version><!-- latest release --></version>
    <executions>
        <execution>
            <goals>
                <goal>verify</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

With no configuration it verifies `org.openmrs.*` against the OpenMRS Bot code-signing key
(`CA12619FDE8CD6A93FAFE458A6F9608DCC73473F`). The `verify` goal binds to the `verify` phase.

### Whitelisting more groups

```xml
<configuration>
    <groups>
        <group>
            <groupId>org.openmrs</groupId>
            <keys>0xCA12619FDE8CD6A93FAFE458A6F9608DCC73473F</keys>
        </group>
        <group>
            <groupId>com.example.trusted</groupId>
            <keys>0xFINGERPRINT_ONE, 0xFINGERPRINT_TWO</keys>
        </group>
    </groups>
</configuration>
```

A group matches an artifact when the artifact's groupId equals the configured `groupId` or is a
subgroup of it. Each `<group>` lists the fingerprint(s) allowed to sign it.

### Parameters

| Parameter | Property | Default | Purpose |
| --- | --- | --- | --- |
| `groups` | — | `org.openmrs` → Bot key | Whitelisted groupIds and their allowed key fingerprints. |
| `keyServer` | `openmrs.pgpverify.keyServer` | `https://keyserver.ubuntu.com` | Where public keys are fetched by id. |
| `failOnMissingSignature` | `openmrs.pgpverify.failOnMissingSignature` | `true` | Fail when a whitelisted artifact has no `.asc`. |
| `skip` | `openmrs.pgpverify.skip` | `false` | Skip the check. |

## How it verifies

For each whitelisted artifact it resolves the `.asc`, reads the signing key id, fetches that public
key from the key server, and **pins** it — the key is trusted only if its fingerprint (or its master
key's fingerprint) is in the configured allowed set, so the key server cannot substitute a different
key under the same identity. The signature is then verified cryptographically with Bouncy Castle.

## Release

The POM stays at `X.Y.Z-SNAPSHOT`; the **Release** workflow (`workflow_dispatch`) runs
`maven-release-plugin` via the shared OpenMRS release script. Required secrets:
`OMRS_RELEASE_BOT_APP_ID`, `OMRS_RELEASE_BOT_PRIVATE_KEY`, `MAVEN_REPO_USERNAME`,
`MAVEN_REPO_API_KEY`, and optionally `MAVEN_GPG_PRIVATE_KEY` / `MAVEN_GPG_PASSPHRASE` to sign the
released plugin jar.
