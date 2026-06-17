# OpenMRS PGP Verify Maven Plugin

Verifies PGP signatures of resolved dependencies, but only for a **whitelist of groupIds**.
Anything outside the whitelist is ignored. Unlike [pgpverify-maven-plugin](https://www.simplify4u.org/pgpverify-maven-plugin/)
(which checks the whole dependency tree and needs every third-party artifact enumerated), this just
answers: *was this OpenMRS artifact signed by the OpenMRS key?* — which is version-independent and
safe to run always.

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

With no config it verifies `org.openmrs.*` against the OpenMRS Bot key
(`CA12619FDE8CD6A93FAFE458A6F9608DCC73473F`). The `verify` goal binds to the `verify` phase.

## Configuring

Whitelist more groups inline:

```xml
<configuration>
    <groups>
        <group>
            <groupId>com.example.trusted</groupId>
            <keys>0xFINGERPRINT_ONE, 0xFINGERPRINT_TWO</keys>
        </group>
    </groups>
</configuration>
```

A group matches an artifact when its groupId equals the configured `groupId` or is a subgroup of it.

Or keep the mappings in an external file (`keysFile`) so the key can be rotated without recompiling
— one `groupId = 0xFINGERPRINT[, 0xFINGERPRINT...]` per line, `#` comments allowed. Must be a local
path or `https` URL.

### Parameters

| Parameter | Property | Default | Purpose |
| --- | --- | --- | --- |
| `groups` | — | `org.openmrs` → Bot key | Whitelisted groupIds and their allowed fingerprints. |
| `keysFile` | `openmrs.pgpverify.keysFile` | — | External keys file (local path or `https` URL); merged with `groups`. |
| `keyRings` | — | — | Public key rings (paths or http(s) URLs) consulted before the key server; enables offline verification. |
| `keyServer` | `openmrs.pgpverify.keyServer` | `https://keyserver.ubuntu.com` | Where keys are fetched by id (blank to disable). |
| `failOnMissingSignature` | `openmrs.pgpverify.failOnMissingSignature` | `true` | Fail when a whitelisted artifact has no `.asc`. |
| `verifySnapshots` | `openmrs.pgpverify.verifySnapshots` | `false` | Verify SNAPSHOT artifacts too. |
| `skip` | `openmrs.pgpverify.skip` | `false` | Skip the check. |

## How it verifies

For each whitelisted artifact it resolves the `.asc`, reads the signing key id, and finds that public
key — local `keyRings` first, then the `keyServer`. The key is **pinned**: trusted only if its
fingerprint (or its master key's) is in the allowed set, so no server can swap in a different key
under the same id. The signature is then verified with Bouncy Castle.

## Release

POM stays at `X.Y.Z-SNAPSHOT`; the **Release** workflow (`workflow_dispatch`) runs
`maven-release-plugin` via the shared OpenMRS release script. Required secrets:
`OMRS_RELEASE_BOT_APP_ID`, `OMRS_RELEASE_BOT_PRIVATE_KEY`, `MAVEN_REPO_USERNAME`, `MAVEN_REPO_API_KEY`,
and optionally `MAVEN_GPG_PRIVATE_KEY` / `MAVEN_GPG_PASSPHRASE`.