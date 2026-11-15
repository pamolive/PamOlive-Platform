# Synthetic fixture provenance and licence proposal

This selected project test-data set is proposed for distribution under the
accompanying AGPL-3.0-or-later licence. Root must approve this scope before
integration/publication; public cryptographic material is not a public-domain
or third-party licence waiver. No unrelated credential or private key is included.

- original/: 17 public Root-generated oracle files, original manifest SHA256
  0abb0aab0f20deaec3e35d6394921f690d4b6d7beaef48910ce65ba8a954545a.
- adversarial/: 320 public R1b.0b synthetic signed files, manifest SHA256
  896b58932cb1d1f9d4b430d1c363824cbd3c2fd08307eedf95bc23136f4c01dc.
- reference-p0-child-report.json: fixed public selected-function witness, SHA256
  c608019c010966e41a3996669fd0fff3f28549d9bf35dfbd49b00dba894cb92a.

All bytes are preserved; none of the generators or their ephemeral private keys
is distributed or rerun. These inputs represent one synthetic process-controlled
fixture context, not independent humans, custody, possession or action authority.
The witness is an input to differential tests, not complete P0 acceptance.
The Django BSD attribution in NOTICE.txt/LICENSE-DJANGO.txt covers the derived
timestamp parser behavior; it neither licenses these synthetic fixtures as BSD
nor adds a Django runtime dependency. Tests/fixtures are not installed in the
package wheel, whose source and licence closure is checked separately.
