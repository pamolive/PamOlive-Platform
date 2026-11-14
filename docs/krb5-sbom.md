# SBOM séparé du backport Kerberos

`deploy/krb5_sbom.py` produit un document **CycloneDX1.6 autonome**, exclusivement dans l'outillage de sécurité isolé. Il ne s'exécute pas lors de la capture runtime, n'importe le validateur CycloneDX qu'au moment de la validation d'export et ne charge aucune bibliothèque native du candidat. Aucun réseau, base ou modification de paquets n'est nécessaire.

Ce SBOM ne doit pas être injecté dans le document combiné application/FreeRDP/Guacamole : celui-ci couvre les deux préfixes compilés approuvés, tandis que les bibliothèques du backport restent des paquets Debian locaux installés aux chemins système. La duplication de l'autorité d'inventaire serait trompeuse. **Le scanner OS continue d'analyser l'archive entière et conserve tous ses findings.** Ce document n'est ni un VEX ni une règle d'exemption.

## Entrées obligatoires

```sh
python deploy/krb5_sbom.py \
  --manifest krb5-inventory.json \
  --report krb5-verification.json \
  --image-digest sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --image-digest-kind image_config \
  --output krb5-backport.cdx.json
```

Le hash d'exemple est fictif. La chaîne CI doit fournir le hash de configuration **effectivement lié** à l'image dont proviennent le manifeste et le rapport. L'exporteur ne peut authentifier à lui seul ce rattachement fourni par son appelant. `image_config` est le seul kind actuellement accepté ; ce hash n'est pas déclaré comme digest de pull ou hash du conteneur entier. Aucun champ `hashes` n'est ajouté au composant image.

Le manifeste doit satisfaire tous les contrôles purs de `krb5_inventory.validate_manifest` : quatre versions locales exactes, sources/commit/patch attendus, ABI conservée, changement du binaire corrigé, tests Debian activés et régressions ASN.1 avant/après cohérentes. Le rapport de vérification réelle doit avoir le même schéma, `verified=true`, `compilation_proof=false` et un inventaire exactement égal au manifeste. Un manifeste de capture seul ou un rapport d'échec n'est pas suffisant.

Ces contrôles ne transforment pas un JSON en attestation autonome de compilation : les preuves du builder, les signatures/source records, les contrôles de fichiers réels et le digest final doivent être conservés dans la chaîne de confiance. Les unités utilisent des preuves explicitement synthétiques ; elles ne sont pas publiées comme résultats Linux.

Le statut des tests Debian apparaît explicitement dans la propriété de métadonnées `pamolive:krb5:debian-test-status`. Il vaut `passed` ou `passed_with_capability_skips`, conformément au contrat vérifié de l'inventaire. Dans le second cas, `pamolive:krb5:unqualified-capability=kernel_keyring` et `pamolive:krb5:capability-skip-count` conservent visiblement la limitation et le nombre d'exclusions. Le nombre provient de la somme des compteurs des deux phases ; il n'est pas fixé artificiellement à quatre.

Cette exception est limitée aux tests `keyring collection tests` et `keyring ccache tests`, lorsque le justificatif épinglé démontre le refus `EPERM` de la capacité par le profil Docker. Les journaux, compteurs par phase, script de sonde et patch de compatibilité restent liés par les hashes du manifeste ; le SBOM ne les recopie pas. La capacité kernel KEYRING reste **non qualifiée** : ces exclusions ne deviennent pas des tests réussis. Elles ne dispensent d'aucun cas de régression ASN.1. Un statut `passed` accompagné d'exclusions, une autre capacité, un motif imprécis ou des compteurs incohérents bloquent l'export, même si le rapport reprend exactement le manifeste ambigu.

## Composants et identités

Le document contient neuf composants, plus l'image de référence en métadonnées :

- Quatre bibliothèques de paquet :libkrb5-3, libk5crypto3, libkrb5support0 et libgssapi-krb5-2, version `1.21.3-5+deb13u1+pamolive1`, publisher «PamOlive local build».
- Quatre composants fichier ELF avec leur SHA-256 réel, séparés des paquets : un hash d'ELF n'est pas présenté comme hash d'une archive `.deb`.
- La source MIT1.21.3, avec les hashes d'archives Debian/amont, les hashes source avant/après et la référence du commit/patch de backport. L'élément CycloneDX `pedigree.patches` décrit le type `backport`. La version amont n'est pas changée artificiellement en1.22.3.

Les package URLs suivent la [définition primaire Debian](https://github.com/package-url/purl-spec/blob/main/types/deb-definition.json), par exemple :

```text
pkg:deb/debian/libkrb5-3@1.21.3-5%2Bdeb13u1%2Bpamolive1?arch=amd64&distro=debian-13
pkg:generic/mit-krb5@1.21.3
```

Le namespace Debian décrit le format/héritage du paquet, tandis que la description et le publisher précisent la reconstruction locale. Aucun repository_url ne prétend qu'une révision PamOlive est distribuée par les dépôts Debian. Le generic de la source n'est pas assimilé à une preuve de couverture CVE par un scanner et aucun CPE constructeur n'est inventé.

Les liens de licence désignent les fichiers publics attendus `/usr/share/doc/<paquet>/copyright`. Aucun identifiant SPDX n'est déduit du nom Kerberos, et aucune présence/hash de fichier de licence absent de l'inventaire vérifié n'est prétendue attestée. Les références sont explicitement distinguées d'une conclusion de licence ; elles doivent être complétées par un inventaire vérifié des copyrights si une livraison exige leurs hashes.

Les dépendances lient image→paquets→source/fichiers. Les références doivent être uniques et tous les liens pointer vers un composant connu. Le document suit la [référence CycloneDX1.6](https://cyclonedx.org/docs/1.6/json/) et passe la validation stricte des schémas locaux installés par requirements-security.lock ; aucun schéma n'est téléchargé depuis une propriété utilisateur.

## Intégrité et refus

Les deux entrées sont lues avec les bornes de taille, profondeur, nombre de nœuds et refus de clés JSON dupliquées du générateur SBOM natif existant. Les hashes des octets d'entrée et le hash canonique du manifeste sont conservés distinctement. Identifiant et sérialisation sont déterministes pour les mêmes entrées et la même configuration d'image.

La sortie est réservée avant lecture avec `O_CREAT|O_EXCL`, mode0600, et limitée à4MiB. Un fichier existant n'est jamais écrasé. Une erreur peut laisser une réservation vide, qui ne constitue pas un SBOM réussi. Les erreurs stdout sont statiques ; aucune sortie de build ou configuration applicative n'est recopiée. L'absence du validateur strict bloque l'export.

## Tests et limites

Commande dans l'outillage de sécurité isolé : `python -m unittest tests.test_krb5_sbom`.

Onze tests couvrent le schéma strict, les neuf composants et purls, les identités/hashes distincts, le déterminisme, les versions/ABI incorrectes, les preuves non vérifiées ou divergentes, le mauvais kind/digest, les tests amont désactivés, l'écrasement de sortie, les clés dupliquées et les budgets d'entrée. Ils vérifient aussi l'affichage des deux statuts Debian, la conservation des exclusions de capacité et le refus des déclarations ambiguës. Aucun binaire Linux, réseau ou base n'est utilisé.

Ces tests ne démontrent pas qu'un backport a réellement été construit. L'export sur le manifeste et le rapport réels de l'image B3, les tests Linux et le rescan OS restent des portes distinctes. Aucun finding High n'est effacé par la production de ce document.

Résultats locaux du 12 novembre 2026 après adaptation du contrat : 11/11 tests SBOM réussis en 3,159s ; gate combiné inventaire+SBOM 28/28 en 4,580s, aucun test ignoré. Le validateur strict des schémas embarqués a effectivement été utilisé dans l'environnement de sécurité isolé. Les messages d'échec de CLI du gate combiné proviennent des scénarios adverses attendus ; la suite se termine par `OK`. Ruff, format et diff-check réussis. Ces résultats unitaires ne qualifient aucun export sur une image B3 réellement construite.
