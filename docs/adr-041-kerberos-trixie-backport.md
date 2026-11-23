# ADR-041 — Correction Kerberos ciblée sur Debian Trixie

L'image Cairo contient Kerberos `1.21.3-5+deb13u2`. Debian identifie cette
version comme corrigée pour les avis couverts par DSA-6650-1, tandis que
CVE-2026-107778 reste ouverte sur Trixie. Le scan de l'image conserve 14 groupes
Kerberos, dont douze liés à des CVE de DSA-6650-1. La recette et la politique
de publication continuent à conserver tous les résultats bruts.
[DSA-6650-1](https://security-tracker.debian.org/tracker/DSA-6650-1) ·
[Suivi Debian de CVE-2026-107778](https://security-tracker.debian.org/tracker/CVE-2026-107778) ·
[Scan Cairo](https://github.com/pamolive/PamOlive-Platform/actions/runs/45125072702)

Le passage à MIT 1.22.3 élimine cette vulnérabilité en amont. Le laboratoire
historique a construit les paquets et validé le contrôle ASN.1 et la
correspondance TLS. Son export d'ABI perd un symbole GSS versionné, ce qui
bloque l'admission du SDK. Nous retenons le correctif ciblé publié par MIT
appliqué au paquet source Trixie `1.21.3-5+deb13u2`. Aucun paquet binaire Sid
ou Forky n'entre dans le laboratoire.
[Qualification 1.22.3](https://github.com/pamolive/PamOlive-Platform/actions/runs/43930338999) ·
[Correctif MIT](https://github.com/krb5/krb5/commit/62196e2b269159a5465f5b8d0ed7cf6f29c3282a)

APT authentifie l'index `Sources` de `trixie-security`. Le laboratoire exige
ensuite les SHA-256 exacts du DSC, des archives et du correctif. La construction
s'effectue sans réseau sous UID non privilégié. Le SHA-256 du fichier modifié
est contrôlé avant et après application de la correction et après compilation.
Le contrôle de compilation conserve les tests Debian. L'adaptation historique
du test de keyring dépend d'un refus EPERM réellement observé sous seccomp,
et le journal conserve les tests que le paquet annonce comme ignorés.

Les quatre paquets runtime et les six paquets SDK proviennent du même build.
Le laboratoire installe le stock officiel et le candidat, compare les SONAME
et chaque export dynamique versionné, puis relie et exécute le consommateur
Kerberos/GSS existant sous Trixie sans réseau. Le candidat reste hors de
l'image produit jusqu'à validation native, revue du reçu et nouvelle campagne
sur l'image exacte. Le résultat du scan n'est pas déduit de l'ABI ni du patch.

## Intégration du backport qualifié

La campagne `0b0d524` a vérifié l'ABI des quatre bibliothèques et le
consommateur du SDK installé. L'inventaire de produit épingle les dix
archives de ce build et les quatre ELF runtime à partir de l'artefact
GitHub vérifié. Le Dockerfile reconstruit les paquets à partir des mêmes
sources et exige les mêmes tailles et empreintes avant toute installation.
[Reçu de qualification](https://github.com/pamolive/PamOlive-Platform/actions/runs/45131107539/artifacts/14798285716)

L'étape Debian officielle reste disponible pour les recettes historiques.
La base du produit utilise une étape distincte qui assemble la glibc Debian
et le backport Kerberos sans installer au préalable le Kerberos stock de
cette recette. Le SDK, FreeRDP, Guacamole et les clients liés à Kerberos
utilisent les paquets issus du même build. APT refuse les autres versions
de cette famille dans l'image produit. L'inventaire distingue le reçu
Debian de celui du backport. Le SBOM conserve le nom source `krb5`, la
version locale et l'empreinte du paquet installé. Sa référence de
distribution pointe vers le reçu du build PamOlive.

La CI lie les preuves de l'image en cours d'exécution et de son archive
chargée. Les essais RDP et LDAP, les régressions PostgreSQL et le verdict
Grype sur l'image exacte déterminent la suite de l'admission. Les seuils,
dispositions et règles de publication restent inchangés.
