# ADR 037 — Qualification de libacl 2.4.0 pour Trixie

Les deux groupes ACL du scan de référence concernent le paquet source Debian
`acl`. Debian classe la version de Trixie comme vulnérable et indique
`2.4.0-1` comme corrigée dans Forky. L'amont préserve toutefois le
comportement des anciennes fonctions par chemin et fournit des variantes
`*_at`. La protection des appels existants dépend donc aussi de
l'adoption de ces variantes dans les consommateurs.
[Suivi Debian](https://security-tracker.debian.org/tracker/source-package/acl) ·
[Annonce amont](https://www.openwall.com/lists/oss-security/2026/06/29/1)

Attendre une mise à jour Trixie maintient la chaîne de support Debian. Le
laboratoire prépare une reconstruction de la source Debian 2.4.0 pour
évaluer sa compatibilité avant toute intégration. Il utilise la même image
Trixie amd64 épinglée que le produit. APT authentifie l'index source Forky
et le contexte vérifie l'intégralité des quatre fichiers par SHA-256.
Le seul changement de source est l'entrée de changelog du rebuild. La
compilation s'exécute hors réseau avec un UID non privilégié.

Le contrôle exige le SONAME historique et la conservation de tous les
exports de l'ancienne bibliothèque, avec leurs versions. GNU tar restaure
une ACL utilisateur nommée sur un fichier synthétique dans les deux variantes.
La variante candidate exerce aussi les appels par descripteur sur un
fichier régulier. La CI conserve le paquet natif, son buildinfo et le reçu
qui relie leurs SHA-256. Le laboratoire est limité à Linux amd64.

L'intégration éventuelle porte sur la bibliothèque seule, avec ses
empreintes qualifiées. Elle devra vérifier les consommateurs de l'image
exacte et l'usage des API historiques. GNU tar déjà compilé reste à tester
en conditions produit. Une recompilation de GNU tar avec les nouveaux
en-têtes doit intégrer le correctif Debian de collision des noms.
Les outils ACL du runner LDAP restent disponibles pour la qualification.
[Compatibilité GNU tar](https://bugs.debian.org/1141146)

Le candidat produit reconstruit le même paquet et exige son SHA-256 avant
installation hors réseau depuis un montage en lecture seule. Il laisse les
utilitaires et en-têtes ACL hors de l'image. Après réimportation de l'image
exacte, la CI inspecte le système de fichiers d'un conteneur jamais démarré.
La création utilise l'identifiant Docker Engine obtenu après rechargement
et vérification de l'archive. Le moteur containerd peut référencer un
descripteur OCI, tandis que le reçu utilise le SHA-256 de la configuration
archivée, lié au descripteur lors de la vérification de l'archive.
L'inventaire relie l'identité dpkg, le lien et le SHA-256 ELF au config ID de l'image
et recense les dépendances et imports dynamiques ACL des fichiers ELF
réguliers, avec leurs modes et propriétaires. Le relevé n'exécute pas ces
binaires et laisse le scan de l'image et sa politique inchangés.

Le portage de libacl fournit les nouvelles API sans migrer les appels
historiques. La revue applicative n'a trouvé aucun flux qui transmet un
chemin de locataire à ces utilitaires. Ce constat couvre les commandes du
produit et son profil supervisé, hors commandes d'opérateur, extensions
ajoutées et montages personnalisés. L'inventaire direct ne couvre pas les
alias par lien dur, les résolutions dynamiques indirectes ou le code
statiquement incorporé.
[Qualification du paquet](https://github.com/pamolive/PamOlive-Platform/actions/runs/45116526133)
