# ADR-038 — Qualification de Cyrus SASL sur Trixie

Sur le candidat Debian `6b06ef2`, Grype relève un groupe High Cyrus SASL pour
CVE-2026-107161 et les paquets `2.1.28+dfsg1-9`. Debian annonce une
correction dans une mise à jour de Trixie et marque Forky corrigée à
`2.1.28+dfsg1-12`. Le défaut se situe dans le plugin DIGEST-MD5.
[Scan du candidat](https://github.com/pamolive/PamOlive-Platform/actions/runs/45112004806) ·
[Suivi Debian](https://security-tracker.debian.org/tracker/CVE-2026-107161)

L'image produit installe le cœur SASL et la base de modules par les dépendances
de libldap et libpq. Le client LDAP embarqué utilise un simple bind après
StartTLS et contrôle du certificat. Le greffon DIGEST-MD5 appartient au paquet
recommandé `libsasl2-modules`. Le laboratoire vérifie son absence dans les
deux variantes et conserve le module de base `libsasldb` requis.

La mise à jour officielle de Trixie est privilégiée dès sa disponibilité.
D'ici là, le laboratoire reconstruit la source Debian corrigée sur Trixie
amd64. Le téléchargement APT utilise un index source Forky authentifié et
contrôle les trois SHA-256. La compilation conserve les modifications
Debian, vérifie l'application du patch du CVE et ajoute uniquement
une entrée de changelog. Elle s'exécute hors réseau sous UID non privilégié.
Les programmes du SDK et les modules facultatifs restent dans le builder.
[Correction Debian](https://bugs.debian.org/1150516)

Le témoin et le candidat vérifient l'identité dpkg du couple, les SONAME,
les exports dynamiques des deux ELF et la chaîne libpq, libldap, libsasl2.
La comparaison conserve le type et la version des fonctions exportées
ainsi que la taille des symboles de données.
Les trois bibliothèques clientes sont initialisées sur des valeurs synthétiques
hors réseau.
Le laboratoire conserve les deux paquets, le buildinfo et les empreintes
des bibliothèques. Une qualification produit devra ensuite vérifier la
liaison depuis `_ldap` et Psycopg, des connexions LDAP StartTLS et PostgreSQL
TLS/SCRAM synthétiques, ainsi que le scan strict de l'image exacte.
