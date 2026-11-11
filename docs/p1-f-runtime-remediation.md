# Remédiation du runtime natif P1-F

Statut au 11 novembre 2026 : **publication bloquée, reconstruction et qualification en cours**. Les CI applicatives et le premier build local ne valent pas absence de vulnérabilités système. Le scan de l'archive précédente a identifié une base Python et des bibliothèques natives nécessitant une correction ; il ne doit pas être remplacé par un résultat de scan portant sur une autre image.

Cette décision complète [ADR-019](adr-019-native-runtime-dependencies.md) et le [rapport de scan](p1-f-image-security.md). Aucun NAS, annuaire ou compte réel n'est utilisé pour ces essais.

## Dépendances retenues

- Base officielle `python:3.12.16-slim-trixie`, index OCI `sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b`. Le manifeste Linux amd64 observé est `sha256:05a994d2344eb364cc186910f4fc8786a38215f39f00d0acc25bff33a08f4177`. Le digest d'index a été comparé au SHA256 des octets servis par le registre avec TLS vérifié. La version de Python effectivement exécutée reste à contrôler dans l'image reconstruite.
- FreeRDP **3.33.1**, release officielle du 10 novembre 2026, compilée depuis son archive amont signée. SHA256 : `4431bbf04d370545cfe2924b9d9f116b95c90c64ff156b2550bbaf82d34e7124`. Clé publique officielle : SHA256 `85de10471e0e4aa4958f8c2906794a5e59de492f38a0731720dec99ded82e026`, fingerprint primaire `7703B333420E0AEF995EB4B3A49454A3FC909FD5`. La signature a été vérifiée avec GnuPG dans un trousseau temporaire dédié ; le build exige également SHA256, signature valide et ce fingerprint, pas simplement un nom de signataire.
- Guacamole server 1.6.0 reste construit depuis son archive Apache épinglée et vérifiée. Le patch PamOlive refusant la redirection RDP est conservé. Guacd, les bibliothèques client FreeRDP et le serveur de test RDP sont compilés contre **les mêmes headers et bibliothèques3.33.1**.
- Les upgrades disponibles proviennent uniquement des dépôts de la base Debian trixie. Aucun paquet sid n'est ajouté. Une mise à jour des paquets ne prouve pas à elle seule la correction de tous les résultats : versions installées et statut fournisseur doivent être contrôlés après reconstruction.

Les versions antérieures FreeRDP 3.15 du paquet trixie ne sont pas superposées par une seconde installation. Le Dockerfile ne les demande plus dans le builder ou le runtime. Leur absence effective ainsi que les chemins chargés seront contrôlés par le vérificateur indépendant.

La qualification réelle a révélé une incompatibilité de cycle de vie Guacamole 1.6.0 / FreeRDP 3.33.1 avant connexion TCP. Le [correctif Apache GUACAMOLE-2328](https://github.com/apache/guacamole-server/commit/ab36756b596520ae2a94cd4d25e406e0b5aa820b) initialise GDI et ses handlers dans PostConnect, après la création du cache par FreeRDP. Le backport minimal adapté à 1.6.0 est appliqué sans fuzz après le patch P0 inchangé. SHA256 : `22abebc3df34da38a96bd476b7387754c97eefc51477112a7ad812dd08a3cb05`. Les métadonnées conservent patch et commit amont. Authentification, certificat et refus de redirection restent inchangés. La validation RDP complète reste requise.

## Problèmes traités et garanties conservées

Les [informations Debian sur CVE-2026-45700](https://security-tracker.debian.org/tracker/CVE-2026-45700) et [CVE-2026-121954](https://security-tracker.debian.org/tracker/CVE-2026-121954) identifient des corrections FreeRDP postérieures au paquet 3.15 présent dans le candidat précédent. Les chemins client et serveur restent distingués dans la revue ; compiler une fixture serveur ne suffit pas à revendiquer que tous les défauts serveur étaient exposés par guacd. Leur présence dans les bibliothèques ne doit cependant pas être ignorée globalement.

[Python 3.12.16](https://www.python.org/downloads/release/python-31216/) comprend des corrections de sécurité du runtime et du traitement TLS. La reconstruction met aussi à niveau les paquets Debian pour les correctifs disponibles, notamment glibc. Les vulnérabilités sans correctif, les correspondances de scanner et les conditions d'exploitation résiduelles restent à analyser explicitement.

RDP n'est pas désactivé. NLA, pin du certificat, refus de redirection, absence d'exposition des credentials, sessions bornées, révocation, enregistrements et séparation UID restent des critères de non-régression. Les options média ou périphériques non exposées auparavant par guacd restent désactivées ; aucune preuve de sécurité n'est déduite de la seule désactivation d'une option de compilation.

FreeRDP est installé sous `/opt/pamolive-freerdp`, guacd sous `/opt/pamolive-guac`. Le linker et la whitelist d'environnement utilisent ces deux préfixes statiques. Le moteur natif ne reçoit aucune variable applicative supplémentaire ; seul son chemin de bibliothèques est ajusté. Les builds restent limités à un job pour le budget local 1 CPU / 1 Gio. Les stages de compilation ne sont pas copiés dans le runtime ; aucune roue intermédiaire ou compilateur ne doit subsister.

## Provenance et couverture du scan

Les métadonnées FreeRDP incluent version, hash source, fingerprint, statut de signature et options CMake sous `/opt/pamolive-freerdp/share/pamolive-freerdp`. Celles de guacd restent sous `/opt/pamolive-guac/share/pamolive`, avec licence, notices, patch et options configure.

Le vérificateur indépendant produit `/opt/pamolive-native-manifest.json` après installation, puis vérifie les empreintes des fichiers ELF et leurs liens effectifs. La disparition du nom de paquet Debian ne signifie pas disparition du composant : le SBOM et le rapport doivent conserver FreeRDP source 3.33.1, guacd 1.6.0 et leurs dépendances natives. Une image sans finding n'est pas qualifiée si son composant compilé a échappé au catalogage.

## Portes de validation avant livraison

1. Build effectif Linux amd64 avec nouvelles dépendances ; importLDAP, pip-check et version Python ; absence des anciens paquets et compilateurs.
2. Vérification indépendante des métadonnées, SHA256 ELF, RPATH/ldd et absence de résolution vers les anciennes bibliothèques FreeRDP.
3. Chargement des plugins SSH/RDP, essais réels SSH et RDP/NLA, pin invalide avant credentials, mauvais mot de passe, image/clavier et refus de redirection.
4. Suites P0 de WebSocket/captures, sessions, expiration et révocations, avec PostgreSQL synthétique et aucun affaiblissement des assertions.
5. Nouveau scan de **l'archive exacte reconstruite**, inventaire OS/Python/natif et revue contradictoire des constats restants.
6. CI complète du commit de livraison et attachement du digest/attestation à l'image réellement testée ; aucune reconstruction pendant la promotion.

## Résultats locaux observés

Le témoin local GDI utilise l'archive de production SHA256 `bf5d0075a25d2fc834aa5b21690fac709c62244a5f3330eee8296e1f58512cca`, manifeste OCI `sha256:0585b52ad0db2aac7e3da04b6cea30f810773e03498583ef06a8b4630d5a6943`, configuration `sha256:cd487974f48fd1ed1c2bbb2f79b1fedc6bbcf5aa790329ff2118155502b80e77`. Il s'agit d'un snapshot F1 local contrôlé, sans F3/G/P2, et non d'une image publiée rattachée à un commit de livraison.

| Contrôle | Résultat observé |
| --- | --- |
| Runtime et installation | Python 3.12.16, python-ldap 3.4.8, OpenSSL 3.5.7 ; pip check réussi ; aucun compilateur, CMake, patchelf, roue intermédiaire ou ancien paquet FreeRDP installé |
| Inventaire indépendant en lecture seule | Réussi :10ELF, empreintes/liens réels, versions publiques 3.33.1/1.6.0, options compilées, patch P0 et backport GDI |
| Commandes de compilation | 387 commandes et 8 fichiers de liens contrôlés ; LTO/SIMD désactivés ; RUNPATH fixé par patchelf 0.18.0 avant inventaire |
| Plugins et SSH réel | Réussis : mauvais host-key refusé avant authentification, clavier et déconnexion du canal constatés |
| RDP réel après backport | Réussi en 5,172 s : mauvais pin et mot de passe refusés, NLA, dessin, clavier et déconnexion constatés |
| PostgreSQL, SSH end-to-end | Première campagne 9/10 : un dépassement check_session de 4 s a coupé la session partagée. Cause non attribuée. Cible isolée1/1 en4,266s puis campagne exclusive 10/10 en 42,881 s ; aucun budget ni assertion changé |
| PostgreSQL, RDP end-to-end | Avec DNS de labo fermé :9/9 en36,118s, incluant redirection sans connexion au piège, pin, révocations, expiration et capture partielle sur deadline de 4 s provoquée |
| Revue et scan indépendants | Rapport détaillé dans p1-f-image-security.md ; l'absence de finding corrigible High/Critical ne supprime pas les autres risques et dépend du digest scanné |

La campagne RDP utilisant le résolveur de laboratoire par défaut a échoué1/9,8erreurs avant authentification. Une expérience entièrement locale a identifié la découverte DNS KDC : les seules questions observées visaient `_kerberos.FIXTURE` (URI) et `_kerberos._udp/_tcp.FIXTURE` (SRV). Réponses NXDOMAIN synthétiques : NLA fonctionnelle ; DNS synthétique silencieux : timeout sans authentification. Le support Kerberos était déjà activé dans la baseline 3.15 ; il n'est pas désactivé pour faire passer les tests.

Le gate durable `deploy/check_native_dns.py` teste cette dépendance avec `tests/fixtures/native_dns.py`. Il exige un conteneur Linux non-root, réseau none, DNS 127.0.0.1, capabilities absentes, NoNewPrivs et rootfs en lecture seule. Les datagrammes sont bornés à512octets et64réceptions ; une question invalide ou inattendue interrompt le fixture. Le parser refuse un résolveur externe dissimulé par des commentaires ou des tokens supplémentaires. Ces contournements disposent de 7 tests unitaires sans réseau ni base.

Commande de qualification, avec une image **native-test** déjà identifiée par digest :

```sh
docker run --rm --user 1000:1000 --network none --dns 127.0.0.1 \
  --cap-drop ALL --security-opt no-new-privileges --read-only --no-healthcheck \
  --cpus 1 --memory 1g --memory-swap 1g --pids-limit 128 \
  --tmpfs /tmp:size=64m,mode=1777 --entrypoint python "$PAMOLIVE_NATIVE_TEST_IMAGE" \
  -m deploy.check_native_dns
```

Le port 53 appartient uniquement à ce namespace loopback. Si ce profil non-root ne permet pas son ouverture, le gate refuse ; aucune modification du sysctl hôte ou des capabilities produit n'est prescrite.

Cette assurance concerne le fixture NTLM synthétique. Elle ne qualifie aucun KDC, annuaire ou Kerberos réel, ni la disponibilité face à un DNS défaillant. Un canal Guacamole ready et un broker active ne prouvent pas que le serveur RDP a authentifié le compte ; ils ne constituent pas execution_confirmed. L'échec SSH initial reste une limite de disponibilité non attribuée, distincte du défaut DNS reproduit. Les durées ci-dessus sont des observations fonctionnelles, pas un benchmark comparatif SIMD.

La revue ultérieure a identifié des bibliothèques embarquées sous psycopg_binary.libs, distinctes des paquets Debian. L'inventaire des dix ELF Guac/FreeRDP et un scan OS ne couvrent donc pas exhaustivement les bibliothèques des roues Python. Cette limite impose une remédiation du driver Linux et un inventaire élargi, notamment des roues natives ; le remplacement par un driver lié aux bibliothèques système doit préserver TLS, l'API et les tests PostgreSQL. Les résultats ci-dessus ne démontrent aucune absence générale de vulnérabilités natives.

Le bootstrap pip fait l'objet d'une remédiation complémentaire. Toute nouvelle archive, puis l'artefact du commit final en CI, doivent être contrôlés par leur propre digest. Aucune publication ni qualification NAS n'est déduite de ce témoin local ; la validation de livraison reste ouverte.

Sources primaires supplémentaires : [release FreeRDP 3.33.1](https://github.com/FreeRDP/FreeRDP/releases/tag/3.33.1), [archives et clé amont](https://pub.freerdp.com/releases/), [code source des Dockerfiles Python officiels](https://github.com/docker-library/python).
