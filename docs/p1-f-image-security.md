# P1-F — qualification de sécurité de l’image

## Contrat de contexte typé en qualification — 17 novembre 2026

Sur main ebc142c, les 1 646 tests PostgreSQL au total comprennent 42 ignorés,
sans échec ni erreur. Le contrôle Docker refuse ensuite pendant export_check
avec context_unknown_entry : le garde couvre un nom hors ensemble ou rencontré
deux fois. Le type et le nom historiques ne sont pas reçus ; aucun répertoire
vide particulier n'est présenté comme la cause prouvée. Les trois builds
suivants et le scan d'image restent sautés, sans image nouvelle qualifiée.

Le contrat v2 distingue les FILE et DIR connus avant Docker. Les répertoires
sélectionnés, y compris les vides connus, appartiennent au TAR réel ; ceux
propres aux contre-cas du probe n'y entrent pas. Les en-têtes et leur empreinte
typée exacte doivent être contrôlés avant la première lecture de contenu.
Une revue adverse a conservé deux contre-cas (mode autorisé différent et taille
différente) : la première proposition refusait finalement après trois lectures.
Cette proposition n'a pas été publiée et le contrôle est avancé avant lecture.
Les modes, propriétaires, liens, alias, limites et racines privées restent
stricts. Les reçus scellés et de parité v1 ne sont pas réutilisables en v2 ;
la création Git v1 sans scellement garde son interface. L'oracle Linux reste
obligatoire. Les FILE Git actuels sont tous0644 ; le mode0755 est contrôlé
dans le TAR et les tests purs, sans preuve native générale pour des FILE futurs.

Le diagnostic APT du navigateur passe à /2 : compteurs finis et au plus16
empreintes de lignes par flux, sans texte brut. Ces observations ne prouvent
ni une cause, ni une installation ; les reçus /1 historiques restent lisibles.
Aucune option APT, autorité, permission ou durée d'installation n'est élargie.
Les preuves GPG et les validations de l'interpréteur et installé/2 sont préservées.

La branche séparée de capture Expat APT (PR22 en brouillon) a atteint les trois
vérifications de dépôts puis refusé la simulation APT. Elle n'a ni approuvé un
jeu de dépendances, ni installé de paquet dans le produit. Les frontières de
provenance, matières, compilation et qualification ADR-021 restent ouvertes.
Aucun tag d'image, déploiement ou accès NAS n'est effectué pour ces essais.

Comptage : les totaux unittest incluent les cas ignorés ; un test ignoré ne constitue pas une validation.

Le diagnostic navigateur R8 ajoute une projection fermée des mêmes buffers
APT sous H1 normal rc100 et une observation interpréteur/1 avant installation.
Les arguments, options, sources, timeouts et conditions de succès ne changent
pas ; ni une observation ni un marqueur ne remplace installed/2 ou la cause
réelle encore inconnue. Les 136 tests purs passent sans skip ; réception Linux
du nouvel essai requise. Les quatre seuls deltas R8 préservent le helper et
les pins du diagnostic Docker A composé dans ce même candidat.

## Diagnostic du probe en cours — 17 novembre 2026

La CI main c752cd1 a réussi les contrôles de sécurité et Directory.
PostgreSQL annonce 1 632 tests au total, dont 42 ignorés, sans échec ni erreur. Le probe a construit le bon scratch
et terminé son export local, puis refusé sa vérification interne sans détail.
Les trois builds produit/native-test/json-reference et le scan ont été sautés.
Ce n'est ni une parité réussie ni une image qualifiée.

Le nouveau diagnostic conserve rc1 et tous les gardes : seuls 65 codes et
10 phases littéraux sont publiables, jamais le texte d'exception, un chemin
inconnu ou un contenu. Un job Linux distinct, borné à cinq minutes, exerce
la même préparation et le probe60+15 ; il ne lance ni PostgreSQL, ni APT,
ni construction produit et ne conserve que quatre feuilles JSON explicites.
Sur le checkout intégré, 69 tests purs passent sans skip ni tentative externe.
Les deux cas créant réellement un Git ne sont pas exécutés sous Windows et
restent en CI. La cause native précise reste à recevoir ; aucun mode ou
contrôle de l'export n'est modifié pour transformer le refus en succès.

## Intégration du code de développement dans main — 17 novembre 2026

À la demande explicite du propriétaire, les vingt PR ouvertes sont réunies
par des fusions conservant leur historique. Les quatre têtes finales étaient
bde355e (runtime/contexte), e4dfb9f (laboratoire Kerberos), 1564317 puis 5583daf
(navigateur/journaux publics) et 9b7e866 (diagnostics publics navigateur).
Cette intégration du code ne constitue ni une validation de toutes les PR,
ni une publication d'image qualifiée ou un déploiement. Les contrôles CI,
les refus ADR021 et le workflow manuel de publication restent actifs.

Les essais bde ont passé 455 tests de sécurité et 1 631 tests PostgreSQL,
avec 42 tests PostgreSQL ignorés dans chacun des deux runs. Le probe Docker
a ensuite échoué en sélectionnant le Dockerfile produit depuis le cwd ;
le correctif ici impose le chemin absolu de sa fixture scratch et conserve
les trois consommateurs TAR. Ancien défaut reproduit, 55 tests purs passent.
La parité moteur et les trois constructions réelles doivent être requalifiées.

Les deux essais 1564317 ont refusé le bootstrap puis l'upload public root
(EACCES), sans reçu interpréteur ou installation. 5583daf corrige uniquement
les permissions des deux feuilles de journaux publics par FD ; 128 tests purs
passent. La cause primaire EXIT42 reste inconnue jusqu'à réception réelle.
Le job navigateur reste restreint à sa branche/PR de laboratoire ; son absence
sur un push main n'est pas une qualification du navigateur sur main.

Le dernier scan runtime reçu (parent5d8f814) reste à 98 High/31 groupes.
Le laboratoire Kerberos conserve son refus ABI et ses profils non admis.
Les bibliothèques/contrats P2 installés et leurs tests ne suffisent pas à
qualifier tout P2/P3. Les notes suivantes sont des témoins historiques de
branches, conservés sans transfert automatique de preuve vers cette fusion.
Aucun NAS ou compte réel n'est utilisé. Une CI du SHA main exact est requise
avant toute conclusion nouvelle ; aucune image Docker n'est publiée ici.

## Notes historiques conservées de la branche navigateur R7

## État courant R7 — diagnostics publics à récupérer, 17 novembre 2026

Les essais Linux du candidat 1564317 ont échoué : bootstrap EXIT42 puis
upload EACCES/scandir sur le sous-répertoire public root. Aucun artefact
navigateur ni reçu interpréteur/installation n'a pu être reçu ; la cause
primaire du bootstrap reste inconnue. Les preuves R5 restent historiques.

R7 donne explicitement0755 aux deux seules feuilles de journaux publics,
via leur FD sans alias, avec propriétaire/dev/ino/mode vérifiés et fermeture.
Les fichiers JSON sont déjà0444 ; umask077 et espaces privés restent inchangés.
128 tests purs passent sans exclusion ni tentative externe, Ruff passe.
Ces modèles ne prouvent ni les permissions sur la VM ni le bootstrap :
nouvelle CI exacte et récupération des diagnostics obligatoires. Voir ADR034.
Aucun main fusionné, image promue ou accès NAS par cette correction.

## Témoin historique R6 avant réception — 16 novembre 2026

Les deux essais Linux du candidat R5 `cd9b2fc`
([push](https://github.com/pamolive/PamOlive-Platform/actions/runs/43948941376),
[PR](https://github.com/pamolive/PamOlive-Platform/actions/runs/43948955828))
ont réellement terminé le générateur GPG TEST et ses huit observations sudo/stat.
Les six buffers publics, le nettoyage et les 17 catégories de contrôles natifs,
de modèles et de gardes sont reçus ; ces catégories ne sont pas 17 signatures
indépendantes. L'acquisition et la simulation APT sont passées. Le refus suivant
sur tool_type_owner_mode intervient avant le lancement du superviseur root.
Le chemin et les métadonnées de la feuille refusée n'ont pas été exportés :
aucune cause précise UID/mode/nlink n'est déduite. Chrome n'a pas été installé.

R6 choisit explicitement /usr/bin/python3.12 pour le superviseur privilégié,
indépendamment du Python du venv. Le guard tool_pin reste inchangé. Le parent
vérifie le pin et l'identité complète avant et après sudo ; le superviseur exige
UID réel/effectif 0, image /proc/self/exe correspondante, CPython 3.12.x finale
et flags -I/-B/-S. Le reçu installé /2 impose la preuve interpréteur /1 liée
aux mêmes source, manifeste, contexte et révision. Un ancien reçu est refusé.
La version système effectivement utilisée reste à mesurer, sans la confondre
avec le Python 3.12.16 du venv. Aucun nouveau processus, privilège ou budget
n'est ajouté : horizons 870/450 et appel sudo 480 secondes conservés.

Sur le checkout intégré, 125 tests purs passent sans échec, exclusion ou
tentative externe ; Ruff et format passent. Les 25 rôles Chrome et 24 pins UI
doivent rester fermés depuis les octets Git. Ces modèles ne prouvent pas
l'exécution du Python système, la réauthentification root, l'installation,
Chrome ou le parcours navigateur : nouvelle CI exacte obligatoire.

Le pin ELF ne prouve pas l'herméticité du loader et de la stdlib Ubuntu.
L'entrée du script par pathname avant ses contrôles et la TCB coopérative
root/même UID demeurent explicites. Un refus après installation n'est pas un
retour arrière. GPG, producteur Owner/2/Observer/1 et ses six rôles TEST restent
inchangés. P1-F/G et l'autorité complète ADR-021 demeurent incomplets.
La branche runtime distincte bde355e teste son contexte scellé séparément ;
aucune qualification ne passe d'une branche à l'autre. Le parent runtime 5d8f814
reste refusé pour 98 High dans 31 groupes. Aucun merge main, nouvelle image
promue ou accès NAS n'est réalisé par R6.

## Témoin historique R4/R5 avant réception — 16 novembre 2026

Le [candidat R4 `095d0eb`](https://github.com/pamolive/PamOlive-Platform/actions/runs/43929358076)
a reçu un refus errno 13 lors de la lecture de `/proc/<PID possédé>/exe`, puis
au précontrôle du nettoyage. Le processus TEST a été repris et drainé, mais le
reçu demeure INCOMPLETE et le nettoyage non validé. Ce diagnostic ne démontre
pas quelle règle du noyau a refusé la lecture. Aucun navigateur n'a été qualifié.

La correction R5 conserve l'observation répétée de l'exécutable. Sur ce seul
errno 13, un observateur fixe `sudo -n -u#0 -- /usr/bin/stat` lit ses métadonnées ;
le générateur, les clés TEST et GPG restent non privilégiés. Les outils de
l'observateur ont leurs propres gardes, sans exception SUID pour GPG ou Python.
PID, parent, session et starttime encadrent chaque lecture. Un résultat incertain
interdit tout nouvel observateur privilégié, y compris pendant le nettoyage.
Le reçu propriétaire et son préflight changent de version et sont exigés par
le consommateur ; les anciens reçus R4 ne sont pas requalifiés.

Les bornes restent 40 frontends, 180/150/30 secondes et 15 secondes de readiness.
Le majorant structurel de 34 compte les frontends ; il ne compte pas l'agent ni
tous les descendants de sudo. Le succès normal repose sur le sudo foreground
de la VM de test ; une fin incertaine reste UNKNOWN/resources_released:false.
Les observations ne rendent pas les transitions d'exécutable atomiques.

Dans le checkout intégré, 110 tests purs passent sans exclusion ni tentative
externe ; la revue indépendante rejoue ces tests et six adverses supplémentaires.
Ruff sur le dépôt passe. Ces modèles ne prouvent ni la nouvelle voie sudo réelle,
ni les signatures GPG, l'installation ou une session navigateur. Une nouvelle
CI Linux du nouveau commit demeure obligatoire avant toute réception native.

La branche runtime distincte `5d8f814` a terminé sa
[CI](https://github.com/pamolive/PamOlive-Platform/actions/runs/43937390888) :
1 597 tests PostgreSQL (42 ignorés), 130 Directory, transports synthétiques,
restauration et SBOM passent ; seul le scan d'image refuse les 98 High dans
31 groupes. Cette preuve ne se transfère pas à la branche navigateur.
Les matériaux et l'autorité de build ADR-021 restent incomplets. P1-G et les
autres qualifications restent ouverts ; aucune nouvelle image n'est promue,
aucune fusion main ni modification NAS n'est réalisée par ce correctif.
Les sections suivantes conservent les états historiques des candidats.

## Historique des candidats et des scans

Statut : **scan OS et bibliothèques du candidat initial terminé, seuil High/Critical non satisfait ; remédiation et scan final en attente**. Le candidat initial ne reçoit pas de validation de sécurité pour une publication utilisable avec PAM/RDP. Les correspondances ci-dessous nécessitent correction ou analyse d’applicabilité explicite. Cette revue ne modifie ni Dockerfile, dépendances, workflow, NAS ou installation existante.

## État courant — contexte scellé en qualification, 16 novembre 2026

Le parent assemblé `5d8f814` a terminé sa
[CI Linux](https://github.com/pamolive/PamOlive-Platform/actions/runs/43937390888).
Les tests PostgreSQL (1 597 exécutés, 42 ignorés), les 130 tests Directory,
les transports synthétiques, la HA sur un seul hôte, la restauration et le
SBOM passent. Le seul échec est le scan strict : 98 High dans 31 groupes,
349 correspondances OS, zéro compiled, contrôle positif 222 et zéro ignore.
La restauration synthétique compare 106 modèles et 82 preuves signées,
conserve legacy/V7 et termine son nettoyage ; safe_to_serve reste false.
Ces résultats restent liés au parent, sans qualification transférée au nouveau code.

L'incrément A lie maintenant le contexte réellement envoyé aux trois builds
production, native-test et json-reference-data. Un TAR exclusif 0400 est
construit à partir des seuls buffers Git validés. Un profil fini de sélection
est lié aux octets exacts Dockerfile/Dockerignore ; le TAR sur stdin ne suppose
aucun filtrage Dockerignore implicite. Avant les builds, un oracle distinct
répertoire/scratch à marqueurs publics compare la sélection au moteur Docker.
Le test d'absence des canaries dans l'image finale reste inchangé.

Chaque consommateur relit le manifeste v1 via FD stable, vérifie les hashes,
la révision et la carte des sources, exige le reçu de parité du même sujet,
puis transmet à Docker le FD TAR déjà validé. Le même TAR sert aux trois
constructions. Le nouveau probe est borné à 60 s +15 s ; le témoin JSON garde
540 s +15 s et son validateur 240 s. Les autres budgets et gates sont inchangés.
Seules deux métadonnées bornées s'ajoutent aux diagnostics publics ; aucun
TAR de contexte ni nouvelle image non qualifiée n'est publié par ce raccord.

Sur le checkout intégré, 43 tests purs passent sans exclusion ni tentative
externe ; la contre-revue indépendante rejoue ces cas et six adverses en plus.
Ruff du dépôt passe. Deux anciens cas créant réellement un dépôt Git ne sont
pas exécutés sous Windows et restent obligatoires en CI, avec la parité et
les trois vrais builds. Aucun succès Docker n'est déduit de ces modèles.

Les contrôles ne sont pas atomiques contre un acteur hostile de même UID/root.
Un refus après un build n'est pas son rollback ; les délais ne prouvent pas le
nettoyage global du daemon. Recette authentifiée, conservation et matériaux de
toutes les frontières, attestations et autorité complète ADR-021 restent ouverts.
Les flags recipe_bound/build_verified/attestation/authority restent false.

La branche navigateur distincte `cd9b2fc` a reçu le générateur GPG et huit
observations sudo/stat, puis refuse avant le superviseur d'installation sur
sa garde d'interpréteur ; aucune installation ou session navigateur n'est admise.
Ses preuves ne se transfèrent pas à cette branche. P1-F/G, P2 et P3 restent
incomplets. Aucune fusion main, promotion d'image ni modification NAS.
Les sections suivantes conservent les témoins historiques et leur portée.

## Capture GCC préservée du parent

Le sidecar GCC réutilise le même appel `deploy.native_inventory`, avec
`--gcc-provider-output`. Le JSON normal et son schéma restent identiques. Aucun
nouveau ldd, subprocess, conteneur ou graphe n'est ajouté. Les lectures restent
plafonnées à 16 Mio pour le fournisseur, 4 Mio pour status et 32 Kio pour la
sortie séparée créée exclusivement. Les champs dpkg ambigus sont refusés.
Les 48 tests dédiés appartiennent au témoin local de 153 tests de l'assemblage parent ; les 25 anciens
contrats restent conservés, avec fixture historique bornée indépendante d'OUT.
L'appel Docker existant n'acquiert aucune garantie H172/PID/reap/drain nouvelle.

## Historique des candidats et des scans

Statut : **scan OS et bibliothèques du candidat initial terminé, seuil High/Critical non satisfait ; remédiation et scan final en attente**. Ce candidat initial ne reçoit pas de validation de sécurité pour une publication utilisable avec PAM/RDP. Les correspondances ci-dessous nécessitent correction ou analyse d’applicabilité explicite. Cette revue ne modifie ni Dockerfile, dépendances, workflow, NAS ou installation existante.

## Candidat identifié

Le candidat est un snapshot contrôlé du working tree, pas une image publiée de main :

| Élément | Identité vérifiée |
| --- | --- |
| Archive locale | `p1-f-production-qualification.tar`, 149 893 632 octets |
| SHA-256 de l’archive | `21803b525a4f953217f304e9f8f6a7bd0c82a865b80f959783a2328f8e29019d` |
| Digest des octets de configuration | `sha256:2f1543e2ef134aa2cb4e021180164d7f1be2cc5fc41755264ad9987ef1bb20ee` |
| Manifeste signalé par le build local | `sha256:fe47d3627fae069b231a0c831e84559a240e49e1e329f3a05a145c23259e9c3b` |
| Plateforme | `linux/amd64` |

Le hash d’archive et le digest de configuration ont été recalculés indépendamment depuis les fichiers. Le manifeste et l’identifiant retourné par Docker 29 ne doivent pas être confondus avec le digest des octets de configuration. Une nouvelle construction ou une image CI différente exige son propre rattachement aux preuves.

## Outil et données

Grype **0.121.3**, release officielle immutable publiée le 9 novembre 2026, a été choisi après consultation des [releases Anchore](https://github.com/anchore/grype/releases/tag/v0.121.3) et de la [procédure officielle de vérification](https://oss.anchore.com/docs/installation/verification/).

Archives officielles téléchargées par HTTPS vérifié, avec digest comparé à l’API de release et au fichier de checksums :

- Windows amd64 : `3007a5afea25c60030a49d6c24d4e5abb6c94c0dbeed7ea303eb26df8e900c18`.
- Linux amd64 : `e9da18cc1429e786722e32161288103600efffd8e483c90761f90485bd1bec85`.
- Fichier de checksums : `1f8cea030e00f362d6b0bb0d1843b123af1d6baad70975dff1cf6fe14096866f`.

Le bundle de signature du fichier de checksums est conservé ; sa vérification cryptographique n’a pas été exécutée dans cette étape. Le contrôle réalisé porte sur l’identité des artefacts servis par les endpoints officiels, pas sur une attestation indépendante de la construction du scanner.

La [base publique Grype](https://oss.anchore.com/docs/guides/vulnerability/database/) a été obtenue séparément par HTTPS, sans credential utilisateur : schéma `v6.1.10`, build du 11 novembre 2026 à 06:21:32 UTC, archive de 200 236 695 octets, SHA-256 `47f709e0217cf091eaf8dc57c8cdea33f9ba2c7d5374237c5011871a0c99d24e`. Son checksum a été vérifié. Les contrôles d’âge et d’intégrité ne sont pas désactivés.

## Exécution et limites observées

Le téléchargement automatique de la base par le CLI Windows a dépassé la borne de 240 secondes. L’import local séparé n’a pas abouti dans le créneau de ressources ; son seul processus a été identifié par son exécutable et sa ligne de commande, puis arrêté pour laisser la priorité aux qualifications applicatives. Les caches partielles sont conservées et ne sont pas considérées comme des bases valides. Aucun verdict de scan n’en découle.

L’outil Linux a ensuite analysé l’archive locale en [mode archive officiel](https://oss.anchore.com/docs/guides/vulnerability/scan-targets/), sans socket Docker, sans réseau et sans démarrage de l’application. Aucun contenu de l’image n’est envoyé à un service. Le pull de l’exécuteur Python officiel épinglé a échoué par résolution DNS DockerHub ; le repli explicitement autorisé utilise le candidat comme système de fichiers d’exécution, avec **ELF Grype statique vérifié comme entrée directe**, sans shell, `LD_PRELOAD` et `LD_LIBRARY_PATH` vidés. Cette dépendance à l’image cible comme exécuteur est une limite d’indépendance ; le scanner lui-même ne provient pas de cette image.

Le conteneur est non privilégié, sans capacités, `no-new-privileges`, rootfs en lecture seule, réseau `none`, CPU 1, mémoire et swap 256 MiB, `GOMEMLIMIT=192MiB`. Seuls l’ELF, la configuration et l’archive sont montés en lecture seule ; une nouvelle cache dédiée contient la base et le rapport. Aucun service existant n’est arrêté. L’import de base a abouti en 264,343 s, sans OOM. Son healthcheck hérité avait effectué des sondes localhost ; le scan final désactive explicitement ce healthcheck. Aucune sonde externe ni application PamOlive n’a démarré.

Premier scan Linux : échec Go `newosproc` à la limite de 32 tâches, rapport vide ; **son code 2 ne constitue pas un verdict CVE**. Second scan : limite de tâches portée à 128, mêmes plafonds mémoire/CPU, **terminé en 54,391 s, sans OOM**, JSON complet et base validée. Son code 2 correspond cette fois au seuil `--fail-on high` dépassé.

Commande effective : `grype -c /grype.json --from docker-archive /image.tar --scope squashed --fail-on high -o json --file /scan/image-report2.json`. Toutes les sévérités et tous les états de correction sont conservés. Aucune règle utilisateur d’ignorance, exclusion ou VEX. Grype ajoutait cependant quatre règles internes pour les kernel headers ; aucun `ignoredMatches` n’était rapporté sur ces témoins. Le mode initial ne rendait pas toutes les suppressions internes visibles : le mode strict décrit ci-dessous corrige cette limite. Enrichissement externe et mise à jour automatique désactivés, contrôles d’âge et de hash de base actifs, conformément aux [options Grype](https://oss.anchore.com/docs/reference/grype/configuration/).

## Couverture requise

Le rapport doit distinguer paquets Debian, bibliothèques LDAP/SASL/TLS et Python réellement présents dans le runtime. Les findings doivent conserver identifiant, version installée, version corrigée éventuelle, statut fournisseur et correspondance précise de paquet. Une absence de fix n’est pas une absence de vulnérabilité ; un match de version n’est pas à lui seul une preuve d’exploitation.

Guacamole server est compilé depuis une archive Apache vérifiée et patchée ; il n’est pas nécessairement catalogué comme paquet Debian. La version source 1.6.0 et le patch doivent donc être recensés séparément. La [page de sécurité Apache](https://guacamole.apache.org/security/) indique que CVE-2024-35164 est corrigée en 1.6.0. Le build actuel désactive VNC, Telnet et plusieurs fonctions média ; cela ne permet pas d’ignorer globalement les vulnérabilités des bibliothèques présentes.

Cette qualification ne remplace ni les tests TLS/SSH/RDP ni une validation d’exposition ou d’exploitabilité. Elle ne qualifie pas un NAS, une architecture ARM, une nouvelle image reconstruite ou l’ensemble des vulnérabilités inconnues.

## Résultats exacts

Le rapport utilise Grype 0.121.3 et la base `v6.1.10` du 11 novembre 2026, déclarée valide. Il identifie Debian 13.6 (trixie).

| Mesure | Résultat |
| --- | ---: |
| Correspondances paquet/vulnérabilité | 1 326 |
| Identifiants de vulnérabilité distincts | 548 |
| Critical / High | 69 / 570 |
| Medium / Low | 450 / 59 |
| Negligible / Unknown | 138 / 40 |
| État `fixed` / `not-fixed` / `wont-fix` | 144 / 631 / 551 |
| Correspondances High/Critical avec fix annoncé | 74 |
| Correspondances Debian / binaire Python / paquet Python | 1 280 / 40 / 6 |
| Correspondances ignorées | 0 |

Ces chiffres ne sont pas autant d’exploitations distinctes. Plusieurs binaires Debian issus du même paquet source portent la même CVE. Par exemple, les trois bibliothèques FreeRDP/WinPR cumulent chacune 118 correspondances High/Critical. Les états Grype reflètent le suivi fournisseur ; `wont-fix` ou `no-dsa` ne signifient pas absence de risque. Le scan ne démontre pas l’accessibilité de chaque chemin vulnérable.

### Corrections prioritaires

1. **Interpréteur Python ancien.** L’image contient réellement Python **3.12.13**, indépendamment de la version du runner CI et des paquets PyPI verrouillés. Grype trouve 40 correspondances binaires, dont 2 Critical et 11 High. Python publie **3.12.16** comme release de sécurité et confirme notamment CVE-2026-115557 (défiance de clés intermédiaires eMudhra compromises), des mises à jour Expat et un correctif tarfile. Il faut actualiser le digest de base, reconstruire, tester et scanner cette nouvelle image ; `pip install` ne met pas à jour l’interpréteur. [Python 3.12.16](https://www.python.org/downloads/release/python-31216/).
2. **Bibliothèques RDP vulnérables, sans correction trixie disponible pour plusieurs problèmes.** FreeRDP **3.15.0+dfsg-2.1+deb13u3** reste explicitement vulnérable selon Debian. CVE-2026-45700 concerne une écriture hors limites dans le décodeur planar (fix amont 3.26.0). CVE-2026-121954 permet à un serveur RDP malveillant de corrompre le tas du client via ResetGraphics/GFX (fix amont 3.32.2). Le patch local interdisant la redirection ne corrige pas les codecs. Une mise à jour APT des paquets disponibles en trixie ne suffit donc pas. Il faut qualifier une version corrigée de FreeRDP et sa compatibilité guacd, ou conserver l’exécution RDP désactivée dans une livraison limitée et clairement documentée. Ne pas mélanger aveuglément des dépôts sid au runtime stable. [CVE-2026-45700](https://security-tracker.debian.org/tracker/CVE-2026-45700), [CVE-2026-121954](https://security-tracker.debian.org/tracker/CVE-2026-121954), [suivi FreeRDP Debian](https://security-tracker.debian.org/tracker/source-package/freerdp3).
3. **Paquets de base hérités à actualiser.** Le runtime conserve notamment glibc `2.41-12+deb13u3` et perl `5.40.1-6`, avec fixes disponibles. Debian confirme glibc CVE-2026-5450 corrigée en `2.41-12+deb13u4` et perl CVE-2026-8376 en `5.40.1-6+deb13u1`. Cette dernière décrit spécifiquement des builds Perl 32 bits ; la cible amd64 n’autorise pas à conclure automatiquement à son exploitabilité. Ces différences de contexte doivent rester dans le triage, sans effacer le finding brut. [glibc](https://security-tracker.debian.org/tracker/CVE-2026-5450), [Perl](https://security-tracker.debian.org/tracker/CVE-2026-8376).

Autres familles avec correctifs High/Critical annoncés par la base : apt `3.0.3→3.0.4`, gzip `1.13-1→1.13-1+deb13u1`, zlib `1:1.3.dfsg+really1.3.1-1+b1→1:1.3.dfsg+really1.3.1-1+deb13u1`, PCRE2 `10.46-1~deb13u1` vers les révisions corrigées u2/u3 selon CVE, SQLite `3.46.1-7+deb13u1→u2` et famille util-linux `2.41-5→2.41.5-0+deb13u1`. La liste exhaustive paquet/CVE/version/fix est conservée hors dépôt ; les versions doivent être vérifiées au moment de la reconstruction. Ne pas fabriquer une unique version minimale à partir d’un tri lexicographique des versions Debian.

### LDAP, SASL, TLS, paquets Python et guacd

Inventaire indépendant de `/var/lib/dpkg/status` dans l’archive : **213 paquets Debian installés**, dont :

| Composant | Version installée | Résultat et applicabilité |
| --- | --- | --- |
| OpenLDAP `libldap2` | `2.6.10+dfsg-1` | 5 correspondances Negligible, non corrigées dans la base ; ne signifie pas « sans vulnérabilité ». |
| Cyrus SASL `libsasl2-2`, `libsasl2-modules-db` | `2.1.28+dfsg1-9` | CVE-2026-107161 High, trixie vulnérable selon Debian. Le problème vise le plugin DIGEST-MD5 ; l’adaptateur utilise simple bind après StartTLS et le seul plugin observé dans l’archive est sasldb, pas DIGEST-MD5. Chemin annoncé non exercé par le collecteur actuel ; toute activation SASL exige réévaluation. |
| OpenSSL `libssl3t64` | `3.5.7-1~deb13u3` | 5 correspondances Unknown/non corrigées ; pas de classement arbitraire « sûr ». |
| FreeRDP/WinPR | `3.15.0+dfsg-2.1+deb13u3` | 18 Critical + 100 High par bibliothèque, corrections/triage nécessaires avant usage RDP. |
| `python-ldap` | `3.4.8` | Métadonnées de distribution présentes ; aucun finding Grype Python attribué à ce paquet. Les bibliothèques natives ci-dessus restent évaluées séparément. |
| `pip` | `25.0.1` | 6 correspondances, 5 Medium/1 Low, fixes annoncés jusqu’à 26.2.0 ; outil de build présent en runtime à actualiser ou retirer proprement. |
| guacd compilé | `1.6.0` + patch redirection | Inventorié séparément, pas de preuve de couverture intégrale du binaire compilé par le scanner. |

Debian confirme le défaut SASL dans DIGEST-MD5 et l’absence actuelle de correction trixie ; ce statut ne vaut pas exemption globale pour tous les usages de SASL. [CVE-2026-107161](https://security-tracker.debian.org/tracker/CVE-2026-107161).

Les bibliothèques ffmpeg `libavcodec61`, `libavutil59`, `libswresample5`, `libswscale8` sont également présentes et chacune porte 24 correspondances High/Critical. La désactivation de l’option ffmpeg au build guacd n’enlève pas automatiquement ces dépendances transitives. Réduire les dépendances et séparer le broker des services Django sont des mesures de réduction de surface à étudier avec les propriétaires du packaging, sans retirer un contrôle P0.

### Matrice High/Critical par paquet source

Comptage dédupliqué par `(paquet source, identifiant)` : **226 couples**, 24 familles. Les états sont ceux de Grype, pas une déclaration d’exploitabilité. Les identifiants et versions corrigées individuels restent dans `output/p1-f-image-hc-matrix.json` ; aucune correspondance n’est éliminée.

| Source | Critical / High uniques | États des couples | Exposition et préconditions à ce stade |
| --- | ---: | --- | --- |
| `acl` | 0 / 2 | wont-fix: 2 | Gestion ACL native ; nécessite une entrée/chemin déclenchant le défaut, accès applicatif non démontré. |
| `apt` | 0 / 1 | fixed: 1 | Gestionnaire de paquets conservé ; chaîne de mise à jour/installation concernée, pas une route HTTP. |
| `cups` | 0 / 2 | not-fixed: 1, wont-fix: 1 | Bibliothèque transitive ; aucune impression prévue par P1-F, appel vulnérable non démontré. |
| `cyrus-sasl2` | 0 / 1 | wont-fix: 1 | Serveur DIGEST-MD5 malveillant requis ; plugin DIGEST-MD5 absent, simple bind StartTLS utilisé. Réexaminer tout futur SASL. |
| `expat` | 0 / 4 | wont-fix: 2, not-fixed: 2 | Parsing XML natif ; vérifier tous les consommateurs et XML contrôlables, absence de chemin non démontrée. |
| `ffmpeg` | 1 / 23 | wont-fix: 24 | Bibliothèques transitives présentes malgré option guacd ffmpeg désactivée ; entrées média/codecs à inventorier. |
| `freerdp3` | 18 / 100 | wont-fix: 39, not-fixed: 79 | Serveur RDP compromis/malveillant et codecs/PDUs atteignables ; TLS pinning ne rend pas honnête un serveur autorisé. |
| `gcc-14` | 0 / 2 | wont-fix: 2 | Bibliothèques runtime GCC, pas preuve de compilateur installé ; préconditions propres à chaque CVE à analyser. |
| `glibc` | 1 / 4 | fixed: 2, wont-fix: 3 | Libc partagée de nombreux processus ; CVE5450 exige scanf %mc avec largeur>1024 ; chemin applicatif non démontré. |
| `gzip` | 0 / 1 | fixed: 1 | Traitement de flux compressé contrôlable ; restauration/outillage à examiner, pas exploitation démontrée. |
| `krb5` | 0 / 7 | not-fixed: 6, wont-fix: 1 | Usage des mécanismes Kerberos/SSP ; simple bind LDAP actuel n’utilise pas Kerberos, usages RDP à vérifier. |
| `libsndfile` | 0 / 2 | wont-fix: 2 | Parsing fichier audio ; chemin média effectif et options build à confirmer. |
| `libx11` | 0 / 1 | wont-fix: 1 | Bibliothèques X11 transitives ; absence de session X11 prévue ne prouve pas absence de tout appel vulnérable. |
| `libxml2` | 1 / 7 | not-fixed: 7, wont-fix: 1 | Parsing XML ; consommateurs de XML non fiable à inventorier. |
| `libxrender` | 0 / 1 | wont-fix: 1 | Fonctions XRender ; pas de serveur X prévu, chemin effectif non établi. |
| `ncurses` | 0 / 1 | wont-fix: 1 | Traitement terminal/capacités ; entrées et consommateurs à inventorier. |
| `pcre2` | 0 / 4 | fixed: 4 | Compilation/exécution regex via bibliothèque native ; regex contrôlée ou entrée pathologique à vérifier. |
| `perl` | 5 / 8 | fixed: 11, wont-fix: 2 | Usage Perl requis ; CVE8376 spécifiquement build32bits, cibleamd64 ; autres CVE à trier séparément. |
| `python` | 2 / 11 | fixed: 13 | Interpréteur en exécution ; ssl/tarfile/Expat/tempfile selon CVE, dépend de données ou chaîneTLS atteignable. |
| `speex` | 0 / 1 | not-fixed: 1 | Traitement codec audio ; usages guacd/FreeRDP à vérifier. |
| `sqlite3` | 0 / 4 | wont-fix: 3, fixed: 1 | Moteur SQLite présent ; backend produit PostgreSQL ne suffit pas à exclure autres usages/outils. |
| `tiff` | 1 / 0 | wont-fix: 1 | Décodage image TIFF ; aucune entrée TIFF de P1-F identifiée, chemin natif non démontré. |
| `util-linux` | 0 / 8 | wont-fix: 4, fixed: 4 | Outils/bibliothèques système ; préconditions locales/mount/terminal propres à chaque CVE à vérifier. |
| `zlib` | 0 / 2 | fixed: 2 | Décompression native partagée ; flux contrôlable et consommateur nécessaires selon CVE. |

### Preuves, limites et suite de qualification

Preuves hors dépôt : `output/p1-f-image-scan-identity.json`, `p1-f-grype-installation.json`, `p1-f-grype-linux-db-import.json`, `p1-f-grype-linux-scan-execution.json` (échec initial), `p1-f-grype-linux-scan2-execution.json` (scan terminé), `p1-f-os-package-inventory.json`, `p1-f-image-security-findings.json`. Le rapport brut `p1-f-grype-report2.private.json` porte le SHA-256 `f61d41fbac605fa39e5524788979a194a9fee31e64c7471a24154b778d73aba6` ; il n’est pas ajouté au dépôt.

La revue ne revendique ni exploitation démontrée de chacune des CVE, ni audit exhaustif du binaire guacd compilé, ni qualification ARM/NAS. Aucun test destructif ou charge réseau n’a été effectué. Le résultat concerne exclusivement l’archive identifiée en tête. Les ressources du scanner sont de nouveaux conteneurs arrêtés et une cache propre à cette tâche ; aucun volume existant n’est supprimé.

Avant publication utilisable : reconstruire avec interpréteur et paquets corrigés, traiter le risque RDP séparément, relancer le scan complet sur **l’image finale exacte**, puis les tests d’import LDAP, `pip check`, TLS/StartTLS et broker concernés. Conserver les états non corrigés et les limites d’applicabilité dans un suivi révisable ; ne pas ajouter une exclusion générale pour obtenir une CI verte. Le succès des tests applicatifs ou de pip-audit ne remplace pas ce contrôle OS/native.

## Requalification du candidat local avec backport GDI

Le rapport initial ci-dessus est conservé comme preuve de découverte. Un premier remplacement FreeRDP/Python (`86651d…`) a corrigé les versions mais révélé une incompatibilité fonctionnelle de guacd 1.6.0 avec le cycle GDI de FreeRDP ≥3.31. Cette archive reste un témoin, pas un candidat fonctionnel approuvé.

Le candidat suivant intègre un backport ciblé du [commit Apache ab36756](https://github.com/apache/guacamole-server/commit/ab36756b596520ae2a94cd4d25e406e0b5aa820b), distinct du patch P0 qui interdit les redirections. La revue statique indépendante confirme le déplacement de GDI et des handlers dans PostConnect, le maintien de la configuration des canaux dans PreConnect et la conservation des callbacks d’authentification/certificat et du refus de redirection. Le hash des deux patches et le commit amont sont désormais imposés par le vérificateur natif.

| Identité du nouveau snapshot local | Valeur |
| --- | --- |
| Archive | `p1-f-production-gdi-qualified.tar` |
| SHA-256 recalculé indépendamment | `bf5d0075a25d2fc834aa5b21690fac709c62244a5f3330eee8296e1f58512cca` |
| Manifeste OCI | `sha256:0585b52ad0db2aac7e3da04b6cea30f810773e03498583ef06a8b4630d5a6943` |
| Configuration, octets vérifiés dans l’archive | `sha256:cd487974f48fd1ed1c2bbb2f79b1fedc6bbcf5aa790329ff2118155502b80e77` |

Le manifeste natif extrait de l’archive a été comparé au rapport réel en rootfs lecture seule : égalité exacte, `verified=true`, `live_link_probe=true`, 10 ELF et versions API FreeRDP/WinPR 3.33.1, guacd 1.6.0. Les options, chemins de chargement, métadonnées de compilation et deux patches attendus sont contrôlés. Le [contrat d’inventaire et de SBOM](native-supply-chain.md) détaille les limites de cette preuve.

### Résultats du scan exact

Même Grype 0.121.3, base du 11 novembre 2026 validée, aucune règle utilisateur d’ignorance/exclusion (quatre règles kernel internes sans `ignoredMatches` rapporté sur ce témoin), réseau désactivé, un seul scanner séquentiel borné à 256 MiB / CPU 1 / 128 tâches, aucun OOM :

| Mesure | Résultat |
| --- | ---: |
| Analyse complète de l’archive OS/native | terminée en 34,594 s |
| Correspondances / identifiants distincts | 349 / 158 |
| Critical / High | **0 / 102** |
| Medium / Low / Negligible / Unknown | 111 / 20 / 77 / 39 |
| `fixed` / `not-fixed` / `wont-fix` | 14 / 164 / 171 |
| High/Critical avec correctif disponible pour la distribution selon la base | **0** |
| Analyse du SBOM applicatif/compilé avec CPE qualifiés | terminée en 14,547 s, **0 correspondance** |

Le code de sortie de l’analyse OS reste **2**, puisque le seuil High est dépassé. Il n’est pas réinterprété en succès universel. Les résidus OS ont été comparés aux findings du témoin précédent par tuple paquet/version/CVE/sévérité/état/version corrigée : égalité exacte.

Le SBOM de 40 composants préserve les 27 composants applicatifs et ajoute identité de l’image, deux paquets compilés et dix ELF. Les tuples fournisseur/produit CPE sont qualifiés par l’API officielle NVD ; une contre-épreuve de versions anciennes synthétiques déclenche 222 correspondances et les deux CVE attendues. Le contrôle initial avec generic purl seul avait donné zéro et a été identifié comme une lacune de couverture, pas comme un succès. Le scan SBOM ne remplace pas celui des paquets OS.

### Risques résiduels conservés

Les 102 correspondances High représentent 35 couples `(paquet source, CVE)`, répartis sur 13 familles : krb5 (7), cJSON (4), perl (2), Expat (4), ncurses (1), gcc-14 (2), cyrus-sasl2 (1), glibc (3), SQLite (3), libXrender (1), util-linux (4), libX11 (1), acl (2). Aucun de ces couples n’est effacé pour rendre un seuil vert. Leur exposition exige une analyse précise par fonction, composant effectivement lié et entrée contrôlable.

Exemples vérifiés dans le suivi fournisseur : cJSON CVE-2026-67215 vise l’application de JSON Patch par cJSONUtils, krb5 CVE-2026-112314 vise des clients GSS-RPC, Expat CVE-2026-117610 vise un sous-parseur d’entité externe avec découpage spécifique des entrées. Ces préconditions ne sont ni une démonstration d’exploitation ni une exemption de tous les usages du paquet. [cJSON](https://security-tracker.debian.org/tracker/CVE-2026-67215), [krb5](https://security-tracker.debian.org/tracker/CVE-2026-112314), [Expat](https://security-tracker.debian.org/tracker/CVE-2026-117610).

Les 14 correspondances `fixed` restantes concernent pip 25.0.1 (six Medium/Low) et des matches binaires Python 3.12.16 (huit Medium/Low/Negligible). Certaines listes de versions corrigées Python ne mentionnent pas la branche 3.12 : elles doivent être confrontées aux versions réellement affectées et aux plateformes, sans migration aveugle vers une autre branche ni suppression globale des résultats.

Le build amont FreeRDP a aussi produit des avertissements GCC dans des fonctions WinPR. Aucun patch arbitraire ne les masque. La provenance signée et un scan de vulnérabilités ne constituent pas une revue exhaustive de ces chemins C.

### Portée et preuves finales locales

Preuve consolidée : `output/p1-f-gdi-independent-security.json`. Rapports bruts OS `p1-f-grype-gdi-os.private.json` (SHA-256 `fc39e20965d63ae1787bb6c1b71a56d709a803205fc555770403ac6629712d83`) et SBOM `p1-f-grype-gdi-sbom.private.json` (SHA-256 `253c3b3afcdd85b9d454d35185668d23883072b70b54dcffafde89833aa42ed7`). Matrice résiduelle complète : `p1-f-remediated-independent-security.json`, validée identique pour ce candidat. Les versions de scanner/base et durées sont conservées dans les rapports d’exécution dédiés.

L’agent infrastructure rapporte ensuite **10/10 SSH en 42,881 s et 9/9 RDP en 36,118 s**, avec DNS fermé. Les premiers échecs (9/10 SSH, cause non attribuée, et 1/9 RDP en phase préauthentification) restent conservés dans les preuves ; ils ne sont pas retirés de l’historique. La régression P0 ciblée rapporte **193 tests en 263,261 s avec un skip explicitement réservé à SQLite**. Aucun de ces résultats ne constitue une qualification NAS ni une autorisation de publication.

Ce candidat est un snapshot de travail local ; ses bibliothèques sont identifiées, mais il ne doit pas être présenté comme l’image exacte d’un futur commit ou d’un build CI différent. Les annotations de documentation ont été complétées après la construction. Toute publication exige le rattachement au commit approuvé, les qualifications fonctionnelles manquantes et le scan de l’artefact effectivement promu, avec décision explicite sur les risques résiduels.

## Checkpoints B1 et B2 : configuration de scan stricte et pilote système

Le témoin B1 (`p1-f-runtime-20261111-b1-production.tar`, SHA-256 `fda9262804e47baedaac28e57fe27e658294281400fb2f03359b04d4dc7c0fb7`) met pip à jour en 26.3. Son scan **strict** a réellement terminé en 56,047 s, mémoire 256 MiB, sans OOM : **343 correspondances, 0 Critical, 102 High, 106 Medium, 19 Low, 77 Negligible, 39 Unknown**. Les six findings pip ont disparu. La configuration rapportée a `ignore=[]`, `match-upstream-kernel-headers=true`, `include-matcher-suppressions=true` et `ignoredMatches=0`. Ce résultat ne reprend pas les limites de visibilité des premiers témoins. Les High restent 35 couples source/CVE sur 13 familles, sans exemption installée.

Le checkpoint B2 remplace sous Linux psycopg-binary par **psycopg-c 3.2.10** lié à libpq système, afin de supprimer les copies vendored de krb5/gssapi/ldap/sasl/crypto qui échappaient au suivi dpkg. L’archive locale `p1-f-runtime-20261111-b2-production.tar` a pour SHA-256 `91f42cac5b0700f61129b9b136a4626efb1c95c13ee5df95e74c2d9c4c756091`, manifeste `sha256:d0f194f8a34c33ae659c76acad6879414f83a9a7d86f93db672bac7522dbb3a8`, configuration `sha256:bb310bd26a512a93a5cecf7b9e55109a5551878969a1e6baf939080a325f008b`. Hash d’archive et octets de configuration ont été vérifiés indépendamment. Le rescan exact B2 a réellement terminé en **34,813 s**, mémoire 256 MiB, sans OOM : **343 correspondances, 0 Critical, 102 High, 106 Medium, 19 Low, 77 Negligible, 39 Unknown**. Configuration stricte validée, aucune règle `ignore`/`exclude`/VEX et zéro résultat ignoré. Les **35 empreintes source/CVE correspondent exactement** à la politique initiale, toujours toutes `untriaged`. Le résultat B1 ne lui a pas été recyclé. Rapport brut local : `output/p1-f-grype-psycopg-c-strict-os.private.json`.

Le gate driver réel rapporte implémentation C 3.2.10, libpq de build/runtime **170011**, deux extensions ELF et dix-huit dépendances système. La suite complète de transport B2 et les connexions TLS/SCRAM ont leurs preuves séparées. La fermeture de ce vendoring ne prouve pas que toutes les dépendances natives du Python runtime sont recensées : le wheel cryptography utilise notamment sa propre version OpenSSL, à vérifier séparément. Aucun zéro natif global n’est annoncé.

Le checkpoint source inclut **100/100 tests d’outillage en 3,578 s, Ruff réussi**, dont le gate hors ligne, les inventaires, le SBOM, les contrôles driver et DNS. Le contrôle pre-commit sur 612 fichiers a réussi hors réseau ; les faux positifs historiques sont préservés et les nouveaux hashes publics ont été revus individuellement. La politique [image-scan-policy](image-scan-policy.md) bloque volontairement la promotion avec ses 35 entrées `untriaged` ; la revue de triage et l’éventuel backport Kerberos sont des travaux distincts. Le code peut être présenté en revue CI sans fusion main, publication d’image ou déploiement tant que ces blocages ne sont pas levés. Le delta de compatibilité JSON Grype (champ vide `ignoredMatches` omis par le format officiel) a ensuite été validé séparément : **22/22 tests du gate en 0,257 s**, Ruff réussi, sans changement applicatif. Le rapport final CI doit concerner l’artefact exact construit depuis le commit, pas ce témoin local.

## Expat — première intégration dans l'image produit

Le laboratoire exact `3d960926` réussit avec les raisons des douze skips stdlib exportées. Le nouveau Dockerfile produit reprend ces mêmes helpers, runtime/SDK et deux extensions ; le snapshot final et ses limites sont décrits dans [ADR-031](adr-031-expat-product-snapshot.md). Les contrôles de l'archive exacte et le SBOM enrichi restent soumis aux scans exhaustifs, sans modification des seuils ni disposition automatique de CVE.

Validation source : 14 tests produit ciblés et 39 tests PostgreSQL purs passent sans skip ni IO externe ; la revue indépendante ajoute six contre-cas. Le test de merge/schema SBOM complet et la suite native-SBOM complète ne sont pas exécutés sous Windows (import ctypes refusé sous audit) : ils restent obligatoires dans la CI Linux. Construction réelle de cette nouvelle image, snapshot, consommateurs, P0, restauration et scans sont encore attendus. Les succès du laboratoire ne les remplacent pas.

Le premier contrôle Linux du candidat produit `4dd2884` a effectivement exécuté
le nouveau test de fusion SBOM. Il a refusé `reserved_bom_ref` parce que ce test
appliquait au résultat enrichi la garde réservée aux entrées applicatives.
La correction conserve cette garde et son refus explicite ; le test de sortie
appelle le validateur strict et contrôle unicité, fermeture des dépendances et
préservation du graphe applicatif. La contre-revue confirme que les quatorze
autres tests restent identiques en AST, avec trois modèles JSON adverses passés.
Ces modèles ne simulent pas une validation de schéma réussie. Le nouveau passage
Linux strict et la construction de l'image exacte restent obligatoires.

Le build réel de la composition `ddf1ccd` refuse au stage SDK Expat : le paquet
libexpat1-dev dépend de libc6-dev ou libc-dev, absent avant son installation
offline. La recette installe désormais libc6-dev depuis les dépôts Trixie
authentifiés dans le seul stage SDK, avant dpkg. Aucun force-depends ni SDK
dans le runtime final n’est ajouté. Le runtime-base Expat avait passé son oracle
avant ce refus ; ni ce succès partiel ni la correction de recette ne qualifient
la nouvelle image. Les étapes natives, SBOM et scans du run échoué étaient
ignorées ; leur absence ne réduit pas les groupes High à traiter.

### Final-copy metadata comparison diagnostic

The SDK C-header correction passed its install gate, and the runtime verifier
completed, in both the 3ceb Expat and 21ea composed PR runs. The final clean COPY
then refused snapshot_metadata_changed. No qualified image, native tests, SBOM
or CVE disposition is inferred from those builds. The specific differing path
or metadata field has not yet been received.

The follow-up leaves metadata(), all exclusions, equality and the refusal code
unchanged. On refusal only, it emits one bounded diagnostic line (24 records,
16KiB), with closed path classes, path SHA256 values and numeric metadata. File
contents, symlink targets, free paths and unknown fields are excluded. A failed
diagnostic cannot replace or heal the original refusal. This does not prove
content hashes, hardlink topology, source origin, image qualification or serving
authority. Existing fourteen Expat pure methods and four added adversarial cases
are preserved; the composed selection of127 pure tests passes without external
attempts or skips. Full strict schema/native/build/scans still require Linux.

### Correctif du sujet de comparaison des métadonnées

Le diagnostic0f confirme que seuls /proc et /sys diffèrent entre le snapshot
image0755 et le worker0555. Le correctif compare désormais deux racines d'image
montées en lecture seule dans un stage séparé. Le runtime conserve son COPY
scratch et n'importe que le reçu de succès ; aucun root de worker n'est copié.
Le helper, ses exclusions et tous les refus restent inchangés, y compris pour
une vraie dérive /proc ou /sys entre images. Voir ADR031 pour le graphe et les
limites ; le nouveau build/config/archive/native/restore/scan reste à recevoir.
