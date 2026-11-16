# Roadmap d’implémentation et qualification

## État courant du candidat commun — 16 novembre 2026

Le [candidat assemblé P1-F](p1-f-runtime-composition.md) réunit Expat, Jansson,
les observateurs ROOT3/PostgreSQL et la fermeture/drainage de restauration.
Les tests purs de composition passent ; la nouvelle image et ses contrôles
Linux complets restent à recevoir. Aucun résultat isolé ne vaut validation de
la combinaison, aucune nouvelle image n'est promue et le NAS reste inchangé.

Les sections d'essais ci-dessous conservent leurs états historiques et leurs
commits propres. Pour ROOT3, les observations reçues à043d5e6 mesurent bien
containerd/v2.4.2 et passwd999/999 sans autorité opérationnelle ni propriété de
PGDATA. Pour Jansson, les oracles reçus à2f772e7 passent mais le scan reste bloqué
sur31groupesHigh. Ces résultats ne sont pas ceux de la nouvelle composition.
Le diagnostic Chrome896 refuse avant navigateur ; P1-G demeure ouvert.

Réconciliation mise à jour le 14 novembre 2026 avec *Architecture & Roadmap 2026–2029* (pages24–28) et la mission de développement autonome continu. Le programme avance par livraisons qualifiées sans confirmation humaine pour les opérations ordinaires autorisées. Cette autonomie ne permet ni contournement des protections GitHub ni utilisation de comptes ou de systèmes de production.

## Référence réellement publiée

P0 et P1-A/B1/C/D/E sont intégrés dans [main dcaa116](https://github.com/pamolive/PamOlive-Platform/commit/dcaa116be6f026f67ad3825feb38d90ac632ce80), [PR1 fusionnée](https://github.com/pamolive/PamOlive-Platform/pull/1). [CI main réussie](https://github.com/pamolive/PamOlive-Platform/actions/runs/43074618211) :931tests découverts, sortie929tests/42exclusions en702,397s ; les exclusions ne sont pas des réussites. Transports natifs, corpus dédiés, HA sur un hôte et restauration/upgrade disposent de gates séparés.

[Image publiée et attestée](https://github.com/pamolive/PamOlive-Platform/actions/runs/43078536377) : `ghcr.io/pamolive/pamolive-platform@sha256:a3e4cdb647d57cb627b0322569e58cf6760d7107793af3d9b4870ee2f6538981`, linux/amd64. Registre anonyme et attestation vérifiés indépendamment. Ce périmètre reste alpha/laboratoire, pas une qualification de production.

Cette référence publiée précède les remédiations de dépendances Python et
FreeRDP documentées depuis l'audit d'image. Elle ne doit pas être utilisée
avec des comptes privilégiés réels. Une attestation de publication ne supprime
pas ces vulnérabilités ; aucune nouvelle image corrigée n'est encore promue.

Le packaging Synology TLS a été réellement exécuté sur Docker Linux avec Compose2.20.1 : migrations, démonstrateur, HTTPS/MFA, isolation, redémarrage et restauration sur copie. L’ancienne instance NAS a son historique de qualification ; **cette nouvelle image n’est pas installée sur le NAS** au point de départ. Son indisponibilité ou un prérequis manquant ne bloque pas les lots suivants.

## Échelle de statut

Chaque livraison indique séparément : implémenté, testé localement, testé en laboratoire, qualifié sur l’infrastructure cible, puis éventuellement prêt pour la production. Une simulation JSON n’est pas un transport LDAP ; une lecture distante n’est pas une autorisation ; un retrait demandé n’est pas un effet confirmé ; une image publiée n’est pas un déploiement.

## P1-F — Connect / Audit, en cours

Réutiliser SCIM, TeamViewer, outbox, correspondances, reprises et reçus existants. Écart immédiat : les prévisualisations AD/LDAP/Entra sont éphémères et sans transport.

| Livraison | Travail | Réception exigée | Statut |
| --- | --- | --- | --- |
| F1 inventaire | Sources immuables liées à destination/identité TLS, observations persistantes, runs signés et mappings explicites ; vues/API/exports paginés | Deux sources/deux tenants avec mêmes UUID, historique et absence incertaine conservés, aucun droit créé | Implémenté, tests ciblés locaux réussis ; promotion bloquée par le runtime |
| F2 lecteurs | LDAP/AD read-only, pagination et identifiants stables ; préparation Graph tenant-scoped ; serveurs factices TLS | Mauvais pin refusé avant secret, referrals/downgrade refusés, pagination bornée, erreurs partielles sans suppression | StartTLS synthétique local et130tests Directory dans deux CI95fe14f réussis ; LDAPS refusé et Graph partiel ; runtime final non promu |
| F3 rapprochement | Rapprocher inventaire, comptes IAM et confirmations SCIM/TeamViewer sans confondre autorités | Collisions visibles, reprises idempotentes,200identique/409divergent, contexte source historique des retraits conservé | Réuni avec G/P2 dans PR3 `09b6fa43` ; 134/134 PG locaux et portes fonctionnelles CI réussies ; promotion bloquée par les 35 groupes High |
| F4 livraison | Migrations/restauration, export auditable, quotas, supervision et revues adverses | PostgreSQL réel, concurrence, rôles restreints, régressions P0, CI et promotion qualifiée | Campagnes locales partielles réalisées ; gate de scan strict ajouté, promotion bloquée |

Le [candidat PR2](https://github.com/pamolive/PamOlive-Platform/pull/2) reste en brouillon. La première analyse exhaustive de son image a détecté des dépendances Python/FreeRDP vulnérables : aucune fusion ou publication de ce runtime n’est autorisée par ses seuls tests applicatifs. [ADR-019](adr-019-native-runtime-dependencies.md) retient une base corrigée et FreeRDP maintenu compilé depuis une source signée, puis une nouvelle qualification complète et un inventaire des bibliothèques réellement chargées. Le [rapport de scan initial](p1-f-image-security.md) conserve tous les findings ; les travaux de remédiation ne constituent pas encore un résultat vert. Les répertoires F3 et revues P2 du checkout restent distincts du candidat F1/F2.

Mise à jour du12novembre : les deux CI95fe14f passent leurs portes fonctionnelles/PG/natives/HA/restauration mais échouent avant verdict complet du scanner, puis au nettoyage LDAP. Les corrections locales sont testées ; le scanner B2 termine sous son nouveau quota et conserve ses High. B3r3 reconstruit le backport Kerberos après les diagnostics ASN.1 avant/après12cas réussis ; aucun paquet ou runtime B3 n'est encore qualifié. Les35groupes High restent non arbitrés, malgré des propositions individuelles documentées. Les nouveaux formats de décision de build ne constituent aucune exception activée.

Au 14 novembre, le socle courant est `2f28224`. Ses deux CI passent les portes
fonctionnelles, 1345 tests généraux comptés / 42 exclusions, les transports
SSH/RDP et la qualification à deux nœuds avec partition de route PostgreSQL
sur un même hôte, puis restauration et retour arrière. Elles échouent au seul
gate final de scan : 35 groupes High non arbitrés, zéro Critical. Les jobs de
sécurité du code réussissent. Les échecs précédents restent historiques dans
le [rapport daté](p1-f-qualification-20261114.md) et les preuves de PR2.
Le sujet local R8-r2 valide la correction ensurepip par deux vrais venvs hors
réseau avec pip 26.3 ; aucune suppression des couches historiques n'est prétendue.
La chaîne des matériaux APT/SDK/compilateur et attestations ADR-021 demeure
incomplète ; aucune exception ni promotion ne découle de ces résultats.

La [fusion locale F3/G/P2](p1-fg-p2-integration-20261114.md) `4c9cd2b` réunit
les fonctionnalités des branches préservées : 134/134 tests PostgreSQL sans
exclusion, 25 tests enveloppe et 17 tests contrats, revue indépendante et scan
de secrets sur 698 fichiers réussis. La branche PR3 `09b6fa43` ajoute la CI
des bibliothèques installées, réussie dans ses deux runs, avec les contrôles
de sécurité du code. Les 1433 tests généraux comptés / 42 exclusions, transports,
HA même hôte avec partition et restauration passent ; seul le scan final
refuse les 35 groupes High. Aucun
service Vault, registre, ledger ou nouveau chemin PAM P2 n'est livré.

ADR de travail : [ADR-018](adr-018-directory-inventory.md). Les écrivains/provisioning réels restent désactivés tant que leur destination, leurs permissions et leur périmètre ne sont pas qualifiés. Les faits d’annuaire ne deviennent jamais une attestation indépendante PAM.

## P1-G — portail complet, après F

Parcours Identity360 → intention/ticket → politique → approbation indépendante → exécution ou session → observation → évaluation/preuve → audit → retrait confirmé. Conserver le portail serveur natif olive/noir, sans Django admin comme interface métier.

Scénarios : arrivée/mobilité/départ, fournisseur, privilège temporaire, expiration, tentative hors périmètre et provenance insuffisante. Réception : deux tenants aux modules différents, UI/API/MFA/sessions/exports/erreurs, accès clavier/accessibilité, captures de démonstration, cibles et données synthétiques. Les personnes et autorités simulées ne prouvent pas l’indépendance d’humains réels.

Premier incrément réuni dans PR3 : Identity360 propose le formulaire existant prérempli avec identité/compte, sous rôle et module autorisés. GET ne crée aucune autorité et n'alimente jamais un POST incomplet. Les tests des routes et du parcours HTTPS participent aux 134 cas PostgreSQL intégrés ; le service conserve la revalidation de l'autorité sous verrou corrigée dans le socle. Les CI de `09b6fa43` sont terminées avec les limites ci-dessus ; la CI du correctif suivant, la promotion qualifiée et le navigateur headless restent requis. P1-G n'est pas déclaré terminé.

Le [complément HTTP PAM](p1-g-pam-http-validation.md) passe ensuite 5/5 cas
jusqu'au ticket pending, à l'arrêt et à l'audit, avec correction de rendu
et conservation des autorités existantes. La régression de 29 modules compte
324 réussites et une exclusion SQLite attendue sur 325, contrepartie PG
réussie. La qualification navigateur/JavaScript reste distincte et non exécutée.

## P2 — architecture hybride et domaines sensibles

### Expat : laboratoire execute, correction des refus natifs en cours

Le correctif candidat reconstruit Expat2.10.0 sur trixie et les deux modules
CPython3.12.16 pyexpat/_elementtree avec le meme SDK, sans falsifier la capsule
C ni confondre symboles ABI @/@@. Les primaires et sous-cles de signature sont
separees et leurs usages fermes.31tests purs passes et contre-revues source
ne prouvent pas encore les signatures GPG ou les compilations reelles.

Le [laboratoire Linux](../deploy/expat-remediation/README.md) a son Dockerfile
et son workflow distincts, sans modifier le Dockerfile produit ni publier sur
GHCR. Il acquiert10materiaux publics epingles, lance GPG hors reseau, puis
rebuild/tests amont/UBSan/ABI/oracles XML. Les extractions et compilations sont
precedees de verifications de signature dans chaque builder. Les empreintes
source et le contexte Git sont verifies avant emploi ; echec ou preuve absente
ne deviennent jamais une reussite. Le run699 a valide acquisition,31purs,
3signaturesGPGhorsreseau (9enfants rc0/reap/drain) et nettoyage du conteneur.
Le build natif a ensuite refuse read_regular sur /etc/os-release, avant
extraction/compilation Debian. Le correctif lit /usr/lib/os-release sans
resolution/fallback ni modification du lecteur ;33purs locaux passent avec
2contre-cas supplementaires. Le run142 a franchi cette garde puis refuse
le sous-processus dpkg-buildpackage apres environ79s ; ses journaux internes
manquent dans la couche echouee. Le wrapper de cette seule commande publie
sur echec des tails8KiB/flux et le recu4KiB en base64/JSON borne, puis relance
l'erreur. Aucun retry, succes presume ni modification common/H1/auth ;36purs
locaux couvrent aussi plafonds, sorties illisibles et console fermee.
Le run5d a ensuite passe la construction du paquet puis refuse un des deux
make check ; le meme diagnostic borne couvre maintenant ces deux commandes,
stages fermes et controles inchanges. Le run e256eff identifie ensuite
make-buildw-check termine avec code2 : le banc amont refuse UTF-16 sans
wchar_t. Ce refus reste bloquant, sans modifier ABI ni supprimer les tests.

La politique explicite [ADR-027](adr-027-native-python-xml-pgo.md), revue
independamment, retire seulement la paire PGO heritee pour les deux extensions
XML ; LTO, options restantes et controles ABI/capsule sont conserves. Les
48purs passent sans exclusion ni execution externe ; Ruff et Bandit deploy
High passent. Le scan de secrets sur1272fichiers ne trouve aucun nouveau
secret. Aucun profil importe, equivalence de performance ou succes natif
n'est revendique ; wide, SDK et oracles restent a qualifier. Le port test-only
[ADR-028](adr-028-expat-utf16-test-harness.md) conserve444cas C et ABI ushort,
sans nouvelle allocation diagnostic ;58purs preparatoires passent. Paquets
SDK/runtime doivent rester byteexacts, logs/TRS complets narrow/wide et
smoke C++ exporte restent a recevoir. Les compilations negatives C99/C++/type
incompatible restent requises avant qualification finale. Le run408 franchit
le builder Debian et source_audit puis échoue à make -j1 UBSan ; la cause et
les faits du compilateur restent inconnus faute de journaux internes. Un
wrapper de diagnostic fermé couvre les trois commandes UBSan sans changer
leurs conditions ; 61 tests purs passent localement. La réception complète
des journaux/paquets et les autres oracles restent nécessaires, sans admission CVE. Les contrôles négatifs C99/C++/type
incompatible sont maintenant raccordés après le self-test positif ; leur
reçu exige un refus attendu avec H1 et diagnostic exacts, sans modifier UNKNOWN.
La préparation compte 83 tests, sans exécution de compilateur local. Le diagnostic
fa17614 confirme make rc2/H1 complet et aclocal-1.19 absent. La voie release
explicitement prévue désactive seulement le mode de régénération mainteneur ;
UBSan et make check restent obligatoires. 87 tests préparatoires passent ;
le résultat Linux de cette correction reste à recevoir. Les deux CI
Platform e256 sont terminees en echec au scan et aux deux observations, avec
les jobs securite et bibliotheques installees reussis.

La [PR13](https://github.com/pamolive/PamOlive-Platform/pull/13) a par ailleurs
publie les diagnostics : f396 a refuse avant toute operation faute du dossier
workflow dans le checkout partiel ;5c16 ajoute ce seul dossier et ses13purs
passent reellement sous Linux. Ses deux lectures Docker reussissent, puis
la mesure env_tool_before refuse NOT_REGULAR. Aucun root-read, pull ou PG ne
suit ce refus. Le target exact du chemin env n'est pas deduit de ce predicat.
Main dcaa116, image produit et NAS restent inchanges ;35High/provenance
bloquent toujours la promotion. Aucun systeme ou secret reel utilise.

### Ubuntu public observer: source correction under review

The bounded diagnostic on 5c16 refused `env_tool_before/NOT_REGULAR` before
any privileged reader, pull or PG action. The independent branch
`agent/public-env-root-helper` measures the explicit Cargo env executable,
including its hardlink count. Multiple links are permitted only for that env
role; root ownership, regular-file type, safe parents, hash/FD/path stability
and all other tool guards remain required. Current receipts use ROOT/2;
historical ROOT/1 evidence is preserved without current admission.

Integration passes 54 metadata, 39 PG and 14 short pure tests plus Ruff.
The two Docker queries, H1 process tracking and PG owner lifecycle remain
unchanged. The typed version-format diagnostic requires complete inner H1,
a stable valid CTR tool and no post-version operations or authority flags.
Package/suffix strings and raw output stay redacted. The exact admission
grammar and allowlists are unchanged; no unknown version is normalized.
Independent composed-parent fake-process cases cover the initial ambiguous
publication path and its corrected refusal. These tests execute no
Docker, sudo, ctr or SQL. The actual ce29 trial confirms regular root-owned
env with 116 stable hardlinks, then a normal ctr-version process whose output
is refused by the reviewed grammar. Its exact CLI version remains unknown;
no plugin/storage/PG step is admitted.

The PG expected profile now uses core0 then nofile64, matching the explicit
[Docker CLI name sort](https://raw.githubusercontent.com/docker/cli/v29.4.2/opts/ulimit.go).
Only those two constant entries change order; values, exact START checks,
create arguments, ownership and cleanup stay unchanged. 39 PG and 14 short
pure tests pass; independent adverse cases preserve closed refusals. This
does not reconstruct the redacted e256 limit names or qualify a real PG identity.

The exact new branch has its own bounded DATA run; no product image or NAS
change and no A1/W commissioning follows from these source checks.

### Reception ecfe : refus des observateurs et correction ciblee

Les deux campagnes [push](https://github.com/pamolive/PamOlive-Platform/actions/runs/43782571449)
et [PR12](https://github.com/pamolive/PamOlive-Platform/actions/runs/43782608225)
du commit ecfe3c6 sont terminees. Securite303+32+26, PostgreSQL/P0,
transports natifs, restauration et Compose passent ; le general rapporte1479
tests, avec40 exclusions de methodes et deux de classes conservees a part.
Le scan garde35 groupes High non admis. Les deux etapes d'observation echouent
aussi ; leurs resultats ne constituent pas des prerequisites qualifies.
Installed52 et verifier30 de ce meme head sont recus sans erreur ni exclusion.

Les quatre lectures Docker sont recues dans chaque campagne : daemoncontainerd
v2.4.2, mais aucune versionCLI ctr ou propriete des outils root. La lecture
privilegiee refuse avant intention/PID ; sa cause exacte n'etait pas exportee.
Le candidat ajoute codes fermes de phase/predicat et utilise le binaire regulier
sudo-rs documente /usr/lib/cargo/bin/sudo, sans suivre d'alternative ni fallback.
La CLI2.4.2 est examinee separement et admise exactement, pas deduite du daemon.
Les32purs existants et4nouveaux passent, puis6contre-cas independants ; aucune
lecture root reelle de ce nouveau sujet n'est encore recue.

PG a produit8IO completes par campagne, CREATE puis inspect, sans START,
UID/GID ou liberation confirmee. R4 sauvegarde l'ACK CREATE avant inspect,
separe l'identite minimale de nettoyage du profil complet de START et ajoute
une projection publique fermee. Le predicat START reste AST identique ; aucune
forme inspect inconnue n'est admise pour deviner la cause.36purs et6contre-cas
Root passent ; les journaux R3 sans ACK ne sont pas adoptes. La liberation
concerne seulement conteneur/client/bail suivis, jamais des volumes inconnus.

Le workflow court [Public prerequisites DATA only](../.github/workflows/public-prerequisites.yml)
est ajoute sur la seule branche agent/ci-public-observer-diagnostics-ecfe.
Il effectue deux lectures publiques, la lecture containerd, un pull PG public
unique puis le proprietaire R4, sans build APP, SQL ou publication. Il refuse
la suite apres UNKNOWN et conserve les reservations de nettoyage (235s au total,
etape240s/job300s). Les quinze buffers sont epingles avant execution ; le PG
existant est reutilise, sans copie runtime supplementaire.13tests purs passent
dans le layout deploye, dont l'absence du vrai workflow. Ruff du depot passe.
Les mesures reelles du candidat restent a recevoir ; ces DATA ne donnent ni
GO A1/W ni qualification produit et ne remplacent aucune porte Platform.

Le diagnostic Bandit additionnel des sept scripts actifs conserve neuf
signalements examines : sept executions de sources epinglees, un chemin tmpfs
RO /tmp du conteneur et un champ booleen de provenance. Aucun High, nosec,
filtre ou seuil ajoute ; le retour Bandit1 reste documente, pas declare vert.

Aucun correctif produit P0, modele ou migration ne change. La nouvelle CI et
les mesures restent a recevoir ;35High et la provenance bloquent main/image.
Aucun Docker local, GUI, NAS, systeme reel ou secret reel contacte.

### Prochain essai : prerequisites publics containerd et PostgreSQL

Le runner exact4671 utilise Ubuntu26.04. Le nouvel enfant isole emploie
explicitement /usr/bin/python3.14, mesure avant/apres ; aucune resolution
arbitraire de symlink ni supposition de Python3.12. Le vrai essai reste requis.

Les deux Platform4671 et les campagnes distinctes installed52/public30 sont
recues ; seul le scan35High refuse. ServerGitCommitd329809 est une observation
reelle, sans inferrer les versions/roots containerd encore inconnus.
Le prochain candidat raccorde au job existant une sonde getent bornee (26purs,
8adverses) et les exports/statvfs containerd (32purs,6adverses). Les essais reels
restent a recevoir ; aucun profil ni UID/PGDATA n'est attribue automatiquement.
Les anciens gates et permissions sont conserves. Le privelege de lecture sudo
est limite a la VM CI jetable. Les avertissements statiques B102/B108 sont
conserves et tries, sans nosec/ignore ni modification de seuil existant.
A1R2 corrige les redirections du raccord source ; W/VR3 distingue les identites
containerd. Tous deux restent inactifs jusqu'aux profils/commissions et essais
reels requis. Les35High et la provenance bloquent toujours main/image/NAS.

### Etat courant du 16 novembre

PR11 d47faeb recoit ses deux campagnes Platform push/PR : gates applicatifs,
PostgreSQL/P0, W62, natifs, HA meme hote, restauration et Compose passes ; scan
seul en echec avec 35 groupes High. Les 1 479 tests generaux rapportes gardent
40 exclusions de methodes et deux de classes. Le run installe distinct recoit
52 tests sans exclusion et ses cinq controles. Les deux collectes publiques sont recues.
Le rapport public observe Docker29.4.2, API1.54 et stockage containerd overlayfs.
Il distingue maintenant en pratique Id de manifeste et digest de configuration.
Le prochain correctif ajoute ServerGitCommit, sans nouvelle commande, avec huit
tests purs. Ces observations ne donnent aucune autorite au runtime.

Les materiaux publics A1 sont publies et recus comme DATA seulement, sans
load ni execution W3. Les propositions classiques W/V et A1 sont refusees sur
ce runner ; adaptation containerd explicite, profils Root, identite PG et
proprietes PGDATA restent requis avant les essais SQL/mTLS. Les 35 High et
la provenance de build bloquent main/image. Aucune modification NAS.
Voir les [preuves et limites courantes](implementation-status.md).

### Reference precedente du 15 novembre


La source W1 est publiée dans [PR10 `6a9a987`](https://github.com/pamolive/PamOlive-Platform/pull/10).
Les deux CI Platform sont reçues : 62 tests purs W sans exclusion ni tentative
externe, PostgreSQL/P0, natifs, restauration et Compose corroborés. Chacune est
refusée uniquement au scan final, avec 35 groupes High non triés. Les 1 479 tests
généraux rapportés conservent 40 exclusions de méthodes et deux de classes.
Runtime installé52 et vérificateur30
sont reçus séparément pour ce head, sans qualification du service W.
Le prochain incrément ajoute une
[collecte publique du runner et des images locales](../qualification/public_engine_measurement/README.md),
avec sept tests intégrés et treize contre-épreuves indépendantes. La vraie mesure
CI précède toute admission de profil ; elle n'exécute aucun conteneur ni SQL et
n'ouvre aucun contexte privé. Les laboratoires W/V et A1 Linux ont des corrections
de confidentialité et de contrôle de reçu/profil à terminer avant livraison.

La [tranche source W1](p2-usage-anchor-source-qualification.md) ajoute le témoin
indépendant, ses schémas SQL explicites et son client miroir V. Les régressions
locales comptent 62 réussites sans exclusion/tentative externe après les
corrections R2, HTTP et SQL fixe. Une wheel est construite hors ligne et reçue
comme données, sans installation. Les revues et les contrats sont conservés ;
la CI ajoute tests purs et analyse statique W aux gates existants.
Ce lot ne livre ni service opérationnel, ni remise de secret. Prochaine porte :
laboratoire SQL/mTLS W/V neuf, avec permissions, concurrence, panne et reprise.

Le correctif d'acquisition Kerberos est publié dans
[PR9 `acd8bc3`](https://github.com/pamolive/PamOlive-Platform/pull/9).
Ses nouvelles CI installées reçoivent 52 tests runtime et 30 tests vérificateur
public, distincts des tests W. Les campagnes Platform push et PR sont reçues séparément : build et
exclusion réussis, PostgreSQL 17.12, régressions, transports natifs, restauration
et Compose corroborés ; seul le scan refuse les 35 groupes High non triés.
Les deux réceptions conservent leurs artefacts et leurs exclusions, sans transfert.
Aucun résultat ancien n'est transféré au nouveau head.
Les 35 groupes High et la provenance de build incomplète continuent à bloquer
main/image ; aucune mise à niveau NAS.

#### Réception précédente : `27cf3b4`

Le correctif `27cf3b4` reçoit maintenant les **52 tests installés sans erreur,
failure ou skip** dans sa
[CI exacte](https://github.com/pamolive/PamOlive-Platform/actions/runs/43753095373).
Les 16 phases, trois wheels et RECORD, pip, origines/bindings/garde et nettoyage
sont corroborés par les téléchargements Root/NSS et une réception AppSec
indépendante. Le défaut de fixture est fermé pour ce sujet. Voir
[la réception détaillée](p2-vault-runtime-installed-qualification.md).
Prochaine porte : laboratoire W sur PostgreSQL/mTLS réel, clusters W/V neufs,
source et rôles isolés, sans remise. Les tests installés ne le remplacent pas.
Les 35 groupes High et la provenance de build restent bloquants ; aucune
promotion de main/image/NAS.

Autre porte actuelle : la CI générale PR `27cf3b4` s'arrête à l'acquisition de
l'index source Kerberos, avant la sonde d'exclusion des fichiers privés et les
scans finaux. Garder le refus composé unicité/SHA, produire des diagnostics
fermés et tester une acquisition de l'index liée au Release vérifié. Ne pas
attribuer ce run aux 35 groupes High historiques ni présumer une cause miroir.
Le [correctif ciblé](kerberos-index-acquisition.md) est maintenant implémenté
localement : 22 régressions durables et 82 tests ciblés passent, contre-revue
indépendante favorable. La nouvelle acquisition/build réels restent à recevoir.

#### Historique du candidat installé `1e81df6`

Le [lot de qualification installée PR8](https://github.com/pamolive/PamOlive-Platform/pull/8)
reçoit sur `1e81df6` trois builds/installations hors réseau, leurs gates
wheel/RECORD et pip. Les 52 tests installés ont zéro failure, **une error**,
zéro skip ; la campagne reste refusée malgré le nettoyage confirmé. La
correction locale complète explicitement le stage avec le helper public requis,
conserve les 52 méthodes et borne les diagnostics de l'enfant `/3`.
Cette porte est désormais reçue sur `27cf3b4`, comme indiqué ci-dessus. Voir
[les résultats et la limite de diagnostic historique](p2-vault-runtime-installed-qualification.md).
Aucune promotion de main/image/NAS n'en découle.

Le candidat précédent `edec99a`, [PR7](https://github.com/pamolive/PamOlive-Platform/pull/7),
reçoit les régressions sur PostgreSQL17.12 réellement observé par SHOW170012
dans ses [CI PR](https://github.com/pamolive/PamOlive-Platform/actions/runs/43736103902)
et [push](https://github.com/pamolive/PamOlive-Platform/actions/runs/43736048530).
Les portes fonctionnelles et de restauration passent ; les deux scans refusent
toujours les 35 groupes High et la provenance de build reste incomplète.
Le détail exact des exclusions et de la revue est dans
[la réception](postgresql-17-12-qualification.md), sans transfert de succès anciens.
À ce head, le runtime Vault installé restait à qualifier ; le reçu `27cf3b4`
ci-dessus ferme seulement ses tests installés. [ADR-026](adr-026-independent-usage-anchor.md)
accepte ensuite la tranche du témoin d'usage indépendant ; code en développement
local, hors publication de ce lot,
aucune réception W/mTLS/SQL ni remise de secret. Les P0 et anciens chemins restent
préservés. Ni main, ni image nouvelle, ni NAS ne sont promus.

La [PR #6](https://github.com/pamolive/PamOlive-Platform/pull/6), head historique reçu `6cbb4d0`,
reste en brouillon. Les deux CI Platform exactes passent les portes exécutées,
dont acquisition/build et exclusion post-build des credentials, 52 purs Vault,
17 cas adverses du contrôle de wheel comme données,
PostgreSQL, natives, SSH/RDP, HA même hôte, restauration et Compose. Elles refusent
uniquement les 35 groupes High ; la provenance de build reste incomplète.
La suite générale annonce 1 457 tests / 42 entrées Skip (40 méthodes et deux
classes), plus deux marqueurs séparés de 1 skip ; aucun calcul par soustraction
n'est présenté comme réussite. Le vérificateur public installé reçoit séparément
30 tests sans skip. Le timeout TLS du push parent `6c17536` reste un échec
historique distinct, sans transfert rétrospectif du succès courant. Résultats et
corrigenda dans [l'état d'implémentation](implementation-status.md).
Aucun merge main ni image nouvelle.

Le packaging sous [ADR-025](adr-025-vault-runtime-installation.md) est intégré,
sans changement des huit modules ni du schéma SQL. La wheel locale et ses
quatorze fichiers étaient reçus comme données sur ce head ; les tests installés
sous Linux sont ensuite reçus séparément sur `27cf3b4`. Réception CI du head historique :
`cdabdd693f66ae2a0125dccc84d908f61ca1943b80f9642f1eaa91eef044c54a`.
Les résultats précédents `67ee7c9` et `80ccdb1` sont historiques, conservés.

La maintenance [PostgreSQL 17.12 en CI](postgresql-17-12-qualification.md) a reçu
ses régressions au head `edec99a`, avec image immuable et version serveur exigée
avant tests. La qualification de l'image auxiliaire locale et sa restauration
restent distinctes et en attente.
Les bases/volumes locaux existants, le NAS et les garanties P0 restent inchangés.

Le vérificateur public V1 du head `bd8d228` a reçu ses 30 tests installés sans
exclusion dans deux CI dédiées ; les contrôles P0 et leurs appelants demeurent
distincts. Les deux CI Platform exactes passent leurs portes fonctionnelles,
1 439 tests généraux comptés dont 42 exclusions et restauration, puis refusent
les 35 groupes High non arbitrés, zéro Critical. Aucune promotion n'en découle.

Le [lot vertical de réservation Vault](p2-vault-reservation-runtime.md) intègre
les sources R2 sous [ADR-024](adr-024-vault-reservation-boundary.md) : 51 purs et
dix méthodes mTLS/PostgreSQL réellement reçues sur un laboratoire synthétique.
Le bind N0 est ensuite limité aux deux adresses exactes, avec un cas pur ajouté
(52 au total). Un laboratoire distinct reçoit deux nouveaux cas : vrai restart
du service avec PG conservé et writer client jetable sorti par `os._exit(73)`
après commit, puis retry mTLS avec même ligne/dates/nonce privé/audit. Le bind
privé exact est corroboré par code épinglé et TLS. Les dix anciens cas wildcard
restent historiques, sans rejeu ; aucune CI SQL/mTLS du service Vault encore.
Slot administré hors Web, DER par connexion, runtime SQL non-owner et retry
durable aboutissent seulement à `pending_proofs`, sans secret ni autorité d'action.
Pas de migration Django, service de production ou image minimale. Les tests
installés reçus ensuite sur `27cf3b4` ne qualifient pas ce parcours SQL/mTLS.

La réception des deux cas confirme les faits H1, 190 clients CLI récoltés/drainés,
six stdin complets et nettoyage 4/3/1, lease libre et PG inchangé. Les 18 retours
non nuls sont des sondes readiness avant succès ; les quatre exits 137 sans OOM
sont les arrêts de nettoyage prévus. Restent les lots crash réel du serveur et
PG power-loss, perte réseau réelle, expiration attendue, backup/restore avec
nouvelle incarnation et frontière OS Web hostile. L'ancrage indépendant des
usages/compteurs reste nécessaire avant
toute remise ; une tête PAM fraîche ne détecte pas un rollback clandestin du
ledger sous la même incarnation. Ces sources ne soldent ni P2 ni les High.

Premier essai de restauration logique : dump/restauration sous rôle restreint
vers une seconde base synthétique et refus 403 de l'ancien contexte reçus, mais
probe finale après commissionnement en échec. Conserver ce refus et diagnostiquer
avant un nouveau lot ; ne pas prolonger la fenêtre 40 s / TTL 30 s pour réussir.
Nettoyage local complet et PG historique inchangé. Restauration complète, PITR
et reprise sur hôtes indépendants restent à qualifier.

### Historique des préparations et premiers refus

Premier complément du15novembre :
[R1b.1 matériaux publics PAM](p2-public-material-verifier.md), source locale
`77613e8`, ajoute la bibliothèque pure selon [ADR-023](adr-023-public-pam-material-verifier.md).
Les30tests de source et30tests purs d'adaptateur passent, avec13matériaux
audités. Les deux premières CI installées du `7083a96` rendent42 avec nettoyage
confirmé ; la remontée de leur diagnostic interne est corrigée sous revue,
avec57tests purs et cinq contre-cas AppSec. La réception installée reste ouverte.
Cette préparation ne fournit aucun service, contexte commissionné, permission
d'action, ledger ou remise. La correction du banc sur l'incertitude des clients
est conservée. Les décisions de détection Linux sont rapprochées individuellement
des fixtures publiques revues, sans modifier filtres ou seuils. Les prochains contrats devront lier
les actions au transcript V2 puis traiter les compteurs et la consommation
durable ; le registre public ne suffit pas à autoriser une session.

Le monolithe modulaire conserve Identity/Governance/Observe/Connect/Audit métier/Machine/Cloud/Defense/Posture et les contrats d’organisation. Séparer progressivement Web/API, worker, broker PAM, Vault, PostgreSQL, gateway, témoin et gestion des clés. Ne pas créer onze microservices.

1. ADR de frontières et contrats versionnés ; identités de service, authentification mutuelle, audiences, opérations autorisées, timeouts et comportements fail-closed. Aucun fallback silencieux vers un ancien chemin lorsque le nouveau composant est indisponible.
2. Vault indépendant : chiffrement à enveloppe, clés par tenant/domaine, gestion des clés séparée, versions/rotation/récupération. Domaine utilisateur et domaine technique distincts ; MFA révélation/export ; aucune revendication zero-knowledge si le serveur déchiffre.
3. Broker isolé : vérification indépendante des mandats/quorum P0-3, capacités tenant/session/destination/credentialversion/TTL/nonce, relais SSH/RDP, révocation et captures ; aucune clé maîtresse Vault dans le broker et aucun secret technique dans Web/navigateur.
4. Audit témoin séparé : clés et autorité distinctes, checkpoints anti-retour arrière, historique V7/V8, exports SIEM, rétention/quota/rotation.
5. Exploitation : rôle migration distinct du runtime sans DDL, backup/PITR/restauration, métriques/alertes/circuit breakers, tests de panne et charge sur infrastructure dédiée. Ancien chemin maintenu explicitement tant que sa migration n’est pas qualifiée.

Réception par composant : revue cryptographique indépendante, fuite simulée et compromission Web/worker/broker, isolation tenant, révocation pendant session, restauration multi-version et preuves historiques. Docker sur un seul hôte ne constitue pas une indépendance de production. KMS/HSM et plusieurs hôtes réels nécessitent leur qualification dédiée ; une absence d’infrastructure est documentée sans arrêter les autres travaux.

## P3 — capacités enterprise puis qualification

- Privilège : JIT/JEA, commandes/profils/contextes et élévation temporaire explicites, sans assimiler le compte OS complet à du moindre privilège.
- Machine/NHI : comptes techniques/workloads, propriétaires, certificats, fédération et rotation, orphelins et preuve de possession.
- Cloud/CIEM : adaptateurs d’inventaire initialement read-only, permissions effectives et chemins d’élévation explicables, recommandations sans remédiation destructive implicite.
- Defense/ITDR/ISPM : règles versionnées avec confiance/source/explication, dérives, comptes à risque, MFA et postures ; réponses contrôlées.
- Gouvernance avancée : délégations, revues de risque/SoD/fournisseurs, politiques contextuelles et rapports.
- Qualification dédiée : deux hôtes, pertes DB/broker/Vault, transports Windows/SSH, interruptions/révocation, concurrence/charge/mémoire/disque/rétention, reprise et protections cryptographiques. Ne pas annoncer enterprise/production à partir de tests unitaires.

## Porte commune à chaque livraison

Tests unitaires/intégration, PostgreSQL réel, permissions/tenants/concurrence, migrations et retour arrière sur copie, restauration, Docker, Ruff/Django, dépendances/SBOM/secrets et revue Red Team. Les échecs sont corrigés ; les exclusions et limites sont explicites. Pour Vault/PAM : revue crypto et tests de fuite/panne/révocation obligatoires.

Branche → modifications/tests/revue → commit/push/PR → CI vérifiée → fusion conforme aux protections → CI du main exact → promotion de son image sans rebuild → digest/attestation vérifiés → statut mis à jour → lot suivant. Aucun force-push destructeur, aucune désactivation de protection, aucune publication arbitraire stable/latest.

## Relation avec l’ancien ordre d’implémentation

L’ancien document décrivait contrats → noyau → IAM → gouvernance → PAM. Ce sont des dépendances historiques déjà partiellement ou largement implémentées, pas de nouveaux lots à réécrire. Les ADR encore proposés restent visibles dans leur index ; l’autonomie technique ne les rend pas rétroactivement qualifiés. Le worker/outbox PostgreSQL actuel est réutilisé ; Redis n’est pas ajouté sans besoin démontré et ADR.

## Expat : succès du laboratoire, produit encore en qualification

Le run [43823586567](https://github.com/pamolive/PamOlive-Platform/actions/runs/43823586567) du `549b0cd` réussit : C narrow/wide, UBSan, ABI et extensions Python. La suite stdlib rapporte 490 tests et 12 skips sans leurs raisons exportées. Le candidat de visibilité conserve tous les plafonds et porte les tests purs à 96 ; la preuve native suivante reste attendue. [Détails et limites](../deploy/expat-remediation/README.md). L'image produit reste distincte, sans fermeture des groupes High ni promotion induite.

## P1-G — premier parcours JavaScript préparé

Un [banc Chromium de CI](../qualification/p1g_headless/README.md) exerce les formulaires de connexion/MFA, WebAuthn, demande Identity360 et deux votes, sans contrôle du navigateur du PC. Les dix contrats purs passent ; le navigateur, PostgreSQL et les sélecteurs restent à qualifier réellement. Le job est limité à sa branche et audite ses outils supplémentaires. Les observations PC-483/PC-991 restent des fixtures historiques distinctes ; le retrait cliqué concerne un nouveau droit local, sans preuve fournisseur. Le [raccord SSH/RDP](../qualification/p1g_headless/NEXT-NATIVE.md) doit encore confirmer transport, expiration, révocation et capture avant de qualifier P1-G complet. Aucun changement des modèles ou contrôles P0.

La garde de délais du témoin PostgreSQL conserve ses maxima stricts. Un contre-exemple flottant reproductible pouvait produire une réserve légèrement supérieure à trente secondes ; le constructeur arrondit maintenant vers le début et reste plafonné par les anciennes échéances. Aucun seuil ni comportement UNKNOWN n'est élargi. La reproduction et les parcours CLI sous horloge contrôlée sont conservés ; ce correctif arithmétique ne prouve pas la valeur d'horloge du run historique en échec.

## Expat — première intégration dans l'image produit

Le laboratoire exact `3d960926` réussit avec les raisons des douze skips stdlib exportées. Le nouveau Dockerfile produit reprend ces mêmes helpers, runtime/SDK et deux extensions ; le snapshot final et ses limites sont décrits dans [ADR-031](adr-031-expat-product-snapshot.md). Les contrôles de l'archive exacte et le SBOM enrichi restent soumis aux scans exhaustifs, sans modification des seuils ni disposition automatique de CVE.

Validation source : 14 tests produit ciblés et 39 tests PostgreSQL purs passent sans skip ni IO externe ; la revue indépendante ajoute six contre-cas. Le test de merge/schema SBOM complet et la suite native-SBOM complète ne sont pas exécutés sous Windows (import ctypes refusé sous audit) : ils restent obligatoires dans la CI Linux. Construction réelle de cette nouvelle image, snapshot, consommateurs, P0, restauration et scans sont encore attendus. Les succès du laboratoire ne les remplacent pas.

## Public Engine : identité CLI ROOT3 en qualification

Les observations réelles du candidat `1e66df2` n'identifient que le format et la version numérique 2.4.2 ; le package masqué reste inconnu. [ADR-029](adr-029-public-containerd-cli-identity.md) retient huit couples package/version exacts documentés, avec un schéma typé ROOT3 ; aucune normalisation de marque ni apprentissage depuis une observation refusée. Les anciens schémas restent historiques.

La revue contradictoire a refusé une première version pour sa projection d'identité diagnostique insuffisamment liée au contexte du processus. R2 exige le même contexte strict avant toute publication de format ou d'identité : processus terminé normalement, flux complets, outil stable et aucune autorité ni requête suivante. Les 65 tests métadonnées, 39 PostgreSQL purs et 14 tests courts passent sans skip ni IO externe. Les 19 fichiers PostgreSQL et les douze lignes de son payload restent inchangés. La nouvelle mesure Linux demeure requise ; ces tests ne constituent ni une mesure UID PostgreSQL ni une autorisation opérationnelle.

La garde de délais du témoin PostgreSQL conserve ses maxima stricts. Un contre-exemple flottant reproductible pouvait produire une réserve légèrement supérieure à trente secondes ; le constructeur arrondit maintenant vers le début et reste plafonné par les anciennes échéances. Aucun seuil ni comportement UNKNOWN n'est élargi. La reproduction et les parcours CLI sous horloge contrôlée sont conservés ; ce correctif arithmétique ne prouve pas la valeur d'horloge du run historique en échec.

## Qualification Jansson en cours

Le backend natif est en qualification sur une branche indépendante ; les tests purs ne valent pas livraison. Voir [preuves et limites](p1-f-jansson-qualification.md) et [ADR-030](adr-030-jansson-native-json-backend.md). Aucune donnée ni migration métier modifiée.

### Active qualification work: runtime composition and browser authentication

The headless candidate incorporates PR #19's runtime fixes. Next gates are an
actual successful image build and unchanged strict security scans, receipt of the
bounded GPG authentication diagnostic, then actual portal and native-session
assertions. Restore coverage must additionally exercise historical V7, Governance
and independently anchored PAM trust data on synthetic PostgreSQL. Pure tests
and a partial restore corpus do not close these gates.

### Porte de restauration synthétique élargie

Les quatre tests PostgreSQL du corpus enrichi ont passé sans skip. Recevoir
ensuite une vraie sauvegarde/restauration avec V7, V8, Governance et confiance
PAM historique.
Recevoir le JSON public lié au source/image exacts et à l'étape réussie, tout
en conservant les refus de clés, l'isolation concurrente et les nettoyages.
La promotion reste aussi conditionnée au build natif et au scan strict ;
la qualification du corpus n'autorise aucune reprise live ou écriture NAS.

### Réception PostgreSQL et intégration du snapshot image

Le run [43870177687](https://github.com/pamolive/PamOlive-Platform/actions/runs/43870177687)
a exécuté les quatre tests dédiés du corpus sur PostgreSQL :4 tests,11.871s,
aucun skip. Le job image avait échoué avant dump/restore ; aucun reçu de
restauration du corpus étendu n'est transféré de ce run.

La branche restore intègre maintenant le correctif runtime75813d8 comparant
deux vues image immuables, plutôt qu'une image et les montages live du worker.
Les octets des helpers et tests restore demeurent identiques au candidatbae ;
les seuils, ancrages, vérificateurs et nettoyages restent exacts. La restauration complète du corpus étendu est maintenant reçue au run5ee62e4,
sous réserve de la réception indépendante du rapport et de ses liens image/source.
Les scans stricts restent bloquants ; aucun réarmement PAM live ni accès NAS.

### Restauration étendue réelle et correction du répertoire de preuve

Le [run5ee62e4](https://github.com/pamolive/PamOlive-Platform/actions/runs/43891400303)
a réussi le dump/restore en12.958s :106modèles,82preuves signées,3reçus de
provenance,1observationlegacy/1évaluationV7,3preuvesGovernance,1registrePAM
et2autorisationspersonnelles,1capture scellée et1preuvecertificat. Les flags
de refus des mauvaises clés/mots de passe et d'isolation/nettoyage sont vrais ;
safe_to_serve restefalse et le PAM live exige un checkpoint courant indépendant.

Le job a ensuite refusé au mkdir exclusif de l'inventaire/SBOM : le nouveau
rapport restore avait créé son répertoire réservé. Cette intégration de chemin
était incorrecte. Le reçu va désormais dans un répertoire restore-public dédié,
créé frais en0700 et publié par son seul fichier JSON nommé. Le mkdir exclusif
du scan, les vérificateurs, les helpers restore et leurs plafonds restent exacts.
La reproduction réelle et un test du cycle des deux répertoires sont conservés.
Ce succès restore ne vaut pas succès SBOM/scan ou qualification globale ; leur
rejeu du candidat corrigé reste requis. Aucun accès NAS ni reprise de production.
