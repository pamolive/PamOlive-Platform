# État réel de l’implémentation

## Livraison du code de développement — 17 novembre 2026

À la demande explicite du propriétaire, la capture Expat APT et ses diagnostics
sont intégrés à main avec le contrat de contexte typé et le diagnostic navigateur.
Cette livraison conserve les historiques et tous les gardes de publication.
Elle ne qualifie ni une image, ni une installation, ni la plateforme complète.

Le dernier main reçu, 7abcdae, a passé le probe Linux de contexte typé,
les jobs Vault et vérificateur PAM installés. La suite PostgreSQL compte
1 665 tests au total, dont 42 ignorés, sans échec ni erreur ; Directory compte
130 tests sans skip. Les builds Docker aboutissent, puis le scan refuse
110 correspondances High OS regroupées en 35 groupes ; le scan compiled
ne trouve aucune correspondance. Aucun garde n'est désactivé et aucune image
n'est publiée. Ces résultats appartiennent à ce SHA, pas à la fusion suivante.

Sur la branche navigateur au même SHA, le bootstrap APT refuse encore rc100 ;
aucun reçu installed/2 ni test UI n'est validé. Le job navigateur est ignoré
sur main par sa restriction de branche existante. Les tests dédiés de modules
signés et d'extension image ont chacun un skip supplémentaire ; ils ne sont
pas présentés comme des suites entièrement réussies.

La capture Expat a vérifié les trois signatures de dépôts, puis refusé la
simulation APT sans approbation de matières ni installation. Ses diagnostics
fermés passent 61 tests purs sans skip et une revue indépendante. Ils gardent
le refus original et ne constituent pas une correction de la cause native.
Le nouvel arbre doit refaire sa CI exacte. Les brouillons de recherche non
intégrés, secrets et preuves privées restent hors publication. Aucun NAS ni
système réel n'est contacté. Aucun déploiement n'accompagne ce push.

## Notes historiques et détails des étapes précédentes

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
## P1-G — premier parcours JavaScript préparé

Un [banc Chromium de CI](../qualification/p1g_headless/README.md) exerce les formulaires de connexion/MFA, WebAuthn, demande Identity360 et deux votes, sans contrôle du navigateur du PC. Les dix contrats purs passent ; le navigateur, PostgreSQL et les sélecteurs restent à qualifier réellement. Le job est limité à sa branche et audite ses outils supplémentaires. Les observations PC-483/PC-991 restent des fixtures historiques distinctes ; le retrait cliqué concerne un nouveau droit local, sans preuve fournisseur. Le [raccord SSH/RDP](../qualification/p1g_headless/NEXT-NATIVE.md) doit encore confirmer transport, expiration, révocation et capture avant de qualifier P1-G complet. Aucun changement des modèles ou contrôles P0.

La garde de délais du témoin PostgreSQL conserve ses maxima stricts. Un contre-exemple flottant reproductible pouvait produire une réserve légèrement supérieure à trente secondes ; le constructeur arrondit maintenant vers le début et reste plafonné par les anciennes échéances. Aucun seuil ni comportement UNKNOWN n'est élargi. La reproduction et les parcours CLI sous horloge contrôlée sont conservés ; ce correctif arithmétique ne prouve pas la valeur d'horloge du run historique en échec.


### Current headless candidate qualification follow-up

The P1-G candidate now composes PR #19's Expat/Jansson/restore runtime and its
Expat SDK C-header fix. Selected pure contract suites passed (293 tests before
the GPG diagnostic delta, then 15 bootstrap and 14 unchanged UI tests rerun).
The actual prior browser run refused authenticate/status_bad before package
installation or UI execution. A bounded public GPG diagnostic was independently
reviewed; it leaves all signature and installation guards unchanged. No successful
browser execution, complete P1-G, qualified image promotion or NAS deployment
is inferred. The new Linux CI is the authority for runtime outcomes.


### P1-G — certificat de navigateur et restauration, intégration locale du 16 novembre 2026

Le merge local 2836fd2 conserve les correctifs de restauration du candidat 94064bc,
avec 204 tests de contrats purs et le contrôle de secrets sur 1 332 fichiers réussis.
Les preuves natives de 94064bc restent liées à ce candidat ; elles ne qualifient
pas une nouvelle image issue du merge.

ADR-034 est implémenté pour une qualification dédiée sous Ubuntu 24.04 :
certificat Google limité au signer déjà autorisé, lignée des paquets contrôlée,
revérification indépendante par le superviseur root, et fixtures GPG synthétiques
sous agent possédé. Les quatre matériaux Google et les prédicats cryptographiques
existants sont inchangés. La fermeture des sources compte 25 fichiers vérifiés
depuis l’index Git ; les huit fichiers du producteur de fixtures sont conservés
exactement. Les 86 tests purs passent, sans accès natif, réseau, base ou navigateur.

La matrice distingue les refus cryptographiques natifs, les gardes sur sorties
natives, les contrôles de données et les modèles de branches. Une réussite des
modèles ne constitue pas une signature authentifiée. Les signatures, la durée
de vie de l’agent, son nettoyage, l’installation et le parcours navigateur doivent
encore être confirmés sur une nouvelle CI liée à ce commit. P1-G reste incomplet.
Le scan strict de l’image 94064bc reste bloquant ; aucune qualification ou
publication de cette nouvelle image, fusion dans main ou modification NAS.

## Notes conservées de la branche Kerberos expérimentale


### Laboratoire Kerberos1.22.3 en préparation

ADR033 accepte uniquement une collecte Linux source/ABI/GSS isolée. Les hunks
produit ne sont pas appliqués et le profilv2 reste admitted:false. Les37 tests
N0 et la revue indépendante ferment deux défauts de contrat avant la collecte ;
GPG, compilation, ABI, skips, GSS/KDC et scans doivent encore être reçus.
Aucune correction de CVE n'est déclarée depuis la seule version amont.

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

Le document de vision décrit la cible complète. Cette branche construit progressivement cette cible ; elle ne constitue pas encore une version de production.

## Programme autonome : référence et travail courant

La [roadmap réconciliée](implementation-roadmap.md) distingue désormais les lots P1-F/G, P2 et P3 du premier ordre historique. Référence publiée : main `dcaa116be6f026f67ad3825feb38d90ac632ce80`, PR1 fusionnée, [CI complète réussie](https://github.com/pamolive/PamOlive-Platform/actions/runs/43074618211) et [image GHCR publiée/attestée](https://github.com/pamolive/PamOlive-Platform/actions/runs/43078536377). Les résultats détaillés P0/P1 demeurent dans leurs rapports ; leur portée historique est conservée.

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

### Mesures publiques du 16 novembre : prochain essai CI borne

Le runner exact4671 utilise Ubuntu26.04. Le nouvel enfant isole emploie
explicitement /usr/bin/python3.14, mesure avant/apres ; aucune resolution
arbitraire de symlink ni supposition de Python3.12. Le vrai essai reste requis.

Les deux campagnes Platform de la [PR11 4671f6f](https://github.com/pamolive/PamOlive-Platform/pull/11)
sont recues : dix ZIP/114 membres verifies, memes gates PostgreSQL/P0, W62,
transports, HA meme hote, restauration et Compose ; seuls les scans35High
refusent. Les suites security303+8 passent. Les campagnes distinctes runtime52
et verifier30 sont aussi recues sans echec/erreur/exclusion, avec nettoyage.
ServerGitCommit=d329809 est maintenant reellement recu sur les deux rapports,
avec Docker29.4.2/API1.54/min1.40 et le CLI3e898 deja decrit ci-dessous.
Aucune preuve du head precedent n'a ete transferee.

Le nouveau candidat conserve ces quatre lectures Docker et ajoute une lecture
publique bornee des vrais exports containerd et de leur filesystem. Un unique
enfant sudo-n est autorise uniquement dans la VM GitHub-hosted jetable, jamais
sur PC/NAS. Il interroge ctr --version local puis Plugins pour le seul CLI2.2.3
examine ; un autre CLI refuse Plugins. L'environnement supprime l'appel Server
indirect de NewClient ; ctr version, Server/UUID et les configurations privees
sont exclus. Parent et deux CLI imbriques exigent H1 complet/outils stables.
Les trois journaux d'intention/PID/resultat sont publies sans streams bruts.
32 tests purs et six contre-epreuves independantes passent ; aucun disque,
endpoint ou profil operationnel n'est auto-admis a partir de ces donnees.

La [sonde PG publique](../qualification/public_pg_identity_probe/README.md)
cree un seul conteneur getent confine, depuis le manifest PG deja local :
CPU0.10/RAM64MiB, netnone, rootfsRO, caps0/NNP, aucun port/bind/volume anonyme,
PGDATA couvert par tmpfsRO. Elle publie seulement UID/GID apres arret/suppression
et H1 confirmes ;26purs et huit contre-epreuves independantes passent. Un create
perdu et deux cleanup conservent UNKNOWN/leaseheld. Ni SQL ni serveur PG ne sont
lances, aucun UID999 ou droit PGDATA n'est suppose. Le fragment est place apres
le scan strict et avant la mesure containerd ; les anciens gates/permissions
sont preserves. Aucune execution reelle de ces deux essais n'est encore recue.

Les sources et manifests sont conserves byte-exacts par des attributs Git
limites aux deux dossiers de qualification. Seuls deux imports de tests ont ete
reordonnes pour la configuration Ruff du projet ; aucun asset runtime n'a change.
L'analyse Bandit complementaire des quatre nouveaux scripts actifs emet quatre
B102 et un B108, conserves et examines individuellement : exec compile seulement
les buffers source verifies par SHA/ensemble ferme avant emploi (dont la classe
Lease recue), et /tmp designe un tmpfs RO du conteneur getent, pas un fichier
hote partage. Ce diagnostic n'est pas une sortie Bandit verte ; aucun nosec,
filtre ou seuil de securite existant n'est ajoute/modifie pour ces points.

La contre-revue A1 a reproduit trois routes de redirection dangereuses dans le
raccord inactif, avec transport memoire sans reseau. Le candidat R2 les refuse
avant contact et borne le worker via H1 :11cas auteur+4contre-cas Root passent.
Il reste inactif, en attente du sujet containerd et des profils/commissions.
La source W/V containerd R3 passe37purs+10contre-cas Root, mais garde son HOLD
stockage/getent/PGDATA avant toute preparation privee. Aucune nouvelle remise
de secret, migration produit ou session PAM n'est ouverte par ces observateurs.

Main reste dcaa116 ;35High et la provenance de build incomplete bloquent
fusion/image. Aucun Docker local, GUI, NAS, donnees reelles ou production touches.

### Reception du 16 novembre : PR11 et donnees publiques du laboratoire

La [PR11 d47faeb](https://github.com/pamolive/PamOlive-Platform/pull/11) publie
le collecteur de metadonnees. Sa [CI PR](https://github.com/pamolive/PamOlive-Platform/actions/runs/43770422458)
et sa [CI push](https://github.com/pamolive/PamOlive-Platform/actions/runs/43770333284)
sont recues separement : PostgreSQL17.12/P0, W62 purs, natifs, HA sur un hote,
restauration et Compose passent. Chaque campagne rapporte 1 479 tests generaux,
40 exclusions de methodes et deux de classes. Seul le scan strict echoue, avec
35 groupes High ; les deux observations publiques et uploads ont reussi.
Le [run installe distinct](https://github.com/pamolive/PamOlive-Platform/actions/runs/43770422438)
a aussi ete recu avec 52 tests, zero echec/erreur/exclusion, cinq controles de
reception et nettoyage confirmes. Ces resultats ne qualifient pas le service W.

Le rapport public PR mesure CLI/Engine29.4.2, API de decouverte1.54/min1.40,
Linux/amd64, overlayfs et io.containerd.snapshotter.v1. L'outil est regulier,
UID/GID0, mode0755, taille45 526 415, SHA3e898b1e7498b1bf98ec29a3d2ce77f9f09dd357e0b8dbf6ca69b463a871de88.
Les quatre lectures et la stabilite du binaire sont confirmees. L'Id inspecte
PostgreSQL correspond au manifeste6f7593, distinct de sa configuration140936 ;
les profils de laboratoire classiques doivent refuser cette representation.
L'Id d'image applicative est egalement distinct de son digest de configuration.
Aucune observation ne devient automatiquement un profil admis.

Le correctif suivant ajoute la donnee publique ServerGitCommit manquante pour
le profil A1 : meme requete version, hexadecimal ferme ou redaction, aucun
nouvel appel. Huit tests purs passent, sans exclusion ni tentative externe ;
les sept cas precedents sont conserves. Une nouvelle CI reste necessaire pour
recevoir ce champ : il n'est pas infere depuis la version du serveur.

Les [materiaux publics A1/W3](https://github.com/pamolive/PamOlive-Platform/releases/tag/data/a1-w3-inputs-20261115-dff762b7)
sont livres comme DATA uniquement, en preversion non-latest : TAR40 membres,
46 643 200 octets, SHAdff762b7743d10314a5e386e50bc223f87f0e96c8d0ebe9a316315871c6105d8,
manifeste SHA2c6c31440779ed422eaffd3e65ebc91d8ce0019ef35c2ac1af042414e43d8eae.
Revue source, reception locale exacte du TAR et revue des notes sont favorables ;
les deux assets distants ont aussi ete recus et rehashes independamment. Ce
n'est ni une image produit ni une execution W3 : son modele classique reste
incompatible avec le runner containerd observe. Les metadonnees privees et
anciennes propositions d'autorisation sont exclues de la livraison publique.

Main reste dcaa116, sans nouvelle image PamOlive ni ecriture NAS. Les 35 High
et la provenance de build incomplete restent bloquants. Prochaine porte :
adaptation explicite containerd des laboratoires, profil Root externe, identite
PostgreSQL et proprietes PGDATA avant W/V SQL/mTLS ou execution A1.

### Reference precedente du 15 novembre : source W et qualification CI

La source W1 est publiée dans la [PR10 `6a9a987`](https://github.com/pamolive/PamOlive-Platform/pull/10).
Ses deux campagnes Platform sont reçues séparément : 62 tests purs W sans
failure/error/skip/tentative externe, PostgreSQL/P0, transports natifs,
restauration et Compose corroborés. Chacune rapporte 1 479 tests généraux avec
40 exclusions de méthodes et deux de classes, sans les compter comme réussites.
Le seul échec reste le scan final, 35 groupes High non triés, zéro finding ignoré.
Les campagnes distinctes
runtime installé (52 tests) et vérificateur public (30 tests) du même head sont
reçues indépendamment, avec ZIP et nettoyage vérifiés. Elles ne qualifient pas W.

Une [collecte publique Docker/Engine](../qualification/public_engine_measurement/README.md)
est maintenant intégrée : quatre lectures fixes et les attributs du binaire
Docker (type, propriétaire, permissions, taille et SHA), sans création, démarrage ou
téléchargement d'image, sans SQL ni lecture d'environnement applicatif. Sept
tests depuis le dépôt et treize contre-épreuves indépendantes passent sans I/O
opérationnelle. La CI ajoute ces observations après ses gates stricts, avec
rapport public projeté et sans acceptation automatique d'un profil. La première
exécution réelle reste à recevoir ; ses résultats serviront à fixer le profil
du prochain laboratoire avant toute donnée synthétique privée.

Les propositions de laboratoire W/V et de témoin A1 Linux restent hors livraison.
Leurs revues ont relevé des métadonnées locales à exclure des dérivés publics ;
le laboratoire W/V doit aussi recevoir l'admission exacte du profil hôte et
compléter son parseur de reçu. Aucun contexte privé n'est démarré pour ces lots.

La [source W1](p2-usage-anchor-source-qualification.md) est implémentée localement,
avec 62 tests purs réussis sans exclusion ni tentative d'I/O externe et revue
indépendante. Le demandeur de l'intention est fixé par W, les mutations Service
ont leur contrôle final et les observations terminales conservent leurs contrôles
d'identité/contexte. Le correctif HTTP conserve le profil fermé du serveur.
La wheel de développement est construite hors ligne et vérifiée comme données ;
elle n'est pas installée. Aucun SQL/mTLS réel ni service W n'est réceptionné.
La CI ajoute ses tests et son analyse statique sans retirer les anciens gates.
Le laboratoire réel W/V est la prochaine porte ; il reste distinct de la source.

Le [correctif CI PR9](https://github.com/pamolive/PamOlive-Platform/pull/9),
`acd8bc3`, publie l'acquisition Kerberos par hash authentifié. Ses campagnes
[runtime installé](https://github.com/pamolive/PamOlive-Platform/actions/runs/43759468228)
et [vérificateur public](https://github.com/pamolive/PamOlive-Platform/actions/runs/43759468205)
reçoivent respectivement 52 et 30 tests sans failure/error/skip, avec vérification
des artefacts et nettoyage. Ces deux campagnes ne qualifient pas W.
Les CI générales [push](https://github.com/pamolive/PamOlive-Platform/actions/runs/43759420683)
et [PR](https://github.com/pamolive/PamOlive-Platform/actions/runs/43759468105)
sont reçues séparément : build et exclusion des fichiers privés réussis, PostgreSQL 17.12,
régressions, transports natifs, restauration et Compose corroborés. Chaque run échoue
uniquement au scan final : 35 groupes High non triés, zéro finding ignoré.
Les 1 479 tests généraux rapportés conservent 40 exclusions de méthodes et deux
de classes ; ces exclusions ne sont pas des réussites.
Le checkout merge de la PR a l'arbre exact du head ; les deux ensembles d'artefacts
et journaux sont rehashés indépendamment, sans transfert de résultat entre runs.
Main reste `dcaa116`, sans nouvelle image ni écriture NAS ; les 35 groupes High
et la provenance de build incomplète bloquent toujours la promotion.

### Réception précédente du 15 novembre : candidat `27cf3b4`

Le correctif `27cf3b4` de la [PR8](https://github.com/pamolive/PamOlive-Platform/pull/8)
reçoit sa [CI installée exacte](https://github.com/pamolive/PamOlive-Platform/actions/runs/43753095373) :
**52 tests, zéro failure/error/skip**, 16 phases, trois wheels/RECORD et deux
contrôles pip réussis. Root et NSS vérifient chacun le ZIP réellement téléchargé ;
la réception sémantique Root puis la contre-revue AppSec confirment les quatre
JSON, leurs bindings et le nettoyage distinct. Les imports du helper sont
paresseux, son banc passe sans site-packages et les 52 méthodes sont conservées.
Voir [le reçu et sa portée](p2-vault-runtime-installed-qualification.md).
Le lot suivant prépare le vrai laboratoire PostgreSQL/mTLS W sur CI Linux isolée ;
aucune réception W réelle ni remise de secret n'en découle.
Main reste `dcaa116`, sans nouvelle image ou mise à niveau NAS. Les 35 groupes
High et la provenance de build incomplète bloquent toujours la promotion.

La [CI générale PR du même sujet](https://github.com/pamolive/PamOlive-Platform/actions/runs/43753095371)
est refusée pendant la reconstruction Kerberos de l'étape construction/exclusion :
le contrôle composé « entrée SHA256 unique et hash de Sources.xz conforme au
Release signé » échoue. L'unicité et le hash ne sont pas distinguables dans ce
rapport historique. Les signatures et gardes précédentes ont passé ; la sonde
d'exclusion des fichiers privés et les scans finaux ne sont pas atteints.
L'hypothèse d'une rotation de miroir n'est pas démontrée sans les bytes du
builder. Une correction ciblée de l'acquisition et des diagnostics est
implémentée localement sous revue : [index par hash](kerberos-index-acquisition.md),
22 régressions durables et 82 tests ciblés réussis sans skip. La nouvelle CI reste
à recevoir ; aucune garde n'est supprimée. Ce refus reste distinct
du reçu des 52 tests installés.

### Historique du défaut de fixture : candidat `1e81df6`

Le [candidat PR8](https://github.com/pamolive/PamOlive-Platform/pull/8),
`1e81df6`, construit et installe réellement les trois composants Vault hors
réseau dans sa [CI dédiée](https://github.com/pamolive/PamOlive-Platform/actions/runs/43747230903).
Les wheels et leurs RECORD passent, ainsi que les deux contrôles pip ; les
52 tests installés rendaient zéro failure, **une error**, zéro skip. Les 16
processus et le nettoyage sont reçus ; aucun succès installé52 n'est déclaré.
La correction locale ajoute la fixture publique manquante, garde les 52 méthodes
intactes et apporte des diagnostics fermés enfant `/3`. La contre-revue et la
nouvelle CI sont maintenant reçues sur `27cf3b4`, comme indiqué ci-dessus. Voir
[la réception détaillée](p2-vault-runtime-installed-qualification.md).
Main reste `dcaa116` ; aucune nouvelle image ni mise à niveau NAS.

### Réception précédente : PostgreSQL 17.12 et réservation limitée

Le candidat précédent reçu est `edec99a`, parent `6cbb4d0`, dans la
[PR7 en brouillon](https://github.com/pamolive/PamOlive-Platform/pull/7).
Les [CI PR](https://github.com/pamolive/PamOlive-Platform/actions/runs/43736103902)
et [push](https://github.com/pamolive/PamOlive-Platform/actions/runs/43736048530)
confirment réellement `SHOW server_version_num=170012` et passent leurs portes
PostgreSQL/P0/migrations, SSH10/RDP9, HA même hôte, restauration et Compose.
La suite annonce 1 457 tests avec 42 entrées Skip (40 méthodes et deux classes),
plus les marqueurs séparés 1+1. Les 52 purs Vault/17 cas de wheel DATA restent
distincts du [vérificateur installé30](https://github.com/pamolive/PamOlive-Platform/actions/runs/43736103912).
Chaque Platform échoue uniquement au scan final : 35 groupes High non arbitrés,
102 High sur 349 OS, zéro Critical/ignoré, compiled0. La contre-revue AppSec
reçoit les preuves exactes (gel `a50643da…`), sans prétendre reconstituer les ZIP
bruts non conservés. Voir [la réception PostgreSQL](postgresql-17-12-qualification.md).
Aucun changement de main, d'image, du NAS ou de l'ancien PG local17.11.

Le parent reçu `6cbb4d0`, après `80ccdb1`, reste dans la
[PR #6 en brouillon](https://github.com/pamolive/PamOlive-Platform/pull/6).
Les deux CI Platform exactes —
[PR](https://github.com/pamolive/PamOlive-Platform/actions/runs/43730559794) et
[push](https://github.com/pamolive/PamOlive-Platform/actions/runs/43730556377) —
passent les portes exécutées de sécurité, acquisition/build, exclusion post-build
des credentials, PostgreSQL, natives, SSH10/RDP9, HA/partition sur le même hôte,
restauration restreinte (23 migrations/374 lignes) et démarrage Compose. Elles
échouent uniquement au scan final : **35 groupes High non arbitrés**,
102 correspondances High sur 349 OS, zéro Critical et aucun match ignoré.
Les 52 purs Vault et 17 tests adverses de validation de wheel comme données
passent séparément dans chacun. La suite générale annonce
**1 457 tests et 42 entrées Skip : 40 méthodes et deux exclusions setUpClass** ;
deux autres suites de 20 ont chacune un skip. Les marqueurs 42 + 1 + 1 restent
distincts ; aucune soustraction ne fournit ici un nombre de réussites.
Le [vérificateur public installé](https://github.com/pamolive/PamOlive-Platform/actions/runs/43730559799)
reçoit séparément 30 tests sans skip et 20 comparaisons de corpus. Neuf ZIP et
les sources/pins sont liés au sujet exact dans la réception
`cdabdd693f66ae2a0125dccc84d908f61ca1943b80f9642f1eaa91eef044c54a`.
Root a collecté les neuf ZIP ; leur vérification indépendante conserve
413 fichiers initiaux et distingue les sept checkouts des trois runs.
La provenance de build demeure incomplète ; ni `main`, ni image, ni NAS ne sont
mis à niveau. Ces CI ne qualifient pas le runtime Vault installé.

Le packaging [ADR-025](adr-025-vault-runtime-installation.md) ajoute seulement
les métadonnées du runtime, une notice et un contrôle borné des quatorze fichiers
de sa wheel. Les huit modules et le SQL restent inchangés. Une construction
locale et sa réception comme données ne sont pas une installation du service.
L'installation Linux autonome et ses RECORD sont maintenant observés dans PR8,
mais son exécution des 52 tests reste en échec comme indiqué plus haut.
Les reçus `67ee7c9` (`1352eef8…`) et `80ccdb1` (`7605f5fd…`)
demeurent distincts ; aucun résultat de parent n'est transféré.

La [maintenance PostgreSQL 17.12](postgresql-17-12-qualification.md) reçoit
maintenant les régressions du service CI épinglé par digest, avec sa sonde de
version en lecture seule. L'image auxiliaire locale et sa restauration restent
une qualification distincte ; aucune mise à niveau d'installation existante.

[ADR-026](adr-026-independent-usage-anchor.md) accepte l'implémentation d'un
témoin synchrone indépendant des usages V2, après confrontation et arbitrage
clientDataJSON signé. Le [contrat](p2-usage-anchor-contract.md) et son
[plan de validation](p2-usage-anchor-validation.md) fixent la tranche réelle
V réservé → W mTLS/SQL → preuves V2 → terminal positif/négatif → miroir V,
sans remise. Le développement local dans `components/usage-anchor` est en revue,
hors publication de ce lot ; aucun test SQL/TLS ni service W n'est encore reçu.
Cette décision ne qualifie pas
la durabilité, l'indépendance humaine/OS, le KMS ou un chemin de production.

Le parent `6c17536` conserve ses résultats distincts : PR fonctionnelle puis
scan High en échec, push arrêté au timeout TLS d'acquisition avant assertion
post-build. Le correctif courant borne les seuls téléchargements publics
idempotents sans assouplir TLS, destinations ou empreintes ; le succès de build
ne prouve pas qu'un retry ait réellement été déclenché. L'ancien calcul
« 1 397 exécutés » est retiré : les logs exacts du parent annoncent 1 439 tests
et 42 entrées Skip, dont 40 méthodes et deux classes. Les addenda
`3edad87793c9f3405e0ee320611ed70831b49c7f6adc26c302f679534fe0a49d`
et `d7a3e7b19118032180443da4511d5dd9cc0ad5bda1e14e5f93c38a38b0a5914e`
corrigent les seuls compteurs des deux sujets ; les reçus historiques sont conservés.

Au parent `bd8d2283a2c27c81eef3652fa0e4e5e02ba99216`, les deux CI dédiées
[push](https://github.com/pamolive/PamOlive-Platform/actions/runs/43690947578) et
[PR](https://github.com/pamolive/PamOlive-Platform/actions/runs/43690955625)
reçoivent chacune les **30 tests installés** du vérificateur public, sans exclusion,
avec 20 comparaisons concordantes au corpus. Cela remplace l'état « installé en
attente » des paragraphes historiques ci-dessous, sans remplacer P0 ni ses appelants.

Les deux CI Platform du même head —
[push](https://github.com/pamolive/PamOlive-Platform/actions/runs/43690947572) et
[PR](https://github.com/pamolive/PamOlive-Platform/actions/runs/43690955671) —
passent sécurité, anciennes bibliothèques P2, 1 439 tests généraux comptés dont
42 exclusions, portes 130/166/22, transports, HA même hôte et restauration de
23 migrations/374 lignes. Elles refusent uniquement le scan : **35 groupes High**,
zéro Critical. La promotion reste bloquée avec la provenance de build incomplète.

Le [runtime de réservation Vault](p2-vault-reservation-runtime.md) selon
[ADR-024](adr-024-vault-reservation-boundary.md) est maintenant intégré comme
source de développement séparée : 51 tests purs initiaux, puis un cas de bind N0
strict supplémentaire, soit 52 purs. La réception locale historique
N0R7 compte dix méthodes mTLS/PostgreSQL réelles réussies, nettoyage confirmé et
PG historique inchangé. Il ne produit que `pending_proofs`, `authorized:false`,
sans secret ni autorité d'action. Un lot local distinct reçoit ensuite deux cas :
vrai restart du service avec PG conservé et writer client jetable `os._exit(73)`
après commit, suivis du retry mTLS de la même ligne/dates/nonce privé/audit.
Le bind privé exact est corroboré par code épinglé et TLS ; les dix anciens
cas wildcard ne sont pas rejoués. Les faits H1 réels et 190 clients CLI
récoltés/drainés, six stdin complets, nettoyage 4/3/1 et PG inchangé sont reçus ;
18 retours non nuls sont des sondes readiness avant succès. Les quatre exits 137
sans OOM sont les `kill` de nettoyage prévus. Aucune CI Vault réelle encore.
Pas de Vault installé/image minimale reçus, crash serveur/PG power-loss,
expiration attendue, backup/restore ou frontière OS Web hostile qualifiés.
Le rollback clandestin sous même incarnation reste hors garantie. Aucun service
Web/P0 ou migration Django n'est changé ; P2 n'est pas terminé.

La campagne d'installation a ensuite reçu les 52 méthodes installées sur
`27cf3b4`. Un chemin CI optionnel prépare le transfert privé des trois wheels
vérifiées et du descripteur dans le même job. Le transfert conditionne l'écriture
du reçu à l'exécution réussie, aux empreintes attendues et au nettoyage confirmé.
La qualification du laboratoire installé avec PostgreSQL et mTLS reste à faire.

Le contrôle qui suit consomme le reçu du même job pour installer les wheels dans
une image de test distincte avec le pilote C psycopg 3.2.10 et libpq 17.12. Le
build et la vérification Python sont hors réseau après l’acquisition vérifiée
des dépendances. PostgreSQL et le service Vault seront démarrés lors de la
qualification suivante sur ce profil.

Un premier laboratoire de restauration déclaré a ensuite réellement exécuté
`pg_dump`, la création d'une seconde base synthétique neuve, sa restauration sous
rôle restreint et les grants courants. Propriétaires et lignes/audits restaurés
concordent ; le nouveau slot externe refuse l'ancien contexte ouvert avec 403,
et la base source reste fermée. La dernière probe après commissionnement échoue :
**la campagne complète n'est pas validée**. Les assertions finales de requête,
conflit et permissions restent à recevoir. Les 183 clients CLI et 12 stdin sont
récoltés/drainés, nettoyage 4 conteneurs/3 volumes/1 réseau confirmé sans OOM,
lease libre et PG historique inchangé. Rapport public :
`9f902fef7a5f9afc8d601db614458473561fe7f14e385dbf5f421ac7fdfbe3c8`.
Les dumps, requêtes, nonces et journaux privés restent hors publication.

### Réception CI du service Vault installé et de la restauration logique

Le [laboratoire installé](https://github.com/pamolive/PamOlive-Platform/actions/runs/44289749907)
du commit `58e9ec7` reçoit six tests PostgreSQL et quatre tests mTLS, sans échec
ni exclusion. La [campagne de restauration](https://github.com/pamolive/PamOlive-Platform/actions/runs/44293387418)
du commit `2078263` termine sept commandes et trois observations distinctes sur
PostgreSQL 17.12. Elle conserve la réservation et l'audit dans une seconde base,
ferme la source, observe le refus 403 de l'ancien contexte et le conflit 409
sur l'ancienne idempotence. Une nouvelle demande reste en attente. Les quatre
mutations SQL refusées, les refus Web/worker et le nettoyage sont confirmés.
Le reçu public a été vérifié indépendamment, SHA-256
`bc79cb4aa69350d1929cd3d537da7834b2a0d77e7bcc503702f56fec5943ca1d`.
PITR, reprise multi-hôte et détection du rollback sous la même incarnation
restent à qualifier.

### Fournisseur OpenBao Transit en laboratoire CI

La [PR nº 33](https://github.com/pamolive/PamOlive-Platform/pull/33) ajoute un
adaptateur explicite et un banc distinct pour la gestion des KEK des credentials
techniques. L'API d'enveloppe et ses octets restent compatibles. Les 31 tests du
fournisseur, dont un canal mTLS synthétique, ainsi que les 25 tests existants de
l'enveloppe passent localement. Ruff, Bandit sur le composant et le scan de
secrets des changements passent. La revue indépendante confirme la sélection
des clés par configuration commissionnée et les limites des jetons bearer.

La [CI native](https://github.com/pamolive/PamOlive-Platform/actions/runs/44297768561)
du commit `123856a` valide la provenance du binaire 2.7.2, installe les deux
wheels et termine cinq tests Transit sans exclusion. Elle relit le contenu V1
après redémarrage sur PebbleDB, refuse l'ancienne version en écriture, réenveloppe
en V2, vérifie les refus d'AAD, d'ACL, d'upsert, de mTLS et de jeton révoqué.
L'arrêt propre est confirmé. Reçu SHA-256
`f3fe27d4ab29d853168e14ef441ceeb462e25904d87b5738ee82a397e6ed3347`.
Les deux premiers essais de démarrage restent archivés. La version 2.7 a
supprimé le backend `file` utilisé dans ces essais. La récupération depuis une
sauvegarde OpenBao, les hôtes et dépositaires distincts et l'autorisation de
remise PAM restent à qualifier. [Notes OpenBao 2.7](https://openbao.org/docs/release-notes/2-7-0/)

### Historique des sujets et refus précédents

Point du 14 novembre : le socle PR2 est `2f28224`. Ses deux CI terminent
migrations, 1345 tests généraux comptés / 42 exclusions, portes dédiées,
transports SSH/RDP, deux nœuds avec partition de route PostgreSQL sur un même
hôte et restauration/retour arrière. Elles échouent uniquement au scan final :
35 groupes High non arbitrés, zéro Critical. Les jobs de sécurité du code passent.
Le sujet local R8-r2 corrige ensurepip et valide deux vrais venvs hors réseau
avec pip 26.3 ; les couches historiques restent conservées. Les matériaux
APT/SDK/compilateur et attestations ADR-021 demeurent incomplets : livraison bloquée.

Le [candidat intégré local F3/G/P2](p1-fg-p2-integration-20261114.md), fusion
`4c9cd2b`, conserve les protections du socle et réunit les routes F3, l'entrée
de demande Identity 360 et les deux bibliothèques P2. Ses tests propres passent :
134/134 PostgreSQL sans exclusion, 25 + 17 tests purs, Ruff et vrai scan de secrets
sur 698 fichiers. Sa branche de développement est depuis publiée dans PR3
au commit `09b6fa43`. Ses deux CI passent les jobs code/bibliothèques P2,
1433 tests généraux comptés / 42 exclusions et les portes natives/HA même hôte/
restauration, puis échouent au seul scan final des 35 groupes High.
Aucun main ou image promue ; le parcours G complet reste à qualifier.
P2 ne livre encore ni service Vault, ni vérificateur d'autorité, ni ledger,
ni isolation opérationnelle. Les paragraphes B2/B3r2 ci-dessous sont historiques.

Au15novembre, une bibliothèque supplémentaire est préparée localement :
[P2-R1b.1 matériaux publics PAM](p2-public-material-verifier.md), commit local
`77613e8`. Elle vérifie registre/checkpoint publics sans Django, avec contextes
explicites ; elle ne fournit aucune autorité d'action ou remise de secret.
30tests de source et30tests purs d'adaptateur passent séparément, sans exclusion.
L'audit des13matériaux et la revue indépendante passent ; les deux premières
CI installées du `7083a96` rendent42 après démarrage, nettoyage confirmé,
diagnostic interne perdu par le wrapper. Son correctif de diagnostic passe57
tests purs et cinq contre-cas AppSec, sans succès installé encore reçu. La CI
Linux détecte aussi1074identités supplémentaires déjà dans les fixtures publiques
revues ; leurs seuls classements sont ajoutés, sans changement des filtres.
Le wheel installé Linux et ses régressions restent des portes obligatoires. Les contrôles
P0 et leurs appelants ne sont pas remplacés. [ADR-023](adr-023-public-pam-material-verifier.md)
fixe cette limite ; P2 n'est pas déclaré terminé.

Un complément [HTTP PAM local](p1-g-pam-http-validation.md) prolonge `09b6fa43` :
5/5 scénarios avec véritables cérémonies synthétiques, deux votes, ticket
pending, arrêt et audit ; correction ciblée du rendu des dates bail/relais.
La régression combinée compte 324 réussites et une exclusion SQLite attendue
sur 325 tests, avec contrepartie PostgreSQL réussie. Les CI ultérieures du
candidat8b annoncent 1 439 tests généraux avec 42 entrées Skip. Le précédent
calcul de 1 397 réussites par soustraction est retiré ; aucun skip n'est une réussite.
La CI PR atteint les transports, HA même hôte et restauration puis refuse
35groupes High ; la CI push échoue plus tôt sur un timeout TLS d'acquisition.
Ces résultats restent liés à leurs sujets exacts. Le complément HTTP
n'exécute pas le JavaScript ni SSH/RDP : ces derniers ont leurs portes distinctes.
La [PR4](https://github.com/pamolive/PamOlive-Platform/pull/4) conserve les refus
réels du stage0 navigateur, dont certutil absent ; aucun succès NSS/TLS/CDP
n'est inféré de ses tests de lecteur public.

Les deux CI du candidat PR4 `7237070` sont désormais collectées :
[push](https://github.com/pamolive/PamOlive-Platform/actions/runs/43668586779)
et [PR](https://github.com/pamolive/PamOlive-Platform/actions/runs/43668590784).
Chacune passe les jobs de sécurité et des deux anciennes bibliothèques P2,
1 439 tests généraux comptés dont 42 exclusions, les transports, la qualification
à deux nœuds sur le même hôte et la restauration synthétique. Chacune refuse au
scan final : 35 groupes High non arbitrés, zéro Critical. Le run PR qualifie son
commit de fusion temporaire ; les identités d'image sont distinctes du push.
Ces résultats ne qualifient pas le nouveau vérificateur installé. L'inventaire
public D0 de `7237070` refuse un nom d'entrée de répertoire ; l'entrée fautive
reste inconnue et aucun inventaire OS/NSS complet n'est revendiqué.

| Périmètre | État réel au démarrage du programme |
| --- | --- |
| P0, P1-A/B1/C/D/E | Intégrés/publiés, tests PostgreSQL et transports synthétiques qualifiés en CI |
| Packaging TLS Synology | Trois services réellement démarrés sur Docker Linux/Compose2.20.1, HTTPS/MFA/isolation/restauration validés ; nouvelle image non installée sur NAS |
| P1-F Connect/Audit | Développement en cours : inventaire persistant d’annuaire et lecteurs LDAP/AD/Graph de laboratoire ; SCIM/TeamViewer existants réutilisés |
| P1-G portail complet | Planifié après F ; parcours transverses présents mais scénarios interactifs et accessibilité à compléter |
| P2 hybride/Vault/broker/clé/témoin | À implémenter et qualifier ; les UID actuels ne protègent pas les secrets contre une compromission complète du portail |
| P3 enterprise | Capacités partielles dans le noyau actuel ; extensions et qualification dédiées à construire |
| Production/multi-hôte réel | Non qualifiée ; les limites d’infrastructure sont documentées sans être comptées comme succès |

La première tranche F1/F2 est implémentée et testée par campagnes locales ciblées :102tests PostgreSQL sous rôle restreint,42tests adverses indépendants, puis43tests de protocole Linux, véritable démarrage TLS et restauration Docker enrichie de preuves Directory. La première suite globale garde son échec de fixture ; un nouveau rejeu complet du checkout de travail avec préparations F3/P1-G passe1226cas en1236,669s,49exclusions. Les deux CI95fe14f passent chacune130tests Directory et1166cas globaux avec42exclusions, ainsi que leurs portes natives/HA/restauration. Elles restent en échec sur l'espace temporaire du scanner et le nettoyage LDAP ; les corrections sont en qualification. Aucun de ces résultats ne remplace la CI du candidat final.

Le scan OS/native a refusé le runtime initial. ADR-019 actualise Python, FreeRDP et pip, ajoute le backport GDI compatible avec les gardes P0, puis remplace le pilote PostgreSQL Linux binaire par psycopg-c lié aux bibliothèques système. Le témoin B2 passe les vérifications natives et10/10SSH,9/9RDP sur PostgreSQL synthétique, ainsi que TLS1.3/SCRAM/CA/nom/concurrence sous rôle non-superuser. Le rescan conserve102matches High et aucun Critical ; les six findings pip sont corrigés. Le gate conserve les findings non triés et bloque la promotion ; les clôtures individuelles et la remédiation Kerberos restent en revue. Le retry B3r2 passe le makecheck Debian témoin puis échoue au harnais ASN.1 : aucune image B3 n'est qualifiée. Le rapprochement F3 est conservé dans une branche locale distincte, commit `ece41d6`,105tests PostgreSQL et contre-revue indépendante45/45 sans exclusion ; aucune publication de ce lot ne découle de ces tests. Les revues P2 restent des travaux de conception. Voir le [rapport courant](p1-f-inventory-validation.md), le [triage](p1-f-os-high-triage.md) et la [politique de scan](image-scan-policy.md).

Les anciennes portes NAS cochées plus bas concernent les anciennes versions et ne prouvent ni installation de cette image ni autorisation de toucher les services existants. Le programme actuel autorise les laboratoires isolés si leurs conditions sont vérifiées ; sinon le développement et les publications continuent sur Docker Desktop.

Au candidat PR5 `ef1285e`, les deux CI Platform confirment désormais les
régressions applicatives :1439tests comptés/42exclusions, transports, HA même
hôte et restauration23migrations/374lignes ; sécurité et anciennes bibliothèques
P2 passent. Le scan refuse35groupesHigh, zéroCritical. Les deux nouvelles CI
installées conservent enfin leur échec : dix processus réussis, puis probe-build
exit1 sans sortie ; les30tests installés restent non atteints. Un diagnostic
enfant borné est ajouté avec42tests synthétiques, sans relâcher les gardes,
en conservant57tests du banc. La cause interne et la réception installée restent
à établir. Les prototypes Vault externes au dépôt ne valent pas service livré.

Les deux qualifications installées du head PR5 `eaa386d` identifient deux
lectures hors racines pendant la sonde Python, nettoyage confirmé sans OOM.
La correction de l'énumération metadata conserve toutes les gardes et examine
tous les répertoires actifs, en omettant seulement le ZIP standard S0 absent.
54tests purs d'adaptateur et57du banc passent sur le candidat préparé. La
réception Linux des30tests installés reste obligatoire, sans transfert de succès.

## Lecture du checkout P1

Les capacités ci-dessous décrivent des livraisons de périmètres différents. Pour le checkout local après remédiation, consulter [P0-3](p0-3-validation.md) et [P0-4](p0-4-validation.md). Les anciennes qualifications NAS, image et transport ne qualifient pas automatiquement les modifications locales non publiées. Le témoin indépendant, le commissionnement réel et la qualification native Linux du contrôle P0-3 restent des portes explicites. Les onze noms produit de la roadmap correspondent aux applications techniques existantes ; ils ne désignent pas onze modules déjà achevés.

## Fonctionnel et testé

Les lots locaux P1-A/B1 puis P1-C/D/E ajoutent le contrat transverse versionné, Identity 360 et les prévisualisations AD/LDAP/Entra sans transport, le cockpit Governance et son registre d'exceptions non dérogatoire, Observe et le démonstrateur synthétique PC-483/PC-991. Les nouveaux lecteurs et les parcours administratifs IAM/IGA réutilisés rechargent leur autorité sous verrou. Voir les rapports [P1-A/B1](p1-a-b1-validation.md), [Identity](p1-c-identity360.md), [Governance](p1-d-governance.md), [Observe](p1-e-observe.md) et la [revue contradictoire](p1-cde-redteam.md). Ces implémentations ne qualifient ni un annuaire réel, ni un nouveau déploiement NAS ; la préparation [Synology N0](synology-p1-preparation.md) reste distincte de toute installation. Les résultats de CI doivent être associés au SHA exact, pas inférés des tests locaux.

- Organisations, appartenances et rôles techniques distincts des identités gouvernées.
- Appartenances administrées dans les formulaires natifs de Paramètres : modification et désactivation limitées à l’organisation, service protégé par rôle/MFA récente et verrou PostgreSQL empêchant le retrait du dernier administrateur. Le rattachement d’un compte existant extérieur à l’organisation est réservé à l’administrateur de plateforme local ; une session OIDC n’hérite pas de cette autorité globale. Aucune réinitialisation de mot de passe ni désactivation globale n’est effectuée par ce formulaire.
- MFA TOTP chiffrée, codes de récupération à usage unique et refus du rejeu de code.
- Validation récente personnelle de 2/5/10/15 minutes et reprise du formulaire conservé après challenge.
- [OIDC multi-fournisseurs par organisation](oidc.md) : découverte et authentification HTTPS complète avant enregistrement, activation séparée, association explicite par le titulaire et secours local conservé. Les claims du fournisseur ne créent ni identité IAM ni permissions et ne remplacent pas la MFA locale. Les sessions fédérées sont limitées à leur organisation et invalidées par la révocation du domaine ou de l’association. Les tests utilisent un IdP éphémère, pas une certification des fournisseurs commerciaux.
- Requêtes organisationnelles refusées sans contexte ; relations croisées refusées dans les modèles et par contraintes PostgreSQL.
- Anciennes vues globales du prototype retirées : réponse 410 sans lecture ni mutation, permissions historiques inopérantes même pour un superutilisateur et contrôle de livraison `pamolive.E010` si leurs routes sont réintroduites. Les tables historiques restent conservées ; elles ne constituent pas des rôles organisationnels actifs.
- Activation indépendante des huit modules livrés dans le même conteneur.
- Extensions communautaires Python séparées : wheels signées Ed25519, inventaire des fichiers et manifeste vérifiés avant import, compatibilité du noyau et dépendances, routes HTTP propres au module avec garde du noyau. Livraison après migrations distincte de l’activation par organisation ; activation liée à l’empreinte exacte du paquet, MFA et audit. Exemple autonome sans modification du noyau, sans installation de code par l’interface et sans conteneur permanent supplémentaire.
- Notifications de modules V2 : outbox transactionnelle PostgreSQL, enveloppes/destinataires signés, consommateurs déclarés dans le manifeste signé, contexte par organisation et aucune MFA héritée. Effets locaux et accusé atomiques, reprises bornées, preuves append-only et suspension sans perte lors d’une désactivation. Création/départ d’identité exposés ; exemple de wheel réellement installée recevant des faits IAM et ses propres publications. Aucun nouveau worker Compose, aucune garantie d’exécution unique d’un effet externe.
- Identités humaines, externes, machines, services, applications, workloads et API.
- Comptes externes séparés, ressources physiques/numériques, références publiques de certificats et badges, droits motivés.
- Intention datée avec méthode, ressource, compte, origine, privilège et justification.
- Approbations indépendantes configurables, responsable de contrat, séparation demandeur/approbateur et votes conservés.
- Ingestion authentifiée par source, déduplication, conservation des faits source.
- [API des systèmes métier](business-api.md) : intégrations indépendantes dans une même organisation, jetons distincts de la télémétrie, lectures séquencées signées et auditables, rejets des collisions et dates régressives, limitation par source, création/révocation/rotation via formulaires natifs et MFA personnelle. Rattachements humains datés aux intentions, corrections et retraits conservés, périmètre d’origine scellé, explication et export séparant le contexte actuel de la décision historique. Un état « approuvé » externe ne crée aucune approbation ni autorisation locale. Les adaptateurs fournisseurs réels restent à qualifier ; les fixtures ne certifient aucun compte GLPI/Jira/ServiceNow réel.
- [Collecte TeamViewer](teamviewer.md) : lecture HTTPS, test avant enregistrement, configuration chiffrée inactive puis activation séparée, MFA personnelle, reprises par page avec curseur signé, rapports versionnés immuables et passages liés à l’audit. Les observations identifient la révision exacte du collecteur ; les correspondances datées signées pour compte opérateur, identité attribuée et cible restent distinctes de la propriété. Les corrections conservent les attestations précédentes et les résolutions partielles ou ambiguës restent visibles. Aucun compte TeamViewer réel n’est qualifié par les fixtures.
- Acteur rapporté séparé du propriétaire du compte ou du credential : comptes partagés et certificats techniques observables sans attribuer leur activité à leur propriétaire. Acteur inconnu conservé ; aucune intention personnelle déduite par propriété. Intention d’observation bornée à l’intervenant et au compte précis, export et graphe distinguant activité rapportée et rattachement actuel d’inventaire. Départ d’un intervenant sans désactivation du compte partagé d’une autre identité ; retrait du propriétaire désactivant ses comptes et les intentions qui les utilisent.
- Sessions TeamViewer regroupées par identifiant source et organisation : relectures, collecteurs multiples et corrections de notes conservent un dossier unique avec liens signés. Les références ou horaires contradictoires empêchent une attribution consolidée ; les correspondances doivent concorder dans chaque révision source. Les observations en attente d’indexation ne sont pas ignorées par la résolution. Formulaires et détail natifs, traitement dans le worker existant et restauration de toutes les preuves.
- [Normalisation et interprétation des observations](observation-context.md) : un événement immuable par session TeamViewer, sans UUID local inventé ; associations résolues séparément et comparaison au périmètre daté. Analyses signées avec leur contexte et leurs faits, espace de source réservé et refus d’adopter une collision manuelle. Corrections ajoutant une analyse sans réécrire l’historique ; détail, export, graphe et chronologie distinguent les faits et l’interprétation actuelle. Une information nécessaire manquante reste inconnue plutôt que déclarée différente ; les privilèges Windows et tickets ne sont pas déduits des notes.
- Comparaison à une intention approuvée ou à un droit applicable ; résultats conformes, écarts ou contexte insuffisant.
- [Évaluation de la durée observée](observed-intervals.md) : fin facultative, périodes semi-ouvertes, changements d’autorisation et de contexte examinés pendant la session, horaires contractuels contrôlés sur toute la période. Les anciennes observations restent instantanées et les anciennes évaluations sont conservées. Au-delà de 31 jours ou 32 périodes de contexte, aucune conformité globale n’est déclarée. La chronologie conserve les chevauchements et distingue durée de session et retard de réception.
- Détail des preuves et export JSON par événement.
- [Recertification périodique](recertification.md) : règles par organisation enregistrées inactives, activation séparée avec MFA, responsable explicite et échéances traitées dans le conteneur existant. Campagnes à périmètre figé, décisions signées sans prolongation des droits et révocation via le contrat IAM. Rattrapage de la période courante avec périodes manquées visibles, absence de campagnes partielles, historique antérieur conservé en lecture seule et export paginé distinguant preuve locale et confirmation fournisseur.
- Départ d’une identité : désactivation locale des comptes, droits, intentions et autorisations temporaires liés.
- Baux PAM limités dans le temps et expiration exécutée par le processus de tâches du conteneur.
- Mandats PAM individuels pour comptes privilégiés ou techniques : lien explicite compte du portail/personne IAM par organisation, vérification administrative avec référence et MFA récente, attestations signées immuables et révocation tracée. Utilisation d’un compte d’identité technique distincte sans transfert de propriété ; l’emprunt du compte personnel d’un autre humain est refusé.
- Votes PAM signés sur un périmètre figé, comptés par personnes IAM indépendantes : les comptes multiples ne permettent ni auto-approbation ni double vote. MFA personnelle à la demande, à la décision et à l’ouverture ; contrôles continus sans challenge pendant SSH/RDP. Révocation du lien coupant les mandats, pas le compte technique partagé ni le compte global du portail. Anciennes demandes conservées mais non exécutables sans nouvelles preuves ; aucune liaison déduite du nom ou de l’e-mail.
- Audit chaîné par organisation, verrous PostgreSQL et protections append-only des preuves.
- Connecteur sortant SCIM 2.0 : test de lecture et capacité PATCH avant activation ; jeton chiffré et destinations HTTPS autorisées côté déploiement.
- Création initiale SCIM depuis une intention IAM approuvée : prévisualisation de lecture, demande et périmètre signés, réservation unique du POST, compte désactivé confirmé par relecture et activation facultative après attribution du groupe confirmée. Reprise d’un résultat incertain par lecture seulement, départ pendant création et preuves historiques restaurables ; qualification sur pairs HTTPS, pas certification d’un fournisseur commercial.
- Correspondances explicites comptes/utilisateurs SCIM et droits/groupes SCIM.
- File transactionnelle pour attribution, retrait de groupe et désactivation de comptes ; état confirmé seulement après relecture sur la cible.
- Branche IAM d’une approbation : droit temporaire, attribution externe puis retrait à l’échéance.
- Départs et recertifications câblés à la file externe ; correspondances absentes, échecs et reprises visibles dans l’interface.
- Reprises avec délais, nombre de tentatives borné, baux par compte et rejet des résultats d’une ancienne tentative ; preuves d’exécution append-only sous PostgreSQL.
- Fournisseurs distincts des identités ; contrats révisés, périmètres, participants, méthodes, horaires IANA, pays et accès physiques explicites.
- Politique d’approbation publiée par organisation ; parcours IAM obligatoire plutôt qu’une attribution directe pour éviter le contournement des validations.
- Séparation des tâches sur droits et intentions approuvées dont les fenêtres se chevauchent.
- Retrait ciblé des droits contractuels ; désactivation globale réservée aux comptes dédiés, conservation des comptes partagés et droits indépendants.
- Évaluation temporelle : révision applicable à la date source, absence de justification rétroactive, conservation des preuves avant départ/révocation et pays observé non inventé.
- Attribution SCIM différée au début de la fenêtre approuvée.
- Graphe relationnel daté : comptes, ressources, certificats, fournisseurs, droits, intentions et observations ; liens de contexte avec provenance et confiance déclarée.
- Relations explicites de propriété, hébergement dans une zone, application gestionnaire d’une porte, hôtes attendus de certificat et topologie réseau. Un lien de contexte ne crée aucun droit.
- Chronologie physique/numérique d’une identité, arrivées tardives, précision d’horloge déclarée et ordre relatif incertain ; aucune attribution automatique d’une machine à son propriétaire.
- Comparaison switch/port/VLAN attendu et observé ; un déplacement doit être précisément inclus dans une intention approuvée pour expliquer l’écart.
- Écart d’hôte de certificat sans prétendre prouver une duplication de clé ; hôtes alternatifs datés et vérifiés par le déclarant.
- Rapports de collecte immuables par source et périmètre, déduplication, corrections séquencées et calcul de couverture par intervalles. Une source activée n’est pas considérée collectante sans rapport.
- Investigations datées : intersection accès physique/privilégié, fournisseurs vers production, comptes privilégiés sans intention ponctuelle et événements sans référence déclarée dans une intention rapprochée.
- Réévaluations append-only des événements, historique conservé et export JSON du graphe et des faits réseau/certificats.
- Les droits, intentions et liens sont datés ; les libellés, types de comptes et classifications de ressources restent leurs métadonnées actuelles, pas un inventaire historique complet.
- Transport PAM dans l’image unique : moteur natif Guacamole SSH/RDP compilé depuis une source épinglée et signée, sans Java/Tomcat ni service Compose supplémentaire. Runtime ASGI et moteur natif privé sous deux UID différents, environnement natif sans secrets applicatifs, capacités effectives nulles pour les processus enfants.
- Sondes pré-authentification SSH et RDP : clé d’hôte ou empreinte SHA-256 obligatoire, NLA/TLS exigés pour RDP, validité temporelle du certificat contrôlée, hôtes/ports et réseaux autorisés explicitement, résolution IP épinglée. Elles n’acceptent ni mot de passe ni clé privée et ne prouvent pas une connexion de compte réussie.
- Relais WebSocket SSH et RDP/NLA même origine, tickets courts à usage unique liés au détenteur/session/organisation/IP et périmètre approuvé scellé. Configuration de cible chiffrée, vérification explicite avant activation, résolution épinglée et injection des secrets côté serveur uniquement.
- Cadrage Guacamole UTF-8 borné et liste fermée d’entrées clavier/souris/affichage ; refus des arguments de connexion, flux montants, fichiers et presse-papiers côté client. Les flux de paramètres natifs sont retirés avant affichage et capture.
- Contrôle continu de l’autorisation avec fermeture du transport en cas de perte, sans rechallenge MFA au milieu du flux. Fermeture de son propre relais sans MFA. Connexions bornées, propriétaire de relais clôturé par jeton de fencing et captures orphelines marquées partielles.
- Capture d’affichage chiffrée dans PostgreSQL avant transmission, chaîne HMAC et fin scellée dans l’audit ; lecture après MFA avec droits revérifiés par lots. Format Guacamole, pas MP4 ni preuve de logoff de l’OS distant. Quotas sans purge automatique.
- Test natif SSH sur serveur factice éphémère : mauvaise clé refusée avant authentification, bon couple clé/identifiants accepté, aller-retour clavier et fermeture effective du canal constatés. Huit scénarios d’image traversent formulaire, WebSocket et moteur avec PostgreSQL : expiration MFA sans interruption puis déconnexion, expiration de bail, cible désactivée, entrée interdite, quota, authentification par clé Ed25519, erreur de base simulée après établissement du canal et contrôle de démarrage volontairement ralenti. L’erreur de base coupe le transport, conserve une capture partielle lisible et reste distincte d’une révocation. Les transactions d’un relais sont ordonnées sans verrou global et avec attente incluse dans la limite de quatre secondes. Diagnostic limité à l’opération et au SQLSTATE validé, sans message d’exception ni secret. Fermeture constatée sur le serveur SSH et capture relue après MFA. Aucun compte système ni shell distant n’est installé par ces fixtures.
- Portes RDP séparées : pair FreeRDP/NLA factice, contrôle des identifiants délégués après vérification NTLM, refus natif des pins et mots de passe incorrects, clavier et pixels cibles vérifiés. Six scénarios WebSocket/PostgreSQL couvrent aussi la MFA périmée, la déconnexion, l’expiration, la désactivation et la redirection malveillante. Cette dernière exige un hook natif constaté et aucune connexion TCP vers la cible leurre. Les outils de test ne sont pas livrés dans l’image de production ; cela ne certifie pas toutes les versions Windows et politiques AD.

## Couverture des huit scénarios initiaux

Les scénarios proviennent de la [vision produit](product-vision.md). Les tests vérifient
les règles internes et des pairs éphémères ; une collecte réelle depuis un produit tiers
reste une étape distincte. Aucun des huit scénarios ne doit être présenté comme intégré
de bout en bout à tous les systèmes cités.

| Scénario | Capacité livrée et tests associés | Travail restant pour le terrain |
|---|---|---|
| Intervention TeamViewer | Événement, acteur, compte, intention approuvée et explication ; [configuration et reprises](../tests/test_teamviewer_collection.py), [correspondances attestées](../tests/test_teamviewer_mapping.py), [normalisation et analyses](../tests/test_teamviewer_access.py), [attribution](../tests/test_access_attribution.py) et [périmètre](../tests/test_platform.py) | Vérification du ticket source, arbitrage des corrections structurelles contradictoires et qualification du jeton réel |
| Chronologie physique et numérique | Ordre source/réception, arrivées tardives, incertitudes d’horloge et domaines séparés ; [chronologie](../tests/test_intelligence.py) | Collecteurs badge/PAM/vCenter et qualité des horloges sur l’installation réelle |
| Fournisseur hors intervention | Contrat versionné, méthodes, horaires, pays inconnus et couverture de collecte ; [gouvernance](../tests/test_governance.py) et [couverture](../tests/test_intelligence.py) | Sources physiques et métier connectées, règles de risque adaptées à l’organisation |
| Déplacement réseau d’une machine | Comparaison switch/port/VLAN et changement approuvé précisément borné ; [réseau](../tests/test_intelligence.py) | Collecteur NAC/switch et résolution fiable de l’identité machine |
| Certificat sur un autre hôte | Références publiques, hôtes attendus et signal d’écart sans conclure à une copie de clé ; [certificats](../tests/test_intelligence.py) | Collecteur PKI/services et preuve de possession de clé lorsqu’elle est disponible |
| Intention et activité réelle | Écart de ressource, méthode, temps, acteur et compte ; évaluation signée et provenance de mobilité par segment ; [évaluation](../tests/test_platform.py), [attribution](../tests/test_access_attribution.py) et [preuves de mobilité](../tests/test_mover_business.py) | Qualifier le contexte métier et l’observation sur de vrais systèmes sources |
| Contrat fournisseur | Participants, révisions, contraintes et retraits ciblés ; [gouvernance](../tests/test_governance.py), [confirmation SCIM](../tests/test_provisioning.py) | Adaptateurs des systèmes concernés, création initiale de comptes et réconciliation d’inventaire |
| Chemins d’accès | Graphe daté, intersection physique/privilégié, fournisseur/production et investigations ; [graphe](../tests/test_intelligence.py) | Connecteurs réels, rôles métier transverses et qualification des recherches à grande échelle |

## Portes de livraison restantes

- [x] Publier le code du socle et sa documentation dans `pamolive/PamOlive-Platform`.
- [x] Déployer une instance NAS avec un seul conteneur applicatif et PostgreSQL séparé.
- [x] Qualifier le noyau sur PostgreSQL et les transports SSH/RDP sur des pairs de test.
- [x] Tester une restauration isolée sans remplacer la base en service.
- [ ] Valider les ADR encore proposés, notamment la place de Redis et la frontière commerciale.
- [ ] Choisir et qualifier les connecteurs réels du premier périmètre client.
- [ ] Vérifier les références métier auprès de leur système source.
- [ ] Qualifier deux VM réelles, le répartiteur, les partitions réseau et la reprise PostgreSQL.
- [ ] Qualifier la charge, la rétention des captures et la rotation des clés.
- [ ] Livrer le contrat et la distribution des modules commerciaux séparés.
- [ ] Qualifier la sécurité et l’exploitation avant une annonce de version stable.

Une porte cochée correspond au périmètre indiqué, pas à une qualification globale du produit.
La version OIDC `0.2.0a6` est qualifiée par la [CI PostgreSQL et image](https://github.com/pamolive/PamOlive-Platform/actions/runs/42479225455)
sur le code `1281979`. La qualification de restauration peuplée inclut des preuves OIDC synthétiques ;
la sauvegarde du NAS ne contient pas de fournisseur réel. Les procédures sont dans
[OIDC](oidc.md), [actif-actif](active-active.md) et [sauvegarde](backup-restore.md).

## Travail requis pour la cible complète

Les expirations du budget de base du relais sont distinguées des révocations : `database_unavailable`, phase interne bornée dans le journal, fermeture du transport avant finalisation et capture partielle. Un cas RDP natif vérifie cette dégradation avec la limite réelle de quatre secondes après clavier et pixels confirmés. Cela ne résout pas la saturation du stockage : les constructions et qualifications lourdes doivent rester séparées des sessions réelles, et la capacité sous charge reste à qualifier.

- Étendre les contrôles MFA aux contrats des futurs services exécutant des actions externes ; conserver les cérémonies WebAuthn PAM P0-3 déjà livrées et qualifier leurs authentificateurs réels avec revue spécialisée.
- Adaptateurs spécifiques AD/Entra, ticketing, accès physiques, PAM et collecte réseau/certificats ; synchronisation d’inventaire et extensions de schéma. Le client SCIM couvre les comptes existants et une création initiale bornée, pas tous les fournisseurs SCIM.
- Vérification des tickets/contrats dans leurs systèmes sources, catalogue de pays de confiance, gestion des délégations et escalades d’approbation. Les horaires sont vérifiés sur la fenêtre d’autorisation entière, pas appliqués nativement à chaque application SCIM.
- Étendre les matrices de compatibilité SSH et Windows/RDP, les politiques AD/Kerberos, les scénarios de panne et la charge. Les fermes RDS à redirection et RD Gateway ne sont pas prises en charge. Le bail seul reste une autorisation ; les sondes testent le serveur, pas les identifiants. Ajouter rétention contrôlée des captures, quotas configurables, restauration et rotation de clé sans perte de preuves.
- Résolution automatique des identifiants externes, groupes/rôles métier transverses, ticketing vérifié auprès d’outils réels et analyse de risque spécialisée. Le [défi de possession](api.md#vérification-de-la-possession-dune-clé-de-certificat) vérifie une signature actuelle ; la collecte de preuves historiques depuis un fournisseur de PKI reste distincte.
- Délégations avancées et élévation fine : les mandats livrés ouvrent les droits natifs du compte choisi (`native_full_account`), sans filtrage de commandes, sudo/JEA ou profil OS « lecture seule ». L’emprunt de comptes personnels et le provisioning IAM pour une autre identité ne sont pas pris en charge.
- Parcours de grand graphe et pagination haute volumétrie. La projection actuelle limite le contexte à deux sauts, 120 nœuds et 400 relations ; chronologie à 500 événements, investigations à 1000 droits examinés, couverture à 100 périmètres et 500 rapports par périmètre. Les limites sont signalées ; une couverture tronquée n’est jamais déclarée complète.
- Extensions commerciales : choix de licence adapté à leur distribution, entitlements et canal privé. L’API d’extension est communautaire. Les [signaux périodiques V3](extensions.md#déclencher-une-projection-périodique) couvrent les projections locales ; les commandes externes et la migration de contrats incompatibles restent distinctes. Les modules Python restent du code de confiance, pas des sandboxes.
- Reprise après sinistre, charge et actif-actif sur deux VM réelles : la restauration isolée, la qualification HTTP et SSH sur deux conteneurs du même hôte et le contrôle de cohérence de deux VM ne prouvent ni une bascule PostgreSQL ni une reprise métier sûre. Une session SSH/RDP ne migre pas à chaud.

Une révocation interne n’est jamais présentée comme la preuve d’une révocation exécutée sur un système externe. Une confirmation SCIM cite une relecture datée ; elle ne garantit pas l’absence d’une modification ultérieure faite hors plateforme. Une absence d’intention dans les données collectées n’est pas présentée comme la preuve que l’accès est illégitime.

## Expat : succès du laboratoire, produit encore en qualification

Le run [43823586567](https://github.com/pamolive/PamOlive-Platform/actions/runs/43823586567) du `549b0cd` réussit : C narrow/wide, UBSan, ABI et extensions Python. La suite stdlib rapporte 490 tests et 12 skips sans leurs raisons exportées. Le candidat de visibilité conserve tous les plafonds et porte les tests purs à 96 ; la preuve native suivante reste attendue. [Détails et limites](../deploy/expat-remediation/README.md). L'image produit reste distincte, sans fermeture des groupes High ni promotion induite.

## Expat — première intégration dans l'image produit

Le laboratoire exact `3d960926` réussit avec les raisons des douze skips stdlib exportées. Le nouveau Dockerfile produit reprend ces mêmes helpers, runtime/SDK et deux extensions ; le snapshot final et ses limites sont décrits dans [ADR-031](adr-031-expat-product-snapshot.md). Les contrôles de l'archive exacte et le SBOM enrichi restent soumis aux scans exhaustifs, sans modification des seuils ni disposition automatique de CVE.

Validation source : 14 tests produit ciblés et 39 tests PostgreSQL purs passent sans skip ni IO externe ; la revue indépendante ajoute six contre-cas. Le test de merge/schema SBOM complet et la suite native-SBOM complète ne sont pas exécutés sous Windows (import ctypes refusé sous audit) : ils restent obligatoires dans la CI Linux. Construction réelle de cette nouvelle image, snapshot, consommateurs, P0, restauration et scans sont encore attendus. Les succès du laboratoire ne les remplacent pas.

## Public Engine : identité CLI ROOT3 en qualification

Les observations réelles du candidat `1e66df2` n'identifient que le format et la version numérique 2.4.2 ; le package masqué reste inconnu. [ADR-029](adr-029-public-containerd-cli-identity.md) retient huit couples package/version exacts documentés, avec un schéma typé ROOT3 ; aucune normalisation de marque ni apprentissage depuis une observation refusée. Les anciens schémas restent historiques.

La revue contradictoire a refusé une première version pour sa projection d'identité diagnostique insuffisamment liée au contexte du processus. R2 exige le même contexte strict avant toute publication de format ou d'identité : processus terminé normalement, flux complets, outil stable et aucune autorité ni requête suivante. Les 65 tests métadonnées, 39 PostgreSQL purs et 14 tests courts passent sans skip ni IO externe. Les 19 fichiers PostgreSQL et les douze lignes de son payload restent inchangés. La nouvelle mesure Linux demeure requise ; ces tests ne constituent ni une mesure UID PostgreSQL ni une autorisation opérationnelle.

La garde de délais du témoin PostgreSQL conserve ses maxima stricts. Un contre-exemple flottant reproductible pouvait produire une réserve légèrement supérieure à trente secondes ; le constructeur arrondit maintenant vers le début et reste plafonné par les anciennes échéances. Aucun seuil ni comportement UNKNOWN n'est élargi. La reproduction et les parcours CLI sous horloge contrôlée sont conservés ; ce correctif arithmétique ne prouve pas la valeur d'horloge du run historique en échec.

La qualification de restauration ferme désormais les connexions Django avant
succès et attend une fermeture normale, bornée, des seules sessions de la copie
scellée. Les identités et l'absence de sessions sont revérifiées avant suppression ;
un zéro tardif conserve la copie. Les 25 tests purs et dix contre-tests indépendants
passent. La restauration PostgreSQL réelle reste à recevoir ; voir
[les garanties et limites du drainage](backup-restore.md).

## Qualification Jansson en cours

Le backend natif est en qualification sur une branche indépendante ; les tests purs ne valent pas livraison. Voir [preuves et limites](p1-f-jansson-qualification.md) et [ADR-030](adr-030-jansson-native-json-backend.md). Aucune donnée ni migration métier modifiée.

### Corpus restore V7 / Governance / confiance PAM en qualification

Le candidat ajoute un corpus synthétique couvrant des chemins absents du reçu
f66 : historique V7 migré sans reclassement, registre et autorisations personnelles
PAM vérifiés avec ancrages publics hors sauvegarde, trois preuves Governance.
Les compteurs proviennent des vérificateurs et ne réarment pas la confiance live.
Le reçu public fermé n'est produit qu'après les nettoyages confirmés.

Validation d'intégration :10 contrats du nouveau corpus,25 tests de drainage
conservés et11 tests du rapport public passent, sans IO externe ni skip.
Les doublures de trois anciens tests CI ont été mises à jour pour fournir les
nouveaux ancrages/compteurs requis ; leurs assertions de refus sont conservées.
La revue a détecté un guillemet manquant du workflow avant publication ; la R2
le corrige et le teste. Les quatre tests dédiés PostgreSQL du corpus ont
ensuite passé ; la sauvegarde/restauration complète du corpus étendu reste
à recevoir, sans transfert des anciens succès.

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


### Expat — deux correctifs locaux supplémentaires, 16 novembre 2026

ADR-035 applique après authentification des sources les corrections amont de
CVE-2026-124317 (convertisseur d’encodage tronqué) et CVE-2026-128241 (lien
symbolique terminal de sortie xmlwf). La reconstruction locale devient
2.10.0-1+pamolive2, avec une preuve V2 explicite des patches locaux ; ce nom
ne désigne pas une nouvelle publication Debian ou upstream. Les signatures
d’origine attestent les sources de base et ne couvrent pas ces modifications.

La composition part du candidat de restauration 94064bc et conserve son
workflow Platform, ses preuves historiques et le comparateur de snapshot.
Les 37 entrées de source et les 14 pins produit sont vérifiés depuis les blobs
Git. Les 103 tests purs de préparation et 21 tests produit sélectionnés passent,
sans exécution native ni réseau. Le test de schéma SBOM strict n’est pas exécuté
sous Windows ; il reste obligatoire sous Linux.

Les témoins avant/après, le refus réel xmlwf, les deux suites C complètes,
UBSan, les signatures, l’ABI, les consommateurs Python, PostgreSQL/P0 et le
scan strict de la nouvelle image restent à recevoir. Le chiffre de 5 340 vérifications
par largeur est une prévision, pas un résultat mesuré. Les reçus V1 restent
historiques et ne qualifient pas un paquet V2. Aucun avis CVE n’est fermé,
aucune image promue et aucune modification NAS effectuée par cette étape.


## Actualisation de livraison main — 17 novembre 2026

Les PR #23 et #24 sont fusionnées à la demande du propriétaire. Le rapport
[de livraison](main-delivery-2026-11-17.md) complète les notes historiques
ci-dessus : cache Chrome corrigé mais refus de garde restant, capture Expat
refusée sur SIGILL, et sous-ensemble de qualification en lecture seule revu.
Les quatorze nouveaux tests purs passent sans skip et disposent de leur job CI.
Les résultats PostgreSQL et scans cités dans ce rapport sont liés à leur SHA ;
la nouvelle fusion doit recevoir sa propre CI. Aucun déploiement ni image
nouvelle qualifiée ne résulte de cette publication de code.
