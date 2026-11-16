# ADR034 — Certificat Google limité à l’autorité de release déjà choisie

Statut : **architecture SOURCE/LAB conditionnelle approuvée par Root ; implémentation candidate à contre-revoir**. Ce candidat contient du code, des entrées publiques et des doubles purs ; aucun GPG, certificat authentifié, installation ou navigateur n’a été exécuté ici. Aucun ancien gel ou résultat n’est réattribué.

## Faits et objet de la décision

Les deux artefacts exacts reçus par Root pour `2fcbec5418aa3596bab38185126a9cfe0224ff28` exposent le même diagnostic SHA256 `f9d97a740ba64d22e4eb5b549aa43ac01f0607383a3ce878d9eec45f45233fa1` : seul BAD nommé `KEYEXPIRED`, un GOODSIG et un VALIDSIG, primary/signer attendus vus sans ambiguïté et non marqués expirés, sept autres clés dont cinq expirées. Le diagnostic déclare explicitement qu’il n’attribue pas KEYEXPIRED à une clé. Ces compteurs ne prouvent ni signature admissible, ni causalité des cinq expirations. Le refus actuel reste valable.

L’autorité attendue reste celle des pins existants : primary `EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796`, signer `0E225917414670F4442C250DFD533C07C264648F`, bundle fournisseur SHA256 `54dea5f6c2a26091578cf52a999cebc6b64df478d37ad4dce96376b711e3b27c`. Aucun fingerprint ne sera appris du statut observé. Le Release, sa signature, Packages et le paquet157 restent les sujets déjà pinnés.

## Options comparées

| Option | Intérêt | Limite / décision proposée |
|---|---|---|
| Conserver le certificat complet et attendre un nouveau bundle officiel | Aucune transformation locale du certificat | Conserver comme alternative de repli fermée. Tout nouveau bundle/SHA/signer exigerait une revue Root ; aucune disponibilité ou résolution du refus n’est supposée. |
| Export natif `drop-subkey` limité au signer déjà pinné | Réduit l’objet de vérification sans changer la clé primaire, le signer ni les prédicats | **Option recommandée sous les conditions ci-dessous**, avec un purpose distinct autorisant cette transformation finie. |
| Remplacer le vérificateur par gpgv ou un autre moteur | Pourrait produire d’autres diagnostics | Change la sémantique de vérification et la TCB ; ce n’est pas le correctif minimal actuel. Nécessiterait sa propre revue. |
| Tolérer KEYEXPIRED si les compteurs semblent bons, nettoyer/minimiser le certificat, retirer des signatures ou changer de clé automatiquement | Peut faire disparaître un symptôme | Rejeté : ce serait une autre politique, sans preuve d’attribution ni maintien de l’autorité attendue. |

Le manuel officiel GnuPG décrit `drop-subkey` comme filtre d’export, `fpr` comme fingerprint de clé et `<>` comme non-égalité de chaîne entière. Il documente aussi que les options clean/minimal suppriment davantage de signatures. Cela justifie la syntaxe proposée, pas son succès sur le binaire CI encore non qualifié. [Manuel GnuPG2.4](https://gnupg.org/documentation/manuals/gnupg24/gpg.1.html), [Import/export](https://www.gnupg.org/documentation/manuals/gnupg/GPG-Input-and-Output.html).

## Contrat proposé pour la transformation

Root autorise **avant l’exécution** un nouveau purpose, par exemple `google-release-selected-signer-certificate-v1`, lié au SHA du bundle original, aux deux fingerprints exacts, à l’expression fixe et au futur code pinné. Ce purpose n’est ni une rotation de clé ni une admission d’image. Le SHA du résultat mesuré sert à sa traçabilité ; il ne choisit ni l’autorité ni une nouvelle valeur attendue. Si Root préfère épingler aussi les octets dérivés, une première réception DATA Linux peut les fournir avant une activation ultérieure ; aucune auto-admission de ce SHA ne sera ajoutée.

La séquence frontend utilise deux homes privés neufs, sans options utilisateur, réseau de clés, agent démarré, trust importé ou service de clés. Les flags actuels restent actifs, dont `--require-cross-certification`. Le bundle fournisseur original est capturé/hashé puis conservé intact. Importer/lister ce bundle ; appeler les fonctions inchangées `one_primary` et `signing_capability` sur **les clés originales** avant export. Primary/signer absent, ambigu, révoqué, expiré, désactivé, sans capacité ou hors temps interdit la transformation.

Exporter ensuite le seul keyblock de la primary exacte avec un argv sans shell : `--export-filter`, `drop-subkey=fpr <> 0E225917414670F4442C250DFD533C07C264648F`, `--export`, fingerprint primary. Ne pas utiliser `export-clean`, `export-minimal`, `drop-sig`, import-filter, édition de clé, réparation ad hoc, changement de date ou filtre du stdout de vérification. L’option ne sélectionne pas le signer depuis le Release.

Avant réimport, contrôler la lignée de cet objet borné : une primary publique identique, exactement le seul subkey signer autorisé, aucun paquet secret, aucune clé ajoutée. Les paquets signés concernant la primary et le signer doivent rester identiques en contenu : self-signatures, révocations connues pertinentes et binding contenant la cross-certification compris. Seuls les blocs des autres subkeys peuvent disparaître. Le dépôt 2f ne contient aucun lecteur de framing OpenPGP. Le nouveau module chrome_key_scope.py est un contrôle DATA borné, à relire indépendamment ; il ne vérifie aucune signature. L’OUT historique expat4-key-bootstrap-20261116/inspect_data.py est seulement une référence conceptuelle N0, non importée (elle contient des effets de bord IO). Comparer les corps de paquets et leur multiplicité, sans rendre l’armor ou les en-têtes de longueur artificiellement normatifs. Si l’export GPG retire/répare d’autres données pertinentes, **refuser**, ne pas ajouter automatiquement une exception. Ce point doit être prouvé sur le vrai export Linux avant admission.

Importer le buffer dérivé dans le second home, puis exiger le keyset exact `{primary, signer}` et les deux états choisis identiques aux états originaux : création, échéance, validité, capacités et désactivation. Les champs agrégés de GPG peuvent théoriquement changer avec les subkeys retirés ; aucune normalisation opportuniste n’est prévue. Une différence réelle déclenchera une revue explicite de la projection, sans fallback.

Vérifier alors **le Release original exact** et sa signature avec le certificat scoppé et le statut complet non filtré. Réutiliser byte-exact `BAD` et les trois prédicats de `chrome_gpg.py` SHA256 `001d178e5876df97156bf2061df19a51fc56bbf5b9bfa102098999bc10357512` : un seul GOODSIG/VALIDSIG, primary/signer exacts, dates/hash autorisés, capacités et validité aux temps courant **et de signature**, vérifiés contre les états originaux et dérivés. KEYEXPIRED persistant, toute erreur de binding/cross-certification ou tout autre BAD refuse toujours avant curl/.deb/APT.

L’ancien chemin de vérification du certificat complet n’est pas requalifié. Ne pas ajouter `try valid_status(original) / except KEYEXPIRED / continue`. La nouvelle vérification a un objet et un purpose distincts, à approuver avant exécution ; aucun échec ancien ne devient une autorité.

## Superviseur root, bornes et livraison future

Le superviseur root recommence la même dérivation et la même authentification depuis les matériaux originaux pinnés. Il ne reçoit pas un certificat frontend à croire sur son SHA seul. Exiger la concordance des SHA original/scoppé frontend/root et du contexte/purpose, avec les mêmes outils mesurés et stables ; toute différence est un refus. Garder ensuite tous les contrôles actuels Release/Packages, fraîcheur UTC7jours/+300s, paquet/version/URLHTTPS/SHA/taille, payload/ownership/mode, dépendances déjà satisfaites et APT local sans récupération réseau.

Le parcours proposé passe de trois à six commandes GPG par superviseur, bornées10s chacune via l’H1 existant, avec caps de listing et de certificat fermés. Le supplément théorique de travail GPG est30s par superviseur. Les deadlines frontend870s/root450s, appel root480s avec réserve existante, step15min/job40min et navigateur600s+60s restent inchangés. L’implémentation doit vérifier le budget restant avant chaque commande et refuser si insuffisant ; ces chiffres ne prouvent pas que la nouvelle CI rentrera dans la fenêtre. Pas de nouveau superviseur, service, retry ou promesse de libération de descendants.

Fichiers futurs minimaux : `chrome_bootstrap.py` pour la séquence et le contrôle DATA ; ses tests pour la fermeture ; le petit manifeste de pins et ses deux littéraux workflow recalculés depuis Git. `chrome_gpg.py`, les quatre matériaux fournisseur, le guard `/opt/google/chrome/chrome`, les oracles/formulaires et le reste du workflow restent inchangés. Les nouveaux reçus publics doivent se limiter aux hashes, purpose, enum/compteurs, booléens de contrôles et faits H1 ; aucun UID, statut brut, argument libre, certificat de test privé ou home GPG exporté.

## Tests requis avant de faire confiance au nouveau sujet

Purs : inverse AST des trois prédicats/BAD et des contrôles paquet/installation ; fingerprints/purpose préexistants avant import ; keyset/paquets exacts ; corruption, duplication, partial/truncated framing et clé ajoutée ; selected-state modifié, bytes/FD/tool changés ; bounds/deadlines/H1 incomplets ; refus avant curl/dpkg/APT ; canary sans fuite ; root redérive et n’apprend aucune autorité du frontend. Aucun de ces modèles ne prouve les signatures.

GPG Linux réel sous le même binaire mesuré : sujet fournisseur exact ; fixture synthétique avec subkey expiré non sélectionné ; primary et signer sélectionné expirés/révoqués ; binding/cross-certification absent ou corrompu ; mauvais signer, mauvaise signature, signature future/hors-validité ; clé/UID/paquet inattendu, option de filtre indisponible. Les contrôles négatifs peuvent comparer le refus strict du certificat complet et le résultat scoppé dans leur harness dédié, jamais intercepter un BAD en production pour l’autoriser. Ne pas publier de clés privées des fixtures.

Critère de passage : nouvelle réception des processus H1, de la transformation exacte et de la vraie authentification sur l’objet scoppé ; puis, séparément, installation root, guard Chrome inchangé et vrai parcours navigateur. Ni le filtre seul ni un rc0/VALIDSIG_count ne donnent un GO. Le bundle gelé ne prouve pas la complétude mondiale des révocations ; la TCB reste Root + fournisseur/TLS + GnuPG, sans besoin inventé de HSM.


## État de l’implémentation candidate

Le purpose est exactement `google-release-selected-signer-certificate-v1`.
Les deux corps de clé v4 sont prépinnés par SHA256 ; le fingerprint SHA1 v4 est
uniquement un identifiant de format, jamais une authentification. Le contrôle
accepte exclusivement des paquets publics v4 RSA à longueur finie et compare
les tuples (tag, corps) ordonnés, avec leur multiplicité. Il refuse les formats
partiels/indéterminés, les paquets secrets/inconnus et tout changement des blocs
primary/signer. Les limites sont64KiB,256paquets et16KiB par corps ; les listings
et statuts positifs sont plafonnés à16KiB. Voir le format historique v4 dans
[RFC4880](https://www.rfc-editor.org/rfc/rfc4880.html) ; le code ne prétend pas
implémenter OpenPGP général ni les certificats v5/v6.

Le manuel GnuPG actuel indique repair-keys actif par défaut à l’import ; un
réordonnancement ou retrait réel des blocs pertinents fera échouer la lignée.
Aucune exception ni option de réparation ne sera apprise du résultat Linux.
Les états sélectionnés doivent être strictement identiques avant/après export.

## R2 du harnais : contrat TEST R3 et matrice réalisable

Décision SOURCE/LAB ; authentification/installation toujours PENDING jusqu’au
vrai résultat Linux lié aux sources exactes. Le gel R1 641 reste historique et
INCOMPLETE. R2 raccorde huit fichiers byte-exacts du producteur NSS R3
870e1bdaf03b7e57cf989795cd1d33a1bf6624ff3bf39d65088bb5b1cfcc312a,
via son pin externe 7bb5c0565e1a4a0c5ddd5f3b729626680076fba66b88a82729b170b115edbf84.
Les fournisseurs originaux, BAD et les trois prédicats001d, le framer1ee et ses
six commandes de dérivation/réauthentification restent byte-exacts.

Le producteur de purpose TEST/2 possède un seul agent supervisé sur Ubuntu24,
interpréteur système /usr/bin/python3.12 fixe, horizon180/work150/cleanup30.
Ses trois homes, socket, PID/SO_PEERCRED et journaux H1 restent sous son contrat
indépendamment revu. Il rend six buffers publics immuables après cleanup confirmé,
sans clé privée/home/log d’agent. Aucun autostart/global kill/adoption n’est ajouté.
La création seulement utilise les heures TEST demandées : clés T-3600 (un jour),
signature future T+3600, expirée T-600 avec seconds=60. Le positif, toute vérification,
import/list et l’agent utilisent le temps réel. Ces demandes ne prouvent aucun résultat.
La fenêtre3600 couvre deux horizons870+skew300 ; aucun budget ni skew n’est augmenté.

Le consommateur lie noms/types/tailles/SHA aux mêmes six buffers, purpose/pin/contexte
et H1. Il compare les blocs publics ordonnés et la seule révocation ajoutée0x28,
puis exige un vrai positif RSA/SHA256, les dates réelles GPG, un vrai sub:r et le
refus key_unusable AVANT export filtré. Les deux signatures temporelles utilisent
le certificat AVANT révocation. Leurs vrais VALIDSIG doivent lier P/S/temps/hash
et classe ; un EXPSIG non authentifié ou le seul horaire demandé ne suffit pas.

| Exigence ADR | Preuve exigée dans R2 |
|---|---|
| Signature fautive, binding/selfsig/crosscert corrompus | GPG réel sur les octets du positif Google ; BAD strict non filtré, H1 complet. Un IMPORT_PROBLEM1 exact peut constituer le refus fonctionnel amont, sans prétendre la branche verify. Une crosscert hachée corrompue peut aussi casser le binding externe. |
| Primaire révoqué/expiré, ancien signer expiré, signer TEST révoqué | Listing natif e/r exact, puis garde inchangée ; DSA/SHA1 Alfa sert seulement au listing r, jamais à une authentification de signature faible. |
| Positif avec autres sous-clés expirées | Positif Google dérivé plus nouvelle lecture originale10s/16KiB frontend après positif ; sous-clés e réellement observées. Aucun état2f transféré. |
| Mauvais P / mauvais S | Vrais octets du VALIDSIG positif confrontés à un tuple attendu délibérément faux ; refus signature_authority, aucune signature forgée. |
| Signature future / expirée | Vraies signatures TEST, vérification temps réel, identité et dates VALIDSIG exactes ; signature_future ou BAD/EXPSIG conservé, jamais retiré pour approuver. |
| Signature avant clé / après expiration de clé | Modèle explicite des gardes à partir du vrai listing natif, avec positif/états/temporalité amont. Pas de fausse signature strict-GPG impossible, ni claim de branche crypto exacte. |
| Clé/UID/packet inattendus | Mutations DATA des vrais blocs dérivés, refus de lignée avant GPG. |
| Export-filter indisponible | Positif natif prouve capacité courante ; purs obligatoires pinés prouvent arrêt/UNKNOWN en cas d’échec de commande. Pas de simulation du binaire hôte. |

Ces17 lignes sont une matrice de preuves mixtes : ADR_evidence_matrix_complete
n’est PAS «17 authentifications négatives natives». Le reçu garde
all_rows_are_native_crypto:false et les evidence_kind par ligne. Les purs
obligatoires doivent eux-mêmes réussir dans le step CI lié à la même source.
Avant/après-clé restent des modèles de branche ; les refus fonctionnels natifs
amont et le positif réel sont distincts. Aucun faux PASS n’est construit.

Un nonzero n’est attendu que rc1/2 normal, reaped/drained, sans kill/exception et
outil stable. Chaque lane UNKNOWN reste présente et inutilisable. Timeout,
signal, non-drain et toolchanged arrêtent le préflight. La source GnuPG2.4.7
gpg.c g10_exit émet FAILURE gpg-exit GENERAL pour rc nonzero : le harnais négatif
ne tolère que ce tuple terminal exact, accompagné du refus spécifique attendu.
BAD001d reste inchangé et reçoit tous les octets originaux. Pour un expiré,
VALIDSIG/EXPSIG et les dates sont tous exigés, sans retirer FAILURE ou EXPSIG.
Toute autre FAILURE/ERROR reste fermée. IMPORT_PROBLEM1 signifie Invalid
Certificate selon doc/DETAILS ; un échec de stockage ne qualifie pas le négatif.

La correction de type Path au contrôle post-GPG négatif répare une indisponibilité
R1 jamais exécutée nativement ; le double teste désormais la vraie API Path.

Avant curl/dpkg/APT, le frontend exige le préflight complet. Root redérive et
réauthentifie Google avec les six commandes byte-exactes, puis exige le reçu lié
source/run/attempt/scopedSHA. Aucun générateur n’est lancé sous root. Le bundle
Google/P/S n’est ni remplacé ni auto-appris du sujet TEST. Le guard Chrome fixe,
formulaires, TLS et oracles UI restent inchangés. Budgets40/15min et
870/450/480s, browser600+60s inchangés ; seul le job dédié reste ubuntu-24.04.

Public : métadonnées typées/H1 et six fichiers publics fixes TEST après admission
consommateur ; jamais homes, clé privée, stderr, statut brut ou UID. La TCB root,
outils et VM coopérative reste explicite ; pas de garantie contre root malveillant,
ni d’effacement sécurisé/global resources_released inféré du teardown.

Sources primaires additionnelles :
- https://raw.githubusercontent.com/gpg/gnupg/gnupg-2.4.7/g10/gpg.c (g10_exit)
- https://raw.githubusercontent.com/gpg/gnupg/gnupg-2.4.7/g10/gpg.h (source GPG)
- https://raw.githubusercontent.com/gpg/gnupg/gnupg-2.4.7/doc/DETAILS (IMPORT_PROBLEM)
- https://raw.githubusercontent.com/gpg/gnupg/gnupg-2.4.7/g10/sig-check.c (contrôles temporels)


## Diagnostic R4 de l’agent TEST

Le run 43916635288 du candidat 38ba300 est refusé avant installation. Le reçu
confirme huit commandes préparatoires terminées normalement, puis l’agent PID
3896 en timeout, tué, repris et drainé ; cleanup_complete reste faux. Il ne
contient ni première cause ni phase suffisante pour choisir une correction de
socket, de permissions ou d’exécution. Le second échec PR n’a pas reçu ici une
contre-preuve complète et n’identifie pas davantage cette cause.

R4 ajoute seulement des diagnostics fermés : phase, classe connue, errno fini
ou nul, garde connue ou unmapped. La première cause primaire est écrite avant
cleanup ; sa voie séparée garde l’échec de contrôle cleanup avant le join.
Aucun message libre, chemin, UID, argv, statut, clé ou stderr GPG n’est lu
pour ces diagnostics. Une erreur de journalisation reste UNKNOWN. Les deux
feuilles JSON sont déjà couvertes par la publication de preuves publiques.

Les commandes, gardes, identité du processus, budgets 180=150+30, six buffers
publics et décisions de nettoyage sont conservés. Le contrat COMPLETE conserve
sa structure ; sa nouvelle identité de source est normalement différente de
R3. Aucun vrai reçu historique ni résultat natif n’est transféré. Les 92 tests
purs de l’intégration passent sans réseau ni natif ; une nouvelle CI exacte
doit encore recevoir la cause et qualifier l’agent avant toute installation.

## R5 : observateur de métadonnées privilégié, générateur non-root

Décision Root du 16 novembre 2026, limitée à une nouvelle VM CI Linux dédiée :
le générateur reste non-root. Si et seulement si le stat direct de
`/proc/<PID du Popen possédé>/exe` refuse avec errno13, un frontend fixe exécute
`/usr/bin/sudo -n -u#0 -- /usr/bin/stat --dereference` avec un format fermé et
cette seule cible. Aucun shell, interpréteur root, lecture de mémoire/clé,
désactivation des protections GPG, adoption de PID ou commande de daemon.
L’observation répétée conserve la comparaison dev/ino aux outils capturés ;
elle n’est pas remplacée par une preuve initiale d’exec.

Cette décision suit la contre-revue indépendante
`adr034-proc-exe-sudo-stat-independent-review-20261116` : note SHA256
`cb531db00a5b0c0d8d8ec1511082bc4ec3b78048bb0ec32a3fde7f8d93dcadd9`,
rapport `4f4e412fefed6ec6f3b157231ca36b83f1b285c6d3f0e81a1038620e2c14004b`,
gel `b2be4d6fe622bbce532fd340cb40598ea2c3e5f199fc8f1fb9db19efb7188380`.
Il s’agit d’une commission SOURCE, pas d’une qualification native reçue.

Les rôles sudo/stat sont distincts des gardes GPG/Python existantes : chemins
fixes, parents root-owned non modifiables et sans alias, ELF réguliers nlink1,
SHA/identités stables avant/après. Seul sudo exige le mode4755 ; stat reste0755.
PPID, session, groupe, starttime et poll du Popen sont revérifiés autour du stat.
Le socket/peer UID/GID/PID et GETINFO restent exigés, sans nouvelles autorités.
La TCB inclut root, les outils et politiques sudo de cette VM coopérative :
un frontend normal terminé/reaped/drained n’est pas une énumération exhaustive
de ses descendants OS. Un timeout, nonzero, sortie ouverte, échec de contrôle ou
incertitude privilégiée reste UNKNOWN/resources_released:false. Cette voie
UNKNOWN est sticky : aucun nouvel observateur privilégié, même en cleanup.
Un cleanup possédé éventuellement réussi ne répare jamais cet état.

La borne structurelle est 23 frontends préparatoires/GPG/Python plus au plus
11 observations sudo (4 readiness, 6 autour de trois GETINFO, 1 avant KILLAGENT),
soit34 FRONTENDS, pas34 processus OS. Le plafond40, l’agent séparé et les
180=150+30 secondes restent inchangés ; aucune capacité supplémentaire n’est
déduite des moniteurs sudo/stat. Au plus7s par frontend observateur dont2s de
travail et5s de reprise, sous les échéances absolues existantes. Un slot client
est réservé au contrôle cleanup ; aucun retry ne prolonge ces bornes.

Le reçu du propriétaire devient `pamolive.gpg-fixture-owner/2` et exige une
preuve `pamolive.gpg-fixture-exe-observer/1`, liée au contexte, à la nouvelle
source et aux faits H1. Le préflight consommateur devient `/3` et refuse
l’ancien reçu sans cette preuve. Le purpose TEST/2, les six buffers, les17
catégories, les gardes crypto Google et tous les budgets restent inchangés.
L’algorithme préservé n’implique pas des reçus byte-exacts avec de nouveaux pins.
La qualification CI réelle doit encore recevoir le fallback et ses refus ;
aucun succès de l’ancien agent, du navigateur ou de l’installateur n’est transféré.

Références primaires de la couture :
- https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html
- https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html
- https://raw.githubusercontent.com/coreutils/coreutils/v9.4/src/stat.c
- https://raw.githubusercontent.com/sudo-project/sudo/main/docs/sudo.man.in

## R6 — rôle Python privilégié distinct du frontend

Arbitrage Root du16novembre2026 sur la base
`cd9b2fcf7bed8278e95108280ec17cbad257134d` : sélectionner exclusivement
`/usr/bin/python3.12` pour le superviseur `--root-install`, avec le guard
`support.tool_pin` inchangé. Aucune résolution préalable de sys.executable,
recherche PATH, alias/fallback, installation Python/pip ou chmod/chown.
Le frontend conserve son venv ; le générateur demeure non-root et le helper
d’installation exige UID0. Le nouveau rôle ne réutilise pas comme commission
la mesure du Python du producteur TEST.

La réception R5 cd9 (rapport SHA256
`da19801d2721bd029de704fb6c24ac5de8717a137b54157921d05e59d9d68bc5`)
reçoit le générateur/six buffers,17 catégories typées et huit sudo-stat, puis
le refus au choix de l’interpréteur du superviseur, avant son lancement.
Les faits leaf du Python alors sélectionné ne sont pas reçus : ni UID, mode,
nlink ou autre sous-prédicat précis ne peut être attribué à ce refus.
La note d’architecture indépendante SHA256
`d1fbb8f76dfd58195f4e009cec0794c500fa6aa361bbc0078a7dc5e89970d6b7`,
rapport `f2dd92075f8bcbc7bd3798ef463f13e224b4282f3b1236671d57601eee7ad6b2`,
gel `baa85dae10bb9125615db995a6794e97e28c9c88957ca6169d86d32d1d6ccb33`
étaye la séparation SOURCE ; elle n’admet pas un outil ni un navigateur.

Le parent mesure le chemin fixe avant sudo puis recontrôle le même hash/pin
et l’identité complète après succès. Commands.run(sudo=True) reste responsable
du frontend sudo ; il n’est pas présenté comme mesure du second exécutable.
Le helper root mesure son rôle avant authentification et après installation,
compare le vrai `/proc/self/exe` aux mêmes métadonnées, et relève in-process
version/implémentation/flags. Aucun frontend --version supplémentaire.
Les champs sont distincts : UID réel/effectif0, chemin fixe, pin/identités,
CPython3.12.x final/cache_tag, flags typés -I/-B/-S, révision/source/contexte/
manifeste. La version système n’est pas supposée3.12.16 ; son micro relève
de la distribution Ubuntu24 maintenue, TCB distincte du venv.

Le reçu d’installation devient `pamolive.chrome-bootstrap/2`, fermé, et exige
`pamolive.chrome-root-interpreter/1`. Un ancien reçu ou un champ absent/optionnel
ne permet pas de sauter le contrôle. Le parent vérifie ces faits, les mêmes
pins/identités, source/contexte/manifeste, scope et signature fournisseur ; il
refuse une dérive après retour. Un échec tardif reste UNKNOWN et ne constitue
pas une annulation d’une installation déjà effectuée. Les drapeaux navigateur,
GO et libération exhaustive des descendants restent false.

Le chemin privilégié utilise seulement les imports stdlib déjà revus. Le hash
de l’ELF ne prouve pas sa stdlib, son loader ni ses extensions : cette TCB système
demeure explicite, `stdlib_loader_hermeticity_verified:false`. Aucune herméticité,
atomicité contre un writer même UID/root, ou protection nouvelle n’est annoncée.
Le script d’entrée reste fourni par pathname avant ses self-checks : la nouvelle
sélection d’interpréteur ne ferme pas cette limite préexistante.

Les helpers partagés, gardes GPG/Chrome, quatre matériaux Google, Owner/2,
Observer/1, six buffers TEST/2 et17 catégories restent inchangés. Environnement/
PRESERVE, -I/-B/-S, H1 et horizons870/450/appel480/réserves sont conservés ;
aucun nouveau processus ni budget. La source R6 et ses purs ne qualifient ni
l’interpréteur réel, ni installation, navigateur, PAM, produit ou CVE. Une
nouvelle CI fraîche liée aux sources exactes est requise après contre-revue.
