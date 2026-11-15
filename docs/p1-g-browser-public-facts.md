# P1-G — inventaire public préalable aux outils NSS

Cette tranche prépare la lecture de fichiers publics de l'image MCR exacte
sur un runner GitHub Linux éphémère. Le stage0 du commit `6b3d6ade` a réellement
observé Node et le profil du conteneur, puis refusé `certutil` absent. Aucun
résultat NSS ou Chromium n'a été mesuré. Cette nouvelle phase ne transforme
pas ce refus en réussite : elle prépare les faits nécessaires au choix explicite
d'outils NSS compatibles. Aucun navigateur ou contrôle graphique du PC ou du NAS.

## Mesure du 15 novembre et diagnostic ciblé

Le candidat `7237070` a réellement lancé cet inventaire en
[CI 43668586740](https://github.com/pamolive/PamOlive-Platform/actions/runs/43668586740).
Il refuse `B0_FACTS_DIRECTORY_ENTRY_REFUSED`, exit42, OOMfalse ; le nettoyage
des objets possédés est confirmé. Le rapport ne révèle ni le répertoire ni le
nom rejeté. Aucune entrée particulière n'est donc réputée observée ou admise,
et aucun inventaire complet OS/NSS n'en est déduit.

Le correctif courant ajoute seulement à ce refus un diagnostic borné : espace
fermé `sources_list_d` ou `trusted_gpg_d`, taille UTF-8 et SHA-256 du basename
refusé, ou valeurs inconnues si sa forme ne permet pas ce calcul. Le nom brut,
le chemin, le contenu de fichier, l'URI et le texte d'exception ne sont jamais
exportés. Après le refus, aucun fichier rejeté n'est ouvert, lu ou staté. Les
prédicats d'admission, le code de refus, les bornes et le lifecycle restent
identiques ; le diagnostic ne crée aucune autorité de dépôt.

L'adaptateur accepte ce champ optionnel exclusivement pour ce code de refus,
avec types et forme fermés. Les anciens rapports sans diagnostic restent
acceptés comme échecs. Le runner charge explicitement les cinq nouveaux tests
Python et les neuf nouveaux tests Node ; les tests antérieurs restent intacts.
Les 36 tests Python et 37 Node du nouvel ensemble passent sans exclusion,
avec contre-revue indépendante des bornes, de la confidentialité, des 15
empreintes de sources et des seuls changements de commandes CI. Aucun succès
réel de cet inventaire corrigé n'est revendiqué avant sa propre mesure CI.

## Contrat et réutilisation

`qualification/b0_facts/adapter.py` réutilise une copie figée du lifecycle
stage0 : marges RAM/disque, acquisition publique par digest, création réservée
durablement avant requête, profil Docker et nettoyage par identité complète.
Les six fichiers historiques restent byte-identiques. L'adaptateur remplace
seulement le suffixe de commande par l'entrée Node explicite `/usr/bin/node`
et le programme `facts.cjs`. Ce chemin n'est pas affirmé comme présent par les
anciennes mesures ; son absence refuse sans shell de recherche ou fallback.
Les schémas, phases, préfixes de run et rapports sont distincts du stage0.

Le conteneur monte uniquement deux assets fermés RO et sa sortie synthétique.
Utilisateur nonroot, rootfs RO, capacités supprimées, NNP, réseau none, IPC
privé, RAM256M sans swap supplémentaire, CPU0.5, tmpfs64M noexec, shm16M,
processus et journaux bornés. Aucun dépôt, socket Docker, profil hôte ou donnée
PostgreSQL n'est monté. Le cache d'image public reste sur le runner jetable ;
`resources_released` vise les objets possédés, pas la suppression du cache.

La sonde emploie uniquement les builtins Node pour lire des chemins publics
fermés : OS, sources APT, identité SHA du keyring Ubuntu, champs publics dpkg,
outils et bibliothèques NSS/NSPR. Aucun APT, dpkg-query, GPG, certutil, ldd,
shell, navigateur, import npm ou sous-processus n'est exécuté. Aucun fichier
d'authentification APT, environnement de processus, clé privée ou profil n'est lu.
Le keyring est hashé sans exporter ses octets ; fingerprints restent `null`.

Les lecteurs contrôlent ancres, alias, types, droits, liens, identité après
ouverture, tailles et budgets avant rétention. Les listings sont incrémentaux,
les stanzas comptent les octets UTF-8 bruts LF/CRLF et la sérialisation est
bornée. Champs, options ou chemins non supportés refusent sans afficher leur
contenu. Les dépendances et versions installées restent des faits ; aucun
solveur ni autorité de dépôt n'est créé.

## Validation et limites

Le candidat `8b0cf1a` a ensuite été exécuté dans deux phases distinctes le
15 novembre. Le [stage0](https://github.com/pamolive/PamOlive-Platform/actions/runs/43665571008)
observe Node `v26.13.0`, nonroot, rootfs RO, capacités nulles et NNP, puis refuse
`B0_PRE_CERTUTIL_MISSING`. Chromium, NSS, TLS et CDP restent non mesurés.
Le [lecteur de faits](https://github.com/pamolive/PamOlive-Platform/actions/runs/43665571053)
atteint sa vérification des sources, puis refuse `B0_FACTS_SIGNED_BY_UNSUPPORTED` :
code enfant42, pas d'OOM, objets possédés et réservation libérés. Le rapport
incomplet ne permet pas d'affirmer les versions OS ou NSS, ni le chemin exact
de la déclaration ayant provoqué ce refus. Aucun de ces essais n'est une réussite
de qualification navigateur.

L'historique public de la configuration MCR déclare une référence NodeSource
pour Node26 avec un autre `Signed-By`. Il s'agit d'une cause candidate, pas d'un
fait mesuré dans le système de fichiers. Reconnaître cette seule déclaration
pour inventaire ne donnera aucune autorité à son dépôt ou à sa clé et ne doit
ouvrir aucun nouveau fichier de clé. Une future mesure conserve ces deux
échecs historiques.

Le lecteur reconnaît désormais seulement le tuple déclaré exact Node26,
`deb`/HTTPS/`nodistro`/`main`, sans architecture explicite, dans le fichier
`nodesource.list` sans alias. La projection conserve son véritable `Signed-By`
avec `candidate_not_authorized` et `key_material_inspected=false` ; son keyring
reste hors des chemins autorisés, sans même être staté. Une autre version,
destination, option, composante, clé ou un fichier source différent refuse.
La projection Ubuntu et le lifecycle restent inchangés. Cette extension est
testée sur FakeFS ; la présence réelle du tuple reste à mesurer en CI.

Les tests du lecteur passent de21 à28groupes Node, avec mutations des champs,
options, chemins et alias et une sentinelle interdisant toute lecture de la clé
candidate. Les31tests Python historiques restent inchangés et réussis, sans
exclusion. Les anciens rapports8b restent conservés séparément.

La contre-revue indépendante ajoute54contre-cas. Le scanner conserve ses
plugins, filtres, paramètres et flags : quatre nouveaux signaux sont classés
individuellement, trois SHA de fichiers publics exacts et une chaîne factice
d'un test d'URI refusé. Trois anciennes empreintes remplacées, absentes de leur
fichier courant, quittent seulement le baseline actif ; leurs décisions restent
dans le commit parent et les preuves de revue. Il reste333décisions actives,
sans suppression de détection ou de contrôle.

Avant intégration, Root a rejoué 31 tests Python sous interdiction de création
réelle de processus/réseau et 21 tests Node sur FakeFS, sans exclusion. Ces
comptages incluent les 18 tests stage0 inchangés et ne représentent aucune
mesure dans l'image. La contre-revue indépendante précède le premier lancement
CI ; son résultat et la mesure réelle seront documentés séparément.

La copie intégrée normalise en LF le seul manifeste d'assets JSON non signé,
avec égalité de l'objet parsé, et formate deux fichiers Python selon le projet,
avec égalité complète de leurs AST. Les dix autres assets runtime/test restent
byte-identiques au prototype revu. Les empreintes concrètes de la copie intégrée
sont vérifiées avant outils/contrôleur ; les sources de préparation et preuves
de développement restent hors publication.

Le workflow utilise les versions de sécurité existantes, Ruff0.14.3 et le
Node hôte du runner pour syntaxe/FakeFS seulement. Ces outils hôte appartiennent
au TCB du runner ; leur provenance n'est pas fermée par un nouveau verrou de
wheels. Le bootstrap pip reste hashé. Aucun résultat hôte ne remplace celui du
Node de l'image. Le manifeste et les pins identifient les octets ; ils ne sont
pas une attestation indépendante du build Microsoft.

Seul `public-facts-report.json` est uploadé, au plus768KiB. Pas de logs Docker
bruts, state/spool, source/status brut, keyring, cookie, profil, ticket ou HAR.
Un succès signifie uniquement inventaire public terminé. Les flags stage0,
authentification Release/archives, NSS, TLS, sandbox, CDP, autorité et publication
restent faux ou non mesurés. Les signatures Ubuntu, archives exactes, fermeture
des dépendances, dérivé de test et nouvelle mesure stage0 sont des étapes
distinctes. Aucun résultat Debian A1 n'est transféré à Ubuntu.

Les 35 groupes High du runtime PamOlive et la provenance de build incomplète
restent bloquants. Cette tranche ne modifie aucun modèle, migration, parcours
P0, protection SCIM/PAM ou service métier ; aucune promotion ou installation
NAS n'en découle.
