# P1-G — inventaire public préalable aux outils NSS

Cette tranche prépare la lecture de fichiers publics de l'image MCR exacte
sur un runner GitHub Linux éphémère. Le stage0 du commit `6b3d6ade` a réellement
observé Node et le profil du conteneur, puis refusé `certutil` absent. Aucun
résultat NSS ou Chromium n'a été mesuré. Cette nouvelle phase ne transforme
pas ce refus en réussite : elle prépare les faits nécessaires au choix explicite
d'outils NSS compatibles. Aucun navigateur ou contrôle graphique du PC ou du NAS.

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
