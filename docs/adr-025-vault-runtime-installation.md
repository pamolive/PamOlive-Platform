# ADR-025 — Installation autonome du runtime de réservation Vault

Statut : accepté pour le packaging et le contrôle local des données de la wheel.
La qualification d'une installation isolée du runtime reste à recevoir.

## Contexte

ADR-024 sépare déjà les sources du runtime, le slot administré, le principal mTLS
et le ledger non-owner. Les 52 tests purs du checkout, les campagnes locales et
le vérificateur public installé sont des sujets différents. Aucun résultat de
ce dernier ne démontre l'installation du runtime Vault. Les limites de mémoire
du PC ne doivent pas conduire à modifier les fenêtres ou les refus de sécurité.

## Décision

Préparer une wheel interne `pamolive-vault-reservation-runtime` version
`0.1.0a1`, contenant seulement les huit modules courants. Elle conserve les
dépendances explicites au vérificateur public V1 et aux contrats, tous deux en
version `0.1.0a1`, à cryptography `50.0.2` et à Uvicorn `0.54.0`. Cette dernière
version est déjà exigée par le pont H11 ; le packaging ne modifie pas son garde.
Les matériaux et outils de qualification seront verrouillés séparément par
empreinte ; un nom/version seul ne suffit pas à accepter un téléchargement.

Le schéma SQL actuel est installé comme donnée sous
`share/pamolive/vault-reservation/schema.sql`, sans copie divergente de sa source.
Le runtime ne le recherche ni ne l'exécute automatiquement. L'opérateur doit
toujours employer un propriétaire distinct du rôle runtime. Le fichier LICENSE
porte les octets de la notice actuelle à la racine du dépôt.

Aucun point d'entrée de service, connecteur par défaut, DSN implicite, migration
Django, nouvelle politique de bind ou API de remise n'est ajouté. Le connecteur
SQL reste une dépendance fournie par le démarrage de confiance. Le package ne
déclare pas de driver SQL dont son code n'effectue aucun import ; un laboratoire
SQL réel devra fournir et qualifier son driver explicitement.

## Qualification exigée

Construire depuis une sélection fermée copiée dans un répertoire de travail neuf,
sans artefact de build dans le checkout. Réutiliser les outils publics verrouillés,
vérifier les entrées ZIP, métadonnées et RECORD de la wheel : sources, notice et
SQL exacts, aucune fixture, contre-fixture R1, intégration, clé, log ou module
supplémentaire. Les fichiers de diagnostic préexistants restent hors publication.
Le backend verrouillé marque `license-file` dynamique après expansion des globs ;
seul cet en-tête précis est admis, avec une notice unique contrôlée octet pour octet.
Les autres métadonnées dynamiques et les dépendances supplémentaires refusent.

La construction locale et le contrôle de ses quatorze fichiers sont reçus avec
17 tests adverses et les 52 tests purs existants, sans exclusion. La contre-revue
indépendante confirme la fermeture des deux constats du premier contrôleur :
rejet des enveloppes mail et du corps parasite WHEEL, lecture bornée du même FD
avec contrôles d'identité. Les constats et le premier candidat restent conservés.
Cette réception ne démontre pas l'installation ou l'exécution du runtime.

La qualification installée devra employer un venv neuf sans site global, puis
installer hors réseau uniquement les wheels publiques vérifiées et les trois
wheels PamOlive construites. Vérifier les dépendances, les origines des imports
et l'absence de Django, de l'application et du SDK de déchiffrement. Les cas
doivent utiliser le package installé ; aucune substitution par le checkout ou
un prototype local n'est permise. Conserver les assertions historiques et les
contre-fixtures de test séparées de l'artefact installé.

Une campagne CI Linux dédiée est la cible pour cette réception et, ensuite,
pour les cas TLS/PostgreSQL/restauration. Elle réutilisera les gardes de ressources,
de provenance, d'ownership et de nettoyage existants avec un sujet Linux explicite.
Les identités Windows/Docker Desktop et leurs anciens résultats ne sont pas
transposables par simple changement de chemin ou normalisation de champs inconnus.
La CI doit mesurer son contexte avant allocation, garder les fenêtres 40/30 et
produire des faits observés, avec des accès GitHub en lecture et des données
exclusivement synthétiques. Le [runner d'installation](p2-vault-runtime-installed-qualification.md)
est maintenant implémenté localement, avec 55 tests de harnais, sept tests de
capture et six tests de garde de démarrage. Sa contre-revue et son exécution
Linux restent distinctes ; aucune installation qualifiée n'en découle encore.

## Alternatives

Conserver uniquement les sources montées ne reçoit pas leur installation.
Distribuer l'image applicative complète comme Vault ajouterait des dépendances
et des autorités sans nécessité ; elle demeure de plus bloquée par son scan.
Publier immédiatement une image Vault prétendrait disposer d'une qualification
et d'une provenance de build qui restent manquantes. Une wheel interne permet
de contrôler d'abord la fermeture du code et de ses dépendances, sans cette
promotion.

## Compatibilité et limites

Les huit modules, le schéma, les rôles N0, SQL/TLS, le slot et les résultats
`pending_proofs` / `authorized:false` restent inchangés. Les installations
existantes et les appelants P0 ne sont pas migrés. Le package n'est ni un
déploiement, ni une image minimale qualifiée, ni une capacité de remise.

La restauration clandestine sous la même incarnation exige toujours un ancrage
indépendant des usages avant toute remise de secret. Les 35 groupes High,
la provenance de build incomplète, la reprise multi-hôte et les limites de
qualification existantes restent ouvertes. Aucun merge main, publication d'image,
NAS ou compte réel n'est autorisé par cet ADR seul.
