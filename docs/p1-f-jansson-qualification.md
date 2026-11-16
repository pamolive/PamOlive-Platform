# P1-F — Qualification du backend Jansson

État : intégration locale pour revue et première CI Linux. Pas de publication
d'image, de fusion dans main ou de déploiement NAS autorisé par ces résultats.

Le changement part de `5c16fa8973b56a188a039f71d8fc797a622a1935` sur une
branche indépendante ; le correctif Expat demeure dans sa propre PR. Les
modifications préexistantes du checkout Core sont conservées.

## Vérifications locales

103 tests synthétiques passent : 83 pour inventaire/SBOM ciblé, archives et scan,
11 pour la réception CI et 9 pour la capture des identités. Zéro échec, erreur ou
skip ; l'audit d'exécution n'a détecté aucune tentative réseau, sous-processus,
SQLite, chargement ctypes ou import de parseur XML.

Les tests de capture couvrent les changements d'heure d'accès légitimes, les
remplacements de chemin/descripteur, permissions, propriétaires, liens, taille,
mtime/ctime, lectures tronquées et fermeture du descripteur après refus.

Le SBOM complet avec validateur de schéma demeure à exécuter sous Linux. Aucun
compilateur, oracle natif, Docker, PostgreSQL ou serveur réel n'a été exécuté par
ces tests purs Windows. Les scénarios P0 complets ne sont pas déclarés rejoués.

## Revue et prochaine mesure

Les deux révisions sources et le raccord CI ont reçu des revues contradictoires.
La première révision a été refusée pour son oracle de profondeur inversé et des
lectures/hashs non liés aux mêmes octets ; ces constats et leurs gels sont
conservés. R2 lie archive et SBOM aux entrées réellement analysées. La correction
supplémentaire du producteur d'identité a reçu une revue indépendante favorable :
24 tests ciblés, dont six contre-cas du reviewer, passent sans skip ni tentative
d'IO externe. Cette revue reste limitée au code et aux données synthétiques.

La campagne CI doit confirmer l'installation de Jansson épinglé, le build natif,
les oracles différentiels/build/runtime et les bibliothèques de l'image exacte.
Les scans OS et compilés restent exhaustifs, sans filtre ni exemption ajoutée.
Une cible de référence cJSON distincte ne doit transmettre que les six DATA
prévus. L'échec de n'importe quel contrôle interdit la promotion.

Les quatre groupes cJSON et tous les autres risques de l'image historique
restent ouverts jusqu'à réception des nouvelles preuves. La qualification
amd64 n'implique aucune compatibilité ARM ou Synology.

Décision : [ADR-030](adr-030-jansson-native-json-backend.md).

La première image produit `7123f3f` se construit réellement. L'oracle C compile puis refuse JANSSON_CASE_142 avant sa capture d'identité : son hypothèse sur les pointeurs initiaux était fausse. FreeRDP initialise un certificat vide. Le banc configure désormais les trois pointeurs NULL avec le setter officiel ownership-aware et une longueur nulle, avant la sérialisation ; toutes les assertions antérieures et limites natives sont conservées. Deux gardes source supplémentaires portent les tests purs à 103. Aucun changement du wrapper ou du produit, et aucune validation native de ce nouveau banc n'est déduite du correctif source.
