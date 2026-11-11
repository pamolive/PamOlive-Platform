# Qualification HA synthétique après P0-3

La CI du candidat `802d560` a franchi les tests PostgreSQL, OIDC/extensions, l'image et les transports SSH/RDP natifs isolés, puis a correctement refusé la préparation des mandats HA avec `TrustError`. L'ancien pilote HA créait des liaisons IAM et une assurance TOTP, sans commissionnement PAM indépendant. Ces éléments ne constituent plus une autorité PAM depuis P0-3. Le correctif concerne **uniquement la qualification**, aucun contrôle PAM de production.

## Autorité synthétique hors portail

En mode `--native-pam` ou `--native-rdp`, l'hôte génère en mémoire deux périmètres d'organisation neufs, les clés du commissaire, trois dépositaires et un témoin. Deux dépositaires cosignent réellement les révisions Ed25519 ; le commissaire signe l'amorçage. Les authentificateurs logiciels ECDSA sont également conservés en mémoire sur l'hôte.

Les helpers de préparation publient les enveloppes publiques par les services ordinaires, enrôlent les authentificateurs via les véritables vérificateurs WebAuthn et réalisent les demandes/votes avec des preuves personnelles. Ils demandent signatures et assertions via leurs pipes privés `stdin/stdout`, sans route Web de signature. Aucune clé privée n'entre dans l'environnement, les montages ou les processus des deux serveurs applicatifs. Les documents d'authentificateur transmis au pilote ne contiennent que l'identifiant du compte de fixture.

Les deux runtimes reçoivent les mêmes ancres **publiques**, le RP ID `ha.pamolive.test` et l'origine synthétique `https://ha.pamolive.test` via un override Compose éphémère. Le témoin hôte observe les révisions commitées, refuse un recul de révision ou un changement de hash au même numéro, et renouvelle les checkpoints signés à durée maximale inchangée de soixante secondes. Le répertoire ne contient que des checkpoints publics et est monté en lecture seule dans A et B. Le validateur autorise exclusivement ce répertoire nouvellement généré, à cette destination fixe, sans exception générale pour d'autres fichiers ou montages. Les remplacements atomiques de fichiers sont visibles grâce au montage du répertoire.

Les nouvelles cérémonies attendent un checkpoint reconnu par le vérificateur courant. Aucun délai de confiance, quorum, exigence de fraîcheur ou contrôle de signature n'est désactivé. Un arrêt du témoin conduit à un refus d'autorité ; le pilote ne poursuit pas en mode dégradé. La publication de confiance et la signature personnelle ne remplacent aucun test de destination P0-2.

Chaque ouverture HTTP SSH/RDP doit d'abord produire une cérémonie PAM. Le pilote fait signer son défi exact par l'authentificateur hôte, soumet l'assertion à `/pam/trust/action/`, puis rejoue seulement le formulaire lié au même navigateur et au même chemin avec la preuve à usage unique. La même séquence est requise pour une nouvelle ouverture après arrêt ou panne. Les contrôles HA de rejeu de ticket, arrêt à distance, capture et perte du propriétaire restent présents.

## Prérequis et limites

Le mode non natif conserve son pilote Python 3.8+ et bibliothèque standard, sans Django local. Le mode natif nécessite en plus les outils `cryptography` et `cbor2` sur l'hôte ; employer l'environnement Python 3.12 installé depuis `requirements-dev.lock`, comme la CI. Aucun paquet n'est installé silencieusement par le pilote. Une dépendance manquante fait échouer la préparation avant le démarrage des conteneurs. Cette préparation ne change aucun prérequis d'une installation NAS existante.

Il s'agit de personnes et authentificateurs **simulés**, contrôlés par le même contrôleur de test, avec signatures et vérificateurs réels. La qualification n'établit ni indépendance de personnes physiques, ni garde de clés matérielles, ni cérémonie de commissionnement d'exploitation. Le driver fabrique le `clientDataJSON` d'un authentificateur logiciel ; il ne qualifie pas un navigateur sécurisé ou la terminaison HTTPS réelle. Les flux HTTP privés des fixtures ne doivent pas être transposés en production.

Le pilote continue de refuser une base d'installation : seules une base PostgreSQL nommée `test_pamolive_ha` ou son suffixe strict, le marqueur de qualification, deux conteneurs nominatifs et les réseaux prouvés sont acceptés. Le répertoire public est créé uniquement sur l'hôte de test et retiré après arrêt des deux conteneurs de qualification ; aucune clé privée n'y est écrite. Aucun NAS, annuaire ou cible réelle n'est contacté par la préparation locale.

## Vérification locale

`tests.test_active_active_trust` ajoute quatre tests : configuration sans privées, checkpoint signé et refus de recul/génération étrangère, montage public exact en lecture seule, puis commissionnement complet sur PostgreSQL avec enrôlement réel et preuves demande/vote/lancement. Le test du lancement refuse aussi une assertion présentée depuis une autre session de navigateur. Seuls la sonde réseau SSH et le transport HTTP sont simulés pour cette campagne ; les services, signatures, preuves et vérificateurs PAM ne le sont pas.

Commande locale : `manage.py test tests.test_active_active tests.test_active_active_trust --noinput`, base dédiée `test_pamolive_ha_p1trust`. Le dernier passage a exécuté **19 tests en 2,456 secondes, tous réussis, aucun ignoré**. Le test historique de refus SQLite impose désormais explicitement ce backend, au lieu de supposer que le nom de base du lanceur ne peut pas être celui d'une qualification HA. Les autres gardes de base/routage sont inchangés.

Docker Engine n'étant pas disponible localement, l'exécution des deux runtimes, des pairs SSH/RDP et des fautes HA après ce correctif reste une porte CI à obtenir. Les résultats locaux ne doivent pas être présentés comme une qualification HA Docker réussie.

Le test de commissionnement conserve le garde de base réel : il s'exécute seulement dans une base `test_pamolive_ha` au suffixe autorisé. Dans la suite générique, sa classe est explicitement ignorée après création de la base de tests ; le workflow exécute séparément les 19 tests avec `PAMOLIVE_TEST_DATABASE_NAME=test_pamolive_ha_trust`, sans mock du garde. Une contre-vérification du coordinateur sur une base au nom générique a effectivement confirmé le refus avant cette séparation des gates ; le passage dédié a ensuite réussi 19/19 en 2,705 s.
