# P1-G — Parcours HTTP PAM et dates du parcours d'accès

## Périmètre

Ce lot prolonge l'intégration `09b6fa43` ; il ne figure pas dans les images ou
CI de ce commit. Il réutilise les routes, formulaires, services et vérificateurs
P0 existants. Aucun modèle, migration, règle d'approbation, mécanisme de clé ou
contrat JSON n'est changé. Le seul correctif produit concerne le rendu HTML
des dates de bail et de relais dans le parcours d'accès.

Les cinq scénarios passent par `Django Client(enforce_csrf_checks=True)` :
connexion avec mot de passe, organisation, véritable enrôlement TOTP, liaison
de personne, configuration de cible et WebAuthn begin/register/finish. Les
assertions ES256 et publications cosignées/checkpoints Ed25519 utilisent les
vérificateurs existants ; aucun `force_login`, timestamp MFA ou booléen
d'autorité n'est injecté. Le probe SSH préalable à l'activation est la seule
substitution réseau : aucun serveur SSH/RDP ou compte privilégié réel n'est joint.

Le constructeur de la fixture de confiance accepte `auto_enroll=True` par
défaut, conservant le comportement historique. Le nouveau scénario choisit
explicitement `False` pour exercer les routes d'enrôlement HTTP, puis publier
les reçus par la cérémonie cosignée synthétique existante. Cette préparation
simule l'autorité indépendante ; elle ne prouve pas l'indépendance d'humains,
la garde de clés physiques ou une attestation matérielle.

## Scénarios exécutés

1. Identity 360 → formulaire existant → demande signée → deux votes de
   personnes commissionnées → ticket/relais `pending` → parcours HTML/JSON →
   arrêt HTTP → chaîne d'audit. Le compte technique partagé conserve son
   propriétaire ; aucune observation ou preuve d'exécution distante n'est créée.
2. Changement d'organisation entre défi, finish et reprise : refus sans objet
   métier étranger ; lectures et vote sur une demande d'un autre tenant refusés.
3. Un compte reviewer contrôlé par l'organisation, avec TOTP et liaison IAM
   mais sans habilitation indépendante, ne complète pas le quorum.
4. Révocation cosignée de l'authentificateur après émission du défi : finish
   et création de demande refusés.
5. Révocation du lien de personne après approbation : lancement refusé,
   décisions et preuves historiques conservées et vérifiables.

Les formulaires de reprise utilisent exclusivement `resume.path` et les
paires `resume.fields` retournées par le serveur. Le test ne reconstruit pas
une autorisation depuis des valeurs originales ou une session modifiée.
Les réponses ne doivent pas contenir le secret cible synthétique.

## Défaut reproduit et correction

Le template utilisait `item.started_at|default:item.connected_at`. Django
résout l'argument du filtre même lorsque `started_at` est renseigné. Or les
lignes de bail n'ont pas `connected_at` et les lignes de relais n'ont pas
`started_at`. Le parcours HTML produisait donc `VariableDoesNotExist` dès
qu'un bail était présent. Ce template était identique dans `dcaa116` et `09b6fa43`.

Le rendu choisit maintenant explicitement le type déjà présent : un bail
affiche sa date locale ; un relais affiche sa date de connexion enregistrée,
ou « Connexion non enregistrée » lorsqu'elle manque. Aucun horaire de bail
n'est substitué à une connexion distante. Les données exportées, états,
permissions, limites et signatures restent inchangés.

Une régression `SimpleTestCase` rend le vrai template sans base avec un bail,
un relais pending et un relais connecté. Elle échoue avant correction sur
`connected_at` manquant, puis passe : chaque date apparaît une fois et le
placeholder n'invente aucune connexion. La contre-revue indépendante vérifie
aussi les dates absentes, les listes vides, l'échappement HTML et le module
désactivé, sans accès à une base.

## Résultats locaux du 14 novembre 2026

| Exécution | Résultat | Portée |
| --- | --- | --- |
| HTTP1 | 5 échecs de préparation, 3,115 s | Attente de test incorrecte : le formulaire retire le LF final d'une clé publique SSH ; aucun scénario métier atteint |
| HTTP2 | 4 réussites, 1 erreur, 11,022 s, zéro ignoré | Défaut de rendu reproduit ; positif atteint le ticket pending, sans arrêt/audit final |
| Rendu avant correction | 1 erreur, 0,032 s | Reproduction isolée, aucune base utilisée |
| Rendu après correction | 1 réussite, 0,031 s | Bail, relais pending et connecté ; aucune base utilisée |
| Contre-revue de présentation | 8 sondes réussies | Original reproduit, nouveaux états/dates/placeholder, autoescape et module désactivé |
| HTTP3 | **5/5 réussis, 10,984 s, zéro ignoré** | Parcours positif jusqu'à l'arrêt et l'audit, quatre négatifs ; PostgreSQL synthétique réel |
| Régression combinée | **324 réussites + 1 exclusion sur 325, 343,719 s** | 29 modules dédupliqués : sélection P0 historique, extras PAM et vues/parcours |

La sélection P0 compte 19 modules : 227 tests exécutés, 226 réussites et
une exclusion SQLite nominative
`test_restore_rejects_a_missing_v8_receipt_and_keeps_v7_verifiable`.
PostgreSQL interdit cette suppression ; sa contrepartie
`test_postgres_refuses_receipt_deletion_and_preserves_verification` réussit.
Cette exclusion n'est pas comptée comme succès. Les trois extras PAM passent
28/28 ; les sept modules de vues/parcours passent 70/70. Aucun autre test n'est
ignoré et aucun échec n'est observé. Les fichiers gelés sont inchangés après
exécution. Cette sélection ne représente pas tous les tests possibles de P0.

Les journaux des premières tentatives restent conservés hors dépôt, sans
les reclasser comme réussites. Chaque base PostgreSQL dédiée a été créée puis
détruite ; zéro session subsiste. L'OID et le propriétaire de la base de
laboratoire préexistante sont conservés ; aucun hash exhaustif de ses données
n'est revendiqué. Aucun volume ou donnée de production n'a été modifié.

Le scan de secrets final et la CI du prochain commit restent requis avant
livraison de ce correctif. Les résultats du sujet `09b6fa43` et de ses images
ne lui sont pas attribués. Aucun modèle ou migration n'a changé ; les portes
de migration/restauration de la CI du nouveau candidat restent nécessaires.

## Limites

Ce parcours n'exécute pas le JavaScript, `navigator.credentials`, un navigateur
graphique ou un WebSocket. Les clés virtuelles Python et les autorités de
fixture sont synthétiques. Le relais reste pending jusqu'à son arrêt, avec
`connected_at` nul et aucune capture ; le ticket ne prouve pas une session
SSH/RDP. Les portes natives existantes demeurent distinctes.

Une tranche navigateur headless séparée est en préparation ; elle devra
conserver TLS/CSRF/P0 et identifier explicitement la simulation UP/UV. Ce lot
ne qualifie ni P1-G complet, ni un service P2, ni une image, la HA ou le NAS.
Les 35 groupes High non arbitrés du socle et les matériaux/attestations
manquants continuent à bloquer la promotion. Aucun `main` modifié, image
publiée ou déploiement ne découle de ces tests.
