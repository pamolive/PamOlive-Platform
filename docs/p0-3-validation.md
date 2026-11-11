# P0-3 — Validation locale du quorum PAM

Date : 11 novembre 2026. Modèle C d’[ADR-013](adr-013-pam-quorum-trust.md), autorisé explicitement par le responsable du projet. Travail limité au checkout local, aux tests synthétiques et à la documentation. Aucun NAS, compte privilégié réel, secret réel, déploiement, push ou commit. Les modifications préexistantes et les protections P0-1/P0-2 sont conservées. Ce rapport décrit la validation P0-3 ; la remédiation suivante est désormais consignée dans [la validation locale P0-4](p0-4-validation.md).

## Résultat de sécurité

Le demandeur peut toujours créer des comptes ordinaires, définir leurs authentifications et leurs liens IAM selon les contrôles existants. Ces comptes ne constituent aucune personne PAM attestée. Les huit reproductions initiales ont été conservées et converties en tests de refus ; sept régressions complémentaires couvrent les personnes canoniques, le quorum critique, la récupération ordinaire, les dates et les changements de contrat/politique après émission du ticket.

Le registre public est signé par deux des trois dépositaires actuels. Une personne concernée par son enrôlement, son habilitation ou sa récupération est exclue des signataires ; un lot exclut l’union des personnes concernées. Les admissions ne peuvent pas utiliser les voix des nouveaux dépositaires. La genèse est autorisée par un responsable de commissionnement hors portail et acceptée par deux dépositaires. L’enrôlement WebAuthn personnel comporte un enregistrement et une assertion de possession, puis une publication indépendante du reçu. Les alias, authentificateurs et clés ne sont pas recyclables entre personnes.

Chaque demande, vote et ouverture comporte une preuve WebAuthn à usage unique, liée au contenu complet, à la personne, au navigateur et à la révision de confiance. Les dates sont normalisées en UTC. Une cible standard exige un approbateur indépendant du demandeur ; une cible critique en exige deux. La criticité, le sponsor, le contrat, sa révision et son empreinte sont protégés par le registre. Les contrôles IAM/IGA existants restent additionnels. Un compte partagé est une cible, pas une unité d’approbation.

Le bail, le ticket, le claim et le contrôle continu vérifient l’autorité actuelle. La remise du secret recharge le relais revendiqué sous verrou d’organisation et le revalide ; elle partage ce verrou avec la publication des révocations. Un relais en attente ou sans propriétaire ne reçoit pas de secret. Les opérations réseau restent hors transaction. Une restauration d’un préfixe ancien ne peut satisfaire le checkpoint indépendant courant.

## Preuves exécutées

PostgreSQL natif **17.11**, accessible uniquement sur loopback, dans de nouveaux clusters et bases jetables aux identités synthétiques. Docker Desktop et les services existants n’ont pas été démarrés. Python 3.12.14, Django 5.2.16, cryptography 49.0.0, webauthn 3.0.1.

| Lot | Résultat vérifié |
| --- | --- |
| Reproductions du quorum | **15/15** SQLite, également incluses dans le lot PostgreSQL. Parcours HTTP, TOTP et véritables signatures WebAuthn synthétiques. |
| Sécurité P0-3, sessions, registre, concurrence, restauration et migrations contrôlées | **100 cas PostgreSQL vérifiés** : 99 réussis dans le lot final ; le test supplémentaire de restauration a ensuite été corrigé et relancé seul avec succès. Aucune suppression ni exclusion de reproduction. |
| Régressions générales | **149/149 PostgreSQL** : plateforme, mandats, migration des anciennes preuves, restauration, WebAuthn, broker, transport, appartenances, gouvernance et OIDC. |
| P0-1/P0-2 | **61/61 PostgreSQL** : configuration des clés, provisioning et création SCIM. |
| Mise à niveau avec privilèges restreints | **19 migrations**, rôle réel `NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`, retour arrière du schéma et des lignes vérifié, application réussie, déchiffrement historique préservé. |
| Contrôles statiques | Ruff sur les fichiers concernés, `manage.py check`, `makemigrations --check --dry-run`, `pip check`, syntaxe JavaScript avec `node --check`, `git diff --check` : réussis. |

Les trois lots PostgreSQL représentent **298 tests distincts** après déduplication des douze tests WebAuthn communs aux deux premiers lots. Ils ont tous un résultat final réussi. Les exclusions PostgreSQL des exécutions SQLite ont été exercées dans ces lots PostgreSQL. Les transports natifs guacd/SSH/RDP de l’image Linux ne sont pas inclus dans ce chiffre.

Les tests couvrent notamment les signatures 2/3, l’auto-nomination et la récupération, les lots de mutations, les alias canoniques, la duplication de clés COSE réencodées, les mauvais RP/origines/signatures et l’absence de présence/vérification utilisateur, le changement d’action ou de navigateur, les refus entre organisations, les contraintes SQL sur références et preuves, les checkpoints périmés ou incompatibles, les restaurations d’une ancienne tête et la vérification des preuves après expiration.

Les cinq tests de concurrence PostgreSQL utilisent des connexions distinctes. Ils vérifient la révocation avant déchiffrement d’un objet déjà chargé, le verrou effectivement observé dans PostgreSQL pendant une remise autorisée, l’impossibilité de terminer deux fois le même défi et de consommer deux fois la même preuve, ainsi que le refus d’un état restauré face à un témoin avancé. Les captures antérieures restent lisibles et scellées.

## Défauts rencontrés et corrigés pendant validation

- La revue Red Team a identifié une empreinte instable selon le fuseau horaire : dates du payload normalisées en UTC et régression HTTP avec relecture en base.
- La même revue a identifié qu’un contrat conservait son UUID après republication : ajout d’une révision et d’une empreinte de clauses/périmètres dans l’autorité signée ; un ticket déjà émis est refusé après changement.
- PostgreSQL a signalé un verrouillage sur le côté nullable d’une jointure d’enrôlement : verrou limité à la ligne de reçu, toujours sous le verrou commun d’organisation.
- Le test SQL entre organisations a révélé l’absence d’une référence composée du défi vers le registre de sa propre organisation : contrainte ajoutée, test conservé. Les tests unitaires WebAuthn isolés disposent désormais d’une tête de registre réelle pour respecter cette référence.
- Le test complet de restauration appelait un instantané qui ouvre une nouvelle isolation depuis une transaction de test déjà ouverte : utilisation explicite du mode transaction existante. Le vérificateur de restauration déduplique aussi les organisations indépendamment de l’ordre des révisions. Le test relancé valide les signatures archivées, la capture, le guard SQL et l’absence de modification des données.

## Reproduire sans système réel

Utiliser un PostgreSQL de tests neuf sur `127.0.0.1`, sans données applicatives, puis un environnement Python installé depuis `requirements.lock`. Ne charger aucun fichier d’environnement de production. Exemple PowerShell, avec le port et les identifiants **exclusivement synthétiques** du cluster local :

```powershell
$env:DATABASE_URL = 'postgresql://synthetic_test:synthetic_test@127.0.0.1:PORT/postgres'
$env:SECRET_KEY = 'synthetic-signing-key-for-isolated-local-tests-only-0123456789'
$env:PAMOLIVE_ENCRYPTION_KEY = 'synthetic-encryption-key-for-isolated-local-tests-0123456789'
$env:PAMOLIVE_TEST_DATABASE_NAME = 'test_pamolive_p03_disposable'
.venv\Scripts\python.exe manage.py test tests.test_pam_quorum_reproduction tests.test_pam_trust_auth tests.test_pam_trust_registry tests.test_pam_trust_concurrency tests.test_pam_trust_restore tests.test_pam_sessions tests.test_controlled_upgrade --noinput -v 1
.venv\Scripts\python.exe manage.py test tests.test_platform tests.test_pam_mandates tests.test_pam_mandate_upgrade tests.test_restore tests.test_pam_trust_auth tests.test_pam_broker_errors tests.test_pam_transport tests.test_memberships tests.test_governance tests.test_oidc --noinput -v 1
.venv\Scripts\python.exe manage.py test tests.test_key_configuration tests.test_provisioning tests.test_scim_creation --noinput -v 1
```

Le runner crée et détruit sa base de tests. Les fixtures conservent les clés privées synthétiques en mémoire et leurs checkpoints dans des répertoires temporaires. Les tests n’appellent ni NAS, ni annuaire, ni cible distante réelle. La qualification du rôle restreint utilise séparément une base jetable et les helpers `prepare_upgrade_fixture.seed`, `controlled_upgrade.make_plan/upgrade` et `restore_application_check.verify_application`, avec le garde de destination réel. Les clusters temporaires ont été arrêtés ; leurs répertoires PostgreSQL ne sont pas supprimés récursivement par cette remédiation.

## Revue contradictoire et indépendance

AppSec a écrit la cérémonie personnelle et relu le registre et son intégration. Le spécialiste cryptographie a écrit le registre signé et relu l’intégration des mandats et décisions. Le spécialiste PAM a écrit les portes d’exécution et leurs tests de concurrence. Le coordinateur a intégré les mandats, les décisions, la politique, les migrations et la restauration. La Red Team indépendante a relu l’ensemble, signalé les défauts UTC et de contrat, puis vérifié leur correction et les dernières portes de secret et contraintes SQL. Sa dernière revue ne confirme aucun blocage de sécurité supplémentaire dans ce périmètre. Cette conclusion est limitée au code et aux scénarios examinés.

## Conséquences et limites avant utilisation réelle

Consulter [la procédure d’exploitation](pam-trust-operations.md) pour la genèse, les clés publiques, les reçus, la récupération, le témoin indépendant et le break-glass hors portail. Les anciens mandats et votes restent archivés ; ils ne deviennent pas une autorité du nouveau modèle. Les captures et anciens formats de signatures sont conservés. Une installation existante doit commissionner ses autorités et authentificateurs et créer de nouvelles demandes.

Les limites sont fixées à 120 secondes pour une action, 24 heures pour le registre et 60 secondes pour le checkpoint indépendant. Toute révision du registre invalide les mandats et sessions actuels, même un renouvellement sans modification de droits ; prévoir leur recréation et une fenêtre de renouvellement. Une expiration du registre nécessite un recommissionnement. Un témoin absent ou périmé ferme les accès. La clé privée du témoin et sa tête durable doivent être exploitées hors du portail et de sa sauvegarde, avec distribution atomique des checkpoints. Aucun témoin autonome n’est déployé par cette phase.

La garantie repose sur l’identité vérifiée hors bande, la garde indépendante des clés et l’absence de collusion, ainsi que sur l’intégrité de l’hôte, du vérificateur et de l’horloge. Les tests utilisent des authentificateurs logiciels synthétiques et ne qualifient pas de matériel physique. Les suites natives guacd/SSH/RDP ont été adaptées mais leur porte Linux n’a pas été exécutée sous Windows ; elle reste à qualifier avant livraison ou utilisation réelle. Le correctif local n’autorise aucune mise en service. P0-4 a depuis été autorisé et validé localement ; ses tests et limites sont décrits dans [son rapport](p0-4-validation.md).
