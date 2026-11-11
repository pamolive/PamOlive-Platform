# Exploitation du registre de confiance PAM — P0-3

Le modèle C d’ADR-013 est accepté. Cette procédure décrit une installation à commissionner : aucun compte réel n’a été enrôlé et aucun déploiement n’a été exécuté pendant la remédiation locale.

## Autorités et préparation

L’administrateur tenant conserve la gestion des comptes, du TOTP et des fiches IAM. Ces opérations ne donnent aucune voix PAM. L’exploitation, le vérificateur, l’hôte et les ancres de configuration restent dans la base de confiance. Trois personnes distinctes sont dépositaires du registre ; leurs clés privées Ed25519 sont gardées séparément, hors portail. Un responsable de commissionnement hors tenant vérifie leurs identités et autorise leur nomination initiale. Deux signatures d’acceptation du manifeste prouvent la possession des clés, sans constituer une auto-nomination. Une organisation avec deux responsables locaux peut recourir à un tiers indépendant. Sans trois dépositaires et sans les personnes requises pour le quorum, le relais reste fermé.

Configurer hors base de données :

| Paramètre | Valeur et responsabilité |
| --- | --- |
| `PAM_TRUST_INSTALLATION_ID` | Audience stable propre à cette installation, identique sur ses nœuds. |
| `PAM_TRUST_RP_ID` / `PAM_TRUST_ORIGIN` | Hôte du portail et origine HTTPS exacte, sans chemin. Les authentificateurs sont liés à cette origine. |
| `PAM_TRUST_COMMISSIONING_KEYS` | Objet JSON `{organization_uuid: {key_id: public_key_base64url}}`. Clés publiques des responsables hors portail. |
| `PAM_TRUST_CHECKPOINT_KEYS` | Même format pour les témoins indépendants de fraîcheur et de restauration. |
| `PAM_TRUST_CHECKPOINT_DIRECTORY` | Répertoire de fichiers `<organization_uuid>.json`, monté en lecture seule pour tous les processus et nœuds PamOlive. |

Les valeurs de clés peuvent aussi porter `public_key`, `active`, `not_before`, `not_after`, `revoked_at`. Conserver les anciennes clés publiques et leurs dates pour vérifier les archives. Aucune clé privée de dépositaire, de commissionnement ou de témoin ne doit figurer dans la configuration du portail, son volume de sauvegarde ou ses tables.

## Cérémonie initiale

1. Créer les comptes et liens IAM ordinaires, puis les cibles P0-2 avec leurs identités cryptographiques et secrets explicitement configurés. Aucune autorité PAM n’est déduite de ces comptes.
2. Produire hors portail un corps `pamolive.pam.trust-registry/1` contenant l’installation, l’organisation, la génération UUID, la révision 1, `previous_hash` vide, `operation=bootstrap`, les dates, les personnes canoniques, leurs alias, rôles et cibles autorisées, trois dépositaires actifs et leurs clés publiques, les cibles exactes et les seuils. Au départ, les authentificateurs personnels sont vides.
3. Le responsable de commissionnement signe le corps canonique avec le domaine `pamolive.pam.trust-registry.v1\0`. Deux dépositaires distincts acceptent exactement le même corps avec leurs signatures. Le format de l’enveloppe est `{body, signatures: {person_uuid: signature}, commissioning_signatures: {key_id: signature}}`. Les helpers `signature_message` et `registry_digest` définissent les octets exacts ; utiliser une implémentation Ed25519 maintenue sur les postes de signature indépendants.
4. Importer le document public : `python manage.py pamolive_trust bootstrap --document manifeste.json`. Le témoin indépendant vérifie cette publication et distribue le checkpoint signé de cette révision. Le portail n’écrit jamais ce fichier.
5. Chaque personne désignée ouvre `/pam/trust/enrollment/` et effectue un enrôlement WebAuthn puis une assertion de possession. Le reçu public reste candidat. Deux dépositaires actuels, distincts de toutes les personnes affectées par la mutation, vérifient l’identité et intègrent le reçu dans une nouvelle révision signée `operation=update`. Importer avec `python manage.py pamolive_trust publish --document revision.json`, puis publier son checkpoint indépendant.

Pour chaque personne, le registre fixe des listes `identity_ids`, `account_ids` (chaînes), `endpoint_ids`, `roles` (`requester`, `reviewer`, `sponsor`) et `authenticators`. Tous les alias d’une personne partagent son UUID canonique. Un identifiant de compte, de personne IAM, de credential ou une clé publique ne peuvent être recyclés pour une autre personne. Un facteur révoqué reste dans l’archive, inactif. La cible contient son `scope` P0-2 intégral, `critical`, `min_reviewers`, `contract_id`, `sponsor_person`. Un contrat impose aussi `contract_authority={revision,hash}` calculé sur ses clauses et périmètres immuables par `contract_authority` ; une republication exige une nouvelle attestation.

## Changements et accès

Toute mutation exige deux des trois dépositaires **actuels**. Les personnes concernées par une nomination, habilitation, récupération ou modification de facteur sont exclues de l’ensemble des signataires, même dans un lot. Un nouveau dépositaire ne peut pas voter son admission. Préférer des opérations séquentielles quand un lot affecterait plusieurs dépositaires. Une mutation doit suivre exactement le hash et la révision précédents. L’import ne détient aucun pouvoir de signature.

Une demande, une décision d’approbation, une décision explicite de sponsor et une ouverture demandent chacune une preuve WebAuthn avec présence et vérification utilisateur. Le défi couvre l’action et son contenu, l’organisation, le compte, la personne, la session, le registre et la politique. Il est consommé une seule fois dans la transaction métier. Une cible standard exige au moins un approbateur indépendant du demandeur ; une cible critique en exige au moins deux. Les exigences plus fortes existantes continuent de s’appliquer. Un sponsor ne compte comme approbateur que s’il dispose aussi de cette habilitation. Aucun compte technique partagé ne représente plusieurs personnes.

## Fraîcheur, révocation et restauration

| Élément | Limite ferme |
| --- | --- |
| Défi et preuve d’action | 120 secondes, usage unique. |
| Registre signé | 24 heures maximum, dates contrôlées. |
| Checkpoint indépendant | 60 secondes maximum, relu sur chaque contrôle sensible. |
| Ticket de relais | 30 secondes, usage unique, navigateur et adresse liés. |
| Surveillance du relais | Contrôle à chaque cycle du broker, intervalle 1 seconde ; aucune nouvelle saisie d’authentificateur pendant le flux. |

Le checkpoint est `{body,key_id,signature}` avec un corps `pamolive.pam.trust-checkpoint/1` contenant `installation`, `organization`, `generation`, `revision`, `registry_hash`, `issued_at`, `expires_at`. Sa signature porte le domaine `pamolive.pam.trust-checkpoint.v1\0` et le corps canonique. Le témoin indépendant conserve son propre dernier état accepté, refuse tout recul et renouvelle le checkpoint de cette même révision sans mutation du registre. Son service et sa clé sont exploités séparément. Remplacer les fichiers atomiquement et distribuer la même tête à tous les nœuds ; un nœud avec une autre tête refuse l’accès. Ce témoin est une dépendance à fournir à l’exploitation, aucune racine privée ou signature automatique de secours n’est créée par l’application.

Une révocation publiée en base prend effet au prochain contrôle. Le verrou d’organisation sérialise la publication et la remise du secret : une révocation déjà engagée et validée avant cette remise la bloque ; une remise déjà autorisée sous verrou peut finir avant la révocation. Aucun verrou n’est conservé pendant le réseau. Le broker recharge le relais et vérifie de nouveau le mandat et la cible avant déchiffrement. Une révocation encore inconnue localement ne peut rester masquée au-delà de la fraîcheur maximale du checkpoint ; à expiration, le relais est arrêté au contrôle suivant.

Le choix conservateur actuel invalide les mandats et sessions dès **toute** nouvelle révision du registre, y compris un renouvellement sans changement de droits. Planifier ce renouvellement avant expiration et faire recréer les demandes. Une modification de politique locale, même ensuite annulée, invalide aussi les anciens mandats. Il n’existe aucun rétablissement automatique des votes. Une expiration du registre bloque sa mise à jour ordinaire ; utiliser la procédure de recommissionnement ci-dessous. La panne du témoin, un fichier absent, un checkpoint expiré, une horloge incorrecte ou une restauration obsolète ferment l’accès.

Après restauration, vérifier les archives avec `python manage.py pamolive_trust history --organization <uuid>`. Les signatures et captures restent vérifiables sans accepter le checkpoint sauvegardé comme preuve de fraîcheur. Comparer la tête restaurée au témoin indépendant avant remise en service. Si la base est en retard, restaurer les révisions manquantes à partir des enveloppes publiques vérifiées. Ne jamais réémettre un vieux checkpoint pour faire accepter une restauration.

## Récupération et urgence

La perte d’un facteur personnel nécessite un nouveau reçu de possession, une nouvelle vérification d’identité et deux signatures actuelles excluant le bénéficiaire. Un mot de passe, un TOTP ou un code de récupération du portail ne suffit pas. Avec un dépositaire perdu, les deux autres peuvent le remplacer, en gardant son entrée historique inactive et en ajoutant le nouveau détenteur. Avec deux dépositaires indisponibles, le registre expiré ou le quorum perdu, arrêter l’accès, faire intervenir l’autorité de commissionnement hors portail, vérifier la dernière tête contre le checkpoint indépendant et autoriser une nouvelle génération `operation=recommission` avec deux acceptations des nouveaux dépositaires : `python manage.py pamolive_trust recommission --document reprise.json`. La reprise n’autorise aucun recul ; le checkpoint précédent doit correspondre à la dernière révision en base, même s’il a expiré. Les anciens facteurs personnels ne sont pas transférés dans cette génération : réenrôler et réattester avant de nouvelles demandes.

Le break-glass est un secours **hors portail**, limité à la cible et au temps d’intervention, avec identifiants d’urgence conservés séparément. Pour une cible critique, deux validateurs distincts de l’opérateur autorisent l’intervention. Consigner le motif, la fenêtre, les validations et les preuves, puis renouveler les identifiants utilisés. Ce secours ne publie aucun registre, ne nomme personne et ne diminue aucun seuil. Les champs d’urgence forgés dans les formulaires PamOlive ne donnent aucun accès. L’application n’introduit aucune porte d’accès universelle.

## Compatibilité

Les migrations sont additives : nouveaux registres, défis, reçus et preuves ; colonnes `pam_trust` vides sur les mandats et votes existants. Aucun ancien vote n’est promu, aucune capture n’est réécrite, aucun secret P0-1/P0-2 n’est modifié. Les preuves HMAC antérieures gardent leur version de signature ; les nouvelles preuves ont leur version propre. Les anciens mandats restent consultables et expliquent les faits historiques, mais ne donnent plus d’accès PAM live. Les clients doivent commissionner leurs autorités et authentificateurs puis faire de nouvelles demandes. Les fonctions IAM/SCIM ordinaires gardent leurs contrôles existants. Le vérificateur de restauration vérifie séparément les nouvelles preuves historiques et rappelle le besoin d’un checkpoint courant indépendant.
