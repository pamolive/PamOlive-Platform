# P1-F1/F2 — inventaire persistant et lecteurs d’annuaire

État : implémenté, validation locale en cours ; non intégré dans main et non installé sur NAS. Ce rapport suit le candidat réel et ne remplace pas les rapports P0.

## Comportement livré

Connect conserve des sources à destination immuable, des collectes acceptées, leurs faits signés et des décisions explicites de correspondance vers les comptes IAM du même tenant. Configuration, activation et rotation sont séparées. La rotation conserve la source et incrémente sa révision ; une autre destination, identité de lecture, base DN ou empreinte exige une autre source.

L’interface native, les API et les exports partagent les mêmes services protégés par activation de modules, rôle frais et organisation. Les mutations imposent une MFA récente. Les lecteurs ne voient pas les contrôles d’administration ; les mots de passe et jetons ne sont jamais réaffichés. Les entrées sont bornées sur les octets réellement lus, même sans Content-Length, et les fixtures exigent une liste JSON explicite. Les doublons de clés et JSON excessivement imbriqués sont refusés.

Une fixture humaine conserve `synthetic_fixture`. Une collecte serveur authentifiée de laboratoire est distincte. Une acceptation signée atteste l’enregistrement par PamOlive, jamais la vérité des faits distants ou l’indépendance d’une personne PAM. Même clé/même contenu retourne le même run ; un contenu divergent provoque un conflit409 audité, sans réécrire l’original.

Le lecteur natif Linux prend en charge LDAP/AD avec StartTLS obligatoire et contrôle CA/nom/pin sur la connexion effectivement utilisée. LDAPS est explicitement refusé avant réseau ou secret : l’API publique utilisée ne permet pas de le qualifier sur le descripteur déjà épinglé. Graph reste une préparation read-only avec vérification du tenant par une requête authentifiée ; l’inventaire des groupes n’est pas qualifié.

L’état LDAP absent reste inconnu. Une absence, un groupe déclaré ou une correspondance administrative ne crée aucun Grant, vote, mandat ou ordre SCIM. Le lecteur est limité aux destinations synthétiques loopback/`.invalid` autorisées, sans annuaire ou identité réelle. Voir [ADR-018](adr-018-directory-inventory.md) et [protocoles](p1-f-directory-protocols.md).

## Schéma et récupération

`connectors.0012_directory_inventory` ajoute `DirectorySource`, `DirectoryRun`, `DirectoryFact` et `DirectoryMapping`, initialement vides. Les anciens modèles et données ne sont pas reclassés. PostgreSQL protège l’immutabilité des preuves et les références inter-organisations. Le downgrade refuse une base contenant ces preuves.

Le vérificateur de restauration recharge le tenant pour chaque famille de preuves, vérifie source, sceau de credential, déchiffrement, normalisation v2, digest, faits et chaîne des correspondances. Le corpus synthétique inclut deux organisations et des histoires de mapping. L’outil de mise à niveau accepte désormais23migrations et41nouveaux modèles depuis son schéma historique de référence. Ces nombres ne représentent pas le nombre total de tables du projet.

Le rôle de migration testé est propriétaire de sa base sans privilège d’administration. Cette qualification ne constitue pas un rôle runtime sans DDL ; cette séparation reste au programme P2.

## Résultats enregistrés

| Campagne | Résultat observé | Portée et limites |
| --- | --- | --- |
| Backend persistant | 25/25 PostgreSQL, 12,386s | Provenance, mapping, quotas, pagination, état nullable, isolation SQL, migration et courses |
| Rôle restreint, campagne finale | 102/102 PostgreSQL, 266,403s, zéro exclusion | Base précréée ; NOSUPERUSER/NOCREATEDB/NOCREATEROLE/NOINHERIT/NOREPLICATION/NOBYPASSRLS ; base et rôle temporaires supprimés |
| Interfaces natives | 12/12 PostgreSQL, 5,209s | Rôles, modules, HTML/API/export, CSRF/MFA, replay/conflit et rotation sans secret |
| Revue indépendante finale | 42/42 PostgreSQL, 11,495s, zéro exclusion | Suites Red Team de services et d’interfaces, fixtures StartTLS ; [reproductions et corrections](p1-f-redteam.md) |
| Protocoles Linux réels, après correction de portabilité | 41/41,10,176s, zéro exclusion ;6/6wire UID1000 en5,307s | 35adaptateurs et6essais OpenLDAP ; réseau none, pairs loopback synthétiques ; LDAPS testé comme refus |
| Migration/restauration/diagnostics | 23/23 PostgreSQL, 214,069s | Migration0012, upgrade contrôlé, rollback et preuves corrompues refusées |
| Archive PostgreSQL réelle | Réussite | pg_dump/pg_restore sur copie :106modèles,87preuves signées,17valeurs chiffrées,1capture scellée ;4sources/6runs/6faits/8mappings, reçus V7/V8 conservés |
| Ruff, Django check et migration dry-run | Réussite | Aucun changement de modèle non migré détecté |
| Dépendances Python et SBOM Linux | Réussite | Lock Linux complet, y compris python-ldap ; aucun avis connu signalé au moment du scan |
| Bandit application/deploy | Réussite | Seuil application moyen/haut, déploiement haut ; ne remplace pas les essais adverses |
| Secrets | Aucun nouveau signal sur582fichiers | Baseline relue conservée, aucune vérification distante de secrets ; nouvelle passe avant commit |
| Première suite PostgreSQL complète locale | 1054tests en1432,975s ;1erreur,48exclusions | Fixture tenantB sans dépendance Access dans le snapshot chargé ; corrigée et revalidée dans les102tests restreints. Aucun résultat global vert n’est revendiqué pour cette exécution ; la CI du candidat exact doit rejouer la suite complète. |
| Image applicative | Build et probe runtime réussis | Linux/amd64, import python-ldap3.4.8, pip check, absence de compilateurs/en-têtes/wheels intermédiaires ; snapshot de travail, pas encore une image publiée |
| Pile TLS locale | Réussite | Application/worker/PostgreSQL/gateway sains, migrations vierges, PC-483 attendu/PC-991 écart, arrêt/redémarrage sans perte et proxy limité au pair exact |
| Restauration Docker avec preuves Directory | Réussite | Même image locale :106modèles,4sources/6runs/6faits/8mappings,8chiffrements et reçus V7/V8 conservés ; copie/rôle temporaires supprimés, volumes préservés |
| Scan OS/native initial | Refus de qualification | 1326correspondances, dont69Critical/570High ;1326matches ne sont pas1326exploits distincts. Python et FreeRDP anciens confirmés ; [rapport et remédiation](p1-f-image-security.md) / [ADR-019](adr-019-native-runtime-dependencies.md). Nouveau runtime et rescan final requis avant fusion/publication. |

La première CI du commit3ae2968 a refusé le candidat : trois positions de ligne de fingerprints existants étaient obsolètes, sans nouveau signal de secret, et les six fixtures OpenLDAP ne démarraient pas sous Ubuntu. La baseline conserve exactement ses88empreintes et décisions de revue ; seuls trois numéros de ligne sont actualisés. Le déplacement initial de la fixture dans un répertoire privé `/var/tmp` n’a pas qualifié Ubuntu : le rejeu f3e68c5 a encore refusé les six pairs avec `fixture_permission_refused`.

Les journaux récupérés distinguent aussi un échec de création d’artefact après cinq tentatives, alors que les analyses du job sécurité avaient réussi. Le candidat suivant crée exclusivement sur le runner éphémère un nouveau sous-répertoire0700 sous le chemin MDB déjà confiné `/var/lib/ldap`, attribué au runner et désigné explicitement à la fixture. Les chemins arbitraires, liens, parents non possédés ou trop permissifs sont refusés ; aucun profil AppArmor n’est modifié. Le nettoyage ne supprime que ce parent vide créé par l’étape. Le plafond256descripteurs s’applique au seul processus fils, sans changer les limites du parent. La cause kernel exacte du refus reste à confirmer, ainsi que la nouvelle CI Ubuntu. Le [rapport Ubuntu](https://lists.ubuntu.com/archives/foundations-bugs/2026-July/550853.html) distingue les permissions de fichiers temporaires ; il ne démontre pas à lui seul les permissions de verrouillage MDB de ce runner.

Rejeu Linux local des sources courantes par six overlays lecture seule : **43/43 en6,703s**, zéro exclusion, réseau none, UID1000, rootfs lecture seule et parent dédié en tmpfs0700. Le premier essai de ce contrôleur avait superposé l’adaptateur actuel avec une ancienne suite wire embarquée dans l’image ; il a été refusé (trois échecs/deux erreurs) et conservé. Le rejeu utilise également la suite wire courante ; il ne qualifie pas l’ancien snapshot ni le profil hôte Ubuntu. La régression P0 ciblée PostgreSQL passe **193tests en263,261s**, une exclusion réservée à SQLite, aucun échec. Les campagnes complètes et native/restore du SHA final restent obligatoires.

Les nombres sont des campagnes distinctes, parfois répétées : ils ne doivent pas être additionnés comme une couverture de tests uniques. Les essais Windows sans bibliothèque native excluent explicitement les six essais OpenLDAP ; seuls les résultats Linux correspondants valident ce transport.

Deux campagnes distinctes ont été exécutées : le corpus complet avec capture scellée via le checkout Python hôte, puis une vraie restauration de l’image Docker locale enrichie de preuves Directory sur deux tenants. Cette dernière conserve106modèles,8valeurs chiffrées et8reçus V8 ; elle n’exerce pas de capture PAM scellée. L’image finale doit encore passer les gates de restauration/upgrade et les régressions P0 de CI à son SHA exact avant publication.

## Revue et risques résiduels

La revue contradictoire a fermé une fenêtre d’émission des credentials après révocation pendant TLS, puis ajouté une revalidation entre pages LDAP. Une vérification finale refuse aussi l’acceptation après rotation ou révocation. Les octets déjà émis au pair précédemment autorisé ne peuvent pas être annulés rétroactivement.

Le plafond LDAP s’applique après décodage OpenLDAP, sans garantie d’allocation mémoire préalable. Les limites du conteneur restent nécessaires. La résolution DNS conserve au maximum quatre opérations en vol, y compris après timeout ; elle ne peut pas tuer le resolver système.

L’équivalence entre un annuaire observé et un connecteur SCIM n’est pas établie par un UUID ou un compte local commun. Les confirmations SCIM et chaînes TeamViewer conservent leurs autorités et contextes historiques. Le [lot de rapprochement suivant](p1-f-reconciliation-review.md) doit les présenter séparément, sans produire d’autorisation ou de confirmation croisée implicite.

Cette version reste alpha/laboratoire. AD commercial, Entra réel, LDAPS, exhaustivité de groupes et production multi-hôte ne sont pas qualifiés. Aucun NAS, compte privilégié réel ou donnée de production n’a été contacté par ces campagnes.

## Avant une mise à niveau réelle

Conserver l’image et les clés historiques, arrêter tous les anciens rédacteurs pendant le changement de schéma, qualifier une sauvegarde sur copie avec le runtime exact et le rôle de migration prévu, examiner le plan autorisé, puis vérifier les preuves après migration. Ne pas redémarrer une ancienne application sur une base enrichie de nouveaux runs. Créer explicitement les sources inactives et leurs justificatifs synthétiques ; aucun import automatique de credentials SCIM/PAM ou de collecteur n’est réalisé.

Le candidat est suivi dans la [PR2 en brouillon](https://github.com/pamolive/PamOlive-Platform/pull/2). La CI finale, le digest et l’attestation seront inscrits après leurs validations réelles. Aucun tag stable/latest ni déploiement NAS n’est implicite.
