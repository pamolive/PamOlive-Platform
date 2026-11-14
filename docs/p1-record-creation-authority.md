# Création d'enregistrements — autorité revalidée après attente

12novembre2026. Correctif local indépendant du raccourci Identity360 de P1-G. La Red Team a identifié une course préexistante dans `platform_modules/access/services.py:create_record`. Aucun environnement réel, compte privilégié réel, NAS ou secret réel n'a été utilisé.

## Chemin reproduit et portée

Le service exécutait `authorize` et `require_module`, puis attendait un `SELECT FOR UPDATE` sur l'organisation. Une révocation commise pendant cette attente n'était pas relue avant construction et sauvegarde. Un acteur précédemment autorisé, son instance Python et le module pouvaient donc conserver une autorité devenue obsolète.

Le test PostgreSQL verrouille l'organisation dans une transaction, lance un écrivain dans une connexion distincte, vérifie son attente réelle `Lock` via `pg_stat_activity`, modifie l'autorité, puis commit. Il n'utilise pas un délai arbitraire pour supposer la course. Les modifications administratives synthétiques sont effectuées sous ce verrou ; aucun contrôle de production n'est modifié.

| Scénario initial | Observation avant correction | Attente conservée après correction |
| --- | --- | --- |
| Intention après désactivation du compte appelant, retrait d'adhésion, désactivation Access | Intention `pending` créée dans les trois cas indépendants Red Team | Refus et aucune création |
| Droit après désactivation du compte appelant ou d'Identity | Grant `active` et opération `unmapped` créés | Refus et aucune création |
| Droit après retrait d'adhésion | Refus déjà assuré par la réautorisation du service d'outbound ; transaction annulée | Refus conservé |
| Organisation désactivée pendant l'attente | Test additionnel : intention créée ; droit déjà refusé | Refus pour les deux types |
| Acteur et modules toujours autorisés après attente | Intention/droit valides | Succès conservé, intention toujours `pending` |

Les six expériences initiales Red Team montrent cinq créations interdites et un refus existant. Les dix premiers tests de régression du coordinateur, avec assertions de refus, échouent avant correction sur six cas en5,929s ; les deux témoins positifs et deux refus préexistants passent. Les deux campagnes ne sont pas additionnées comme attaques uniques.

Aucun connecteur SCIM n'est configuré par ces expériences. Une opération `unmapped` n'est ni un PATCH, ni une confirmation fournisseur. Aucun secret, vote d'approbation ou session PAM n'est émis. L'impact démontré est une création locale après perte d'autorité, pas un provisioning distant ou une rupture du quorum P0-3.

## Correction minimale

La prévalidation existante reste en place. Dans la transaction et le contexte de l'organisation, `lock_authorized_actor` prend le même verrou d'organisation, recharge l'organisation active et le compte actif depuis PostgreSQL, puis vérifie l'adhésion et le rôle actuels. Le module et ses dépendances sont relus ensuite, avant toute construction d'enregistrement.

Les objets frais sont employés pour le demandeur et l'audit. Le verrou reste détenu jusqu'à la sauvegarde, l'audit et l'éventuelle mise en file. L'ordre de verrouillage reprend celui des services existants ; aucun nouveau verrou sur compte/FK, cycle ou mécanisme d'autorité n'est introduit. Les administrateurs utilisant les services de révocation partagent ce verrou d'organisation.

La MFA/CSRF des interfaces, les politiques, l'activité des objets contrôlée par les validations actuelles, `prepare_request` PAM, les preuves et la provenance P0-4 sont conservés. La modification ne prétend pas résoudre toutes les courses possibles d'objets liés ou sérialiser des écritures SQL administratives arbitraires qui ignoreraient les protocoles du projet.

## Validation locale

- Reproduction avant correction :10tests, six échecs d'assertion de refus,5,929s, aucun test ignoré.
- Après correction :35/35tests PostgreSQL en15,569s, sans exclusion :10premiers cas,17routes P1-G et8parcours HTTPS SCIM.
- Version finale :12cas de création et15tests existants d'isolation P1,27/27 en17,933s, sans exclusion. Deux organisations montrent qu'un retrait local de rôle/module ne retire pas l'autorité valide dans l'autre.
- Contre-revue indépendante :35/35en17,131s, sans exclusion :six reproductions Red Team devenues refus,12cas définitifs et17routes. Les écrivains ont réellement attendu le verrou ; aucune intention, droit ou opération n'est créé après le refus.
- Régressions P0 ciblées :224tests PostgreSQL en280,939s, aucun échec, une exclusion. Les18modules sélectionnés couvrent configuration de clé, provisioning/SCIM, sessions/mandats/quorum/confiance PAM et provenance/consommateurs/crypto/migrations/restauration d'événements. L'exclusion est `test_restore_rejects_a_missing_v8_receipt_and_keeps_v7_verifiable`, réservée à SQLite ; son homologue PostgreSQL vérifie le refus de suppression du reçu V8. Les preuves historiques V7/V8 restent vérifiables. Ce n'est pas une nouvelle qualification de transport natif.
- Ruff réussit. Aucune migration nouvelle n'est créée ; les scénarios de migration/restauration P0 sélectionnés restent distincts d'une restauration peuplée de toute l'image.

Les bases de ces campagnes sont synthétiques, dédiées et détruites par Django après leurs essais. Les journaux et deux rapports Red Team sont conservés hors dépôt. Les assertions supplémentaires SQL/audit et les témoins positifs empêchent de rendre les tests verts en refusant globalement les créations.

## Compatibilité et mise à niveau

Aucun modèle, migration, format API, clé, mandat ou preuve historique n'est modifié. Les créations qui avaient perdu leur autorité pendant l'attente sont désormais refusées. Les appels valides conservent les mêmes règles métier et le même état initial.

Le correctif ne supprime ni ne reclasse les anciens enregistrements. Une mise à niveau réelle devra conserver les journaux et examiner les créations proches de révocations administratives si une investigation historique est nécessaire. Cette note ne prétend ni avoir inspecté des données réelles ni reconstituer une exécution fournisseur depuis le seul statut local.

Fichiers du correctif : `platform_modules/access/services.py`, `tests/test_record_creation_authority.py` et ce rapport. Il est indépendant des trois lecteurs F3 et des liens de formulaire P1-G ; sa validation et son intégration peuvent être suivies séparément.
