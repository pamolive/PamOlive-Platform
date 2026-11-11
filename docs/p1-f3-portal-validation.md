# P1-F3 — activation locale du portail et préparation P1-G

12novembre2026. Travail exclusivement local et synthétique dans un checkout de revue séparé, branche `agent/p1-f3-portal`, base95fe14ff3473da426e91383f605795d671e34552. Les résultats ci-dessous précèdent l'intégration du coordinateur. Aucun push, PR, déploiement, NAS ou navigateur du PC n'a été utilisé pour ce sous-lot. La base native95fe14f n'est pas une image promue et n'est pas qualifiée par ces résultats fonctionnels.

## Préservation du travail existant

Treize fichiers F3/P1-G ont été copiés depuis le checkout principal, sans les retirer ni modifier leurs octets sources. Les hashes avant/après et destination initiale sont conservés hors dépôt dans `output/p1-f3-source-copy-manifest.json`. Les modifications d'intégration ci-dessous concernent exclusivement le nouveau checkout.

L'outil de worktree géré n'a pas réussi à valider le dépôt à cause de son ownership Git, puis un appel est resté suspendu sans identifiant d'opération. Le coordinateur a autorisé le repli `git -c safe.directory=… worktree add`. Le checkout Git est fonctionnel ; son attachement comme worktree géré a été refusé par l'application et aucun attachement n'est revendiqué. Une entrée safe.directory globale ajoutée pendant le diagnostic a été retirée ; les deux entrées préexistantes sont conservées. Les commandes Git du sous-lot utilisent des exceptions par commande.

## Intégration ciblée

`config.urls` inclut maintenant le module canonique des trois routes F3 : HTML, API de session et export JSON. Les services, vérificateurs, destinations et autorités du lecteur restent ceux contre-vérifiés auparavant. Aucune migration, nouvelle opération, attribution de droit ou autorité de création n'est ajoutée.

La fiche F1 d'une source relie sa revue des comptes, avec limite et curseur validés conservés. Identity360 relie l'index des sources seulement lorsque Connect et ses dépendances sont disponibles. Le parcours de navigation est Identity360→sources→fiche de source→revue ; ce lien n'invente aucune association de personne historique à une observation d'annuaire.

Les URLconf additionnels de tests sont retirés. Les29méthodes Red Team sont identiques selon comparaison AST, sans modification d'assertions ; la preuve est `output/p1-f3-red-assertion-preservation.json`. La présentation/export reste une relecture actualisée et bornée, avec références et dates du run, jamais un snapshot ou bundle de preuve publique.

Quatre nouveaux tests d'intégration couvrent les routes canoniques effectives, le chemin HTML complet sans écriture, le masquage du lien Identity360 lorsque Connect est désactivé sans requête aux tables Directory, et la conservation d'une continuation réellement signée avec bornes facts/absent respectées. Le contrat F3 préexistant, section « Entrée et permissions », indique déjà qu'une page peut contenir fin des faits et début des absences :la limite s'applique donc par phase, pas à l'union. Les interfaces F1/F3 affichent maintenant explicitement «jusqu'àNfaits etNabsences, maximum2N» et F3 expose `page_limits`. Le test compare les payloads d'observation, source, run et continuation de F3 à ceux de F1, puis chaque borne et le libellé HTML ; il ne remplace pas le contrat par la longueur observée de l'implémentation.

## Validation PostgreSQL

Commande via le runner privé dédié au worktree :

```text
run_p1f3_worktree_tests.py --label f3_portal_full
  tests.test_directory_reconciliation
  tests.test_directory_reconciliation_concurrency
  tests.test_directory_reconciliation_views
  tests.test_directory_reconciliation_redteam
  tests.test_identity_journey_contract
  tests.test_directory_views
  tests.test_identity360
```

**105tests PostgreSQL réussis en41,991secondes**, aucune erreur, aucun échec et aucun test ignoré, après l'affichage et les métadonnées de limites par phase. Le journal privé final de la suite est `output/p1-f-f3_portal_bounds.log`. Le précédent passage105/105en41,205s reste conservé séparément dans `output/p1-f-f3_portal_full.log`, sans addition des nombres comme tests uniques. La base de test éphémère est distincte de celles des autres campagnes et a été détruite par Django à la fin ; aucun volume ni service existant n'a été supprimé ou redémarré. Les essais de concurrence utilisent les verrous PostgreSQL réels. Le parcours P1-G SCIM utilise le vrai serveur HTTPS de boucle locale des fixtures existantes, exclusivement synthétique.

Après renforcement des assertions de comparaison du payload complet F1/F3, du run, de la source et de la continuation :rejeu ciblé11/11tests de vues en5,218s, aucun test ignoré, journal `output/p1-f-f3_portal_final_views.log`. Ces11cas font partie des105, ils ne sont pas additionnés comme nouveaux tests uniques.

Les premiers essais ont détecté un mauvais encodage Windows dans les deux liens ajoutés par script, puis une attente de test incorrecte sur la limite facts/absent. Ces erreurs d'intégration/fixture ont été corrigées sans modifier les gardes, le lecteur métier ou les assertions Red Team. Les journaux initiaux sont conservés séparément et ne sont pas présentés comme validations.

Ruff et diff-check passent sur le périmètre. Le warning WhiteNoise indique que les assets statiques ne sont pas collectés dans ce nouveau checkout : le rendu serveur HTML est testé, pas une qualification visuelle des styles ou du JavaScript. Aucun build Docker n'a été lancé en parallèle de B3.

## Fichiers du lot dans ce worktree

Cinq fichiers suivis modifiés :`config/urls.py`, `platform_modules/connectors/directory_views.py`, `platform_modules/identity/identity360_views.py`, `templates/connectors/directory_detail.html`, `templates/identity/identity360.html`.

Treize fichiers nouveaux conservés pour livraison :les trois `platform_modules/connectors/directory_reconciliation*.py`, `templates/connectors/directory_account_review.html`, les quatre `tests/test_directory_reconciliation*.py`, `tests/test_identity_journey_contract.py`, `docs/p1-f-reconciliation-contract.md`, `docs/p1-f-reconciliation-redteam.md`, `docs/p1-g-journey-plan.md` et ce rapport. Les fichiers du noyau métier ne sont pas réécrits ; le lecteur F3 reçoit uniquement les métadonnées de bornes additives en plus du code précédemment relu. Les modèles, migrations, politiques et transports ne changent pas.

## Limites et portes suivantes

- Aucune nouvelle migration : une campagne de migration/restauration supplémentaire n'a pas été exécutée pour ces seuls liens/routes. Les vérifications de restauration et P0 historiques ne sont pas comptées comme nouveaux tests de ce lot.
- La suite complète P0 et tous les modules ne sont pas rejoués par les105tests sélectionnés. Une CI et la qualification de l'image finale restent nécessaires avant publication.
- L'attestation PAM, les cérémonies WebAuthn, le transport distant, l'isolation P2 et les annuaires commerciaux ne sont pas qualifiés par ce portail.
- La revue indépendante de l'intégration canonique et du diff final est favorable :45/45tests PostgreSQL en25,822s, aucun ignoré, base dédiée détruite après l'essai. Elle couvre29cas Red Team,11vues et5courses, inclus dans les105cas et non additionnés. La comparaison AST des29méthodes a été répétée indépendamment. Les permissions/routes réelles, liens conditionnés aux modules, provenance distincte, exports actualisés et limites ont été relus ; il s'agit d'une revue par agent indépendant, pas d'une revue humaine authentifiée.
- Le prochain lot P1-G reste une préparation : actions guidées au-dessus des services existants, politiques versionnées, scénario headless sur stack synthétique et parcours PAM distinct. Aucun compte ou secret réel n'est autorisé par ce document.
