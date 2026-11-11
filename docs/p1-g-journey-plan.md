# P1-G — Qualification préparatoire du parcours Identity Security

Statut : tests locaux des services existants, sans nouveau code produit. Cette préparation ne publie pas P1-G, ne remplace pas les validations F1/F3 et ne redéveloppe pas le démonstrateur PC-483 / PC-991.

Complément du12novembre2026 : ces tests sont conservés dans le worktree F3 séparé, basé sur95fe14f, et exercent `config.urls` réel. Le portail F3 y ajoute les liens Identity360→index des sources→fiche F1→revue des comptes, avec dépendances de module appliquées. Cela ne crée pas une association de personnes historiques. La base native95fe14f n’est pas une image promue ; aucun résultat de ce lot ne qualifie son packaging pour la production.

## Contrat vérifié

Le parcours réutilise `build_identity360`, `create_record`, `decide`, `process_changes`, `ingest_event`, `build_access_contract` et `revoke_grant`. Il conserve les autorités distinctes :

1. Identity 360 lit une identité et ses comptes locaux ; leur existence n'atteste pas une personne indépendante.
2. Une intention `iam_group` décrit le droit demandé et sa fenêtre. Elle ne provisionne rien.
3. Une décision du service d'approbation applique la politique courante. Le test ne fabrique pas de ligne approuvée ni de droit par mise à jour SQL.
4. La décision crée le droit local et l'opération SCIM ; avant exécution, aucun effet fournisseur n'est affiché.
5. Un vrai serveur HTTPS sur boucle locale reçoit le PATCH SCIM ; la relecture GET confirme l'appartenance. La preuve reste une confirmation enregistrée à cet instant, sans état actuel garanti ni signature indépendante de l'annuaire.
6. Un principal collecteur distinct fournit une observation. Le reçu V8 et l'évaluation historique sont vérifiés. Le rapprochement n'affirme ni causalité ni véracité indépendante des faits source.
7. Le retrait exige une autorisation récente, conserve le binding d'origine et n'est confirmé qu'après sa relecture distante. Le compte partagé reste actif ; aucun arrêt global n'est demandé.

Le test HTTPS réutilise le cycle TLS des fixtures SCIM existantes et leur serveur HTTP synthétique. La CA temporaire est injectée dans la politique du test ; aucune désactivation de vérification TLS n'est utilisée. Les destinations autorisées sont uniquement `127.0.0.1`, sur port éphémère. Aucun NAS, collecteur réel, annuaire ou navigateur utilisateur n'est contacté.

## Cas automatisés préparés

Fichier : `tests/test_identity_journey_contract.py`.

- Parcours HTTPS complet : intention, décision réelle, état local, ajout confirmé, observation collecteur V8, évaluation vérifiée, retrait confirmé et chaîne d'audit.
- Deux organisations : refus de lecture et de décision sur UUID étranger, refus d'ingestion avec un principal de l'autre organisation.
- Connect désactivé après approbation : aucun PATCH, confirmations masquées ; réactivation seule insuffisante ; reprise par service explicite avec MFA.
- Opérateur incapable de configurer le connecteur ou d'approuver ; promotion à reviewer insuffisante pour approuver sa propre demande.
- TOTP synthétique vérifié par `verify_mfa`, puis contexte d'assurance récent pour configuration ; absence et expiration de l'assurance refusées. Les autres contextes d'assurance sont ceux des fixtures de tests existantes, pas une cérémonie de connexion de production.
- Télémétrie sans privilège attendu : reçu et évaluation vérifiables, mais verdict inconnu et aucune intention inventée.
- Adhésion reviewer supprimée après demande : décision refusée, aucune décision et aucun effet fournisseur.
- Rendu HTTP Django : lien Identity 360 vers le parcours existant et export, sans navigateur graphique.

Le test importe les modules de fixtures, pas leur classe TestCase comme symbole public ; cela évite d'exécuter implicitement toute la suite de provisioning comme s'il s'agissait de nouveaux tests P1-G.

## Observations issues des essais préparatoires

Les premières attentes de fixture ont échoué sur des protections existantes : un événement sans `privilege=reader` n'est pas rattaché à l'intention qui l'exige ; un retrait sans assurance MFA récente est refusé atomiquement ; un module désactivé bloque l'opération au lieu de la reprendre automatiquement à sa réactivation. Ces comportements ont été conservés et les tests ont été adaptés au contrat réel. Aucun correctif produit n'a été appliqué pour rendre le parcours artificiellement passant.

La politique de référence IAM est `baseline/1` en l'absence de politique organisationnelle. `approval_requirements` compte alors des comptes de connexion pour IAM ordinaire. Les personnes attestées, clés personnelles et preuves WebAuthn du registre P0-3 concernent PAM ; elles ne doivent pas être prétendues présentes dans une simple approbation IAM. Ce lot ne qualifie pas une séparation de personnes indépendantes pour toutes les décisions IGA.

## Frictions d'interface à traiter dans un futur lot produit

Analyse des templates actuels `identity/identity360.html` et `governance/access_contract.html`, complétée par le rendu HTTP Django :

- Identity 360 expose déjà les liens vers les demandes existantes, le parcours, la gestion de l'identité et Mover. Le template n'offre pas une entrée « demander un accès » préremplie avec identité/compte/ressource ; l'utilisateur doit passer par le workflow de création existant.
- Le parcours dispose de liens vers la demande et son export, ainsi que vers les observations. Les références de décision, de preuve SCIM, de binding et de reçu sont principalement affichées en texte. Avant d'ajouter des liens, chaque cible doit être tenant-scopée et protégée par son module ; ne jamais transformer un UUID en autorité.
- Le parcours de lecture n'est pas un assistant de publication de politique, d'approbation, de reprise SCIM ou de retrait. Les actions doivent rester dans leurs services d'autorisation ; une future expérience unifiée peut les orienter sans transférer leur autorité au lecteur.
- Les listes sont bornées et exposent la troncature ; une page et son export ne constituent pas une preuve hors ligne exhaustive. Il faut conserver les liens vers les vérificateurs d'origine et expliciter les preuves indisponibles.
- Les projections F3 peuvent rapprocher un compte explicitement mappé et des historiques SCIM/TeamViewer. Elles n'établissent pas automatiquement une identité de destination entre annuaire importé et fournisseur SCIM, ni l'authentification d'un compte OS ou d'une personne.

Ces points sont des observations de code et de rendu serveur ; aucune ergonomie interactive au navigateur n'a été qualifiée ici.

## Étape PAM distincte à qualifier

Une continuation PAM doit réutiliser ADR-013 et les cérémonies réelles du registre, notamment `pam/trust.py` et les tests `test_pam_trust_auth`, `test_pam_trust_registry`, `test_pam_trust_concurrency`. Elle doit vérifier l'enrôlement, la seconde assertion, la publication indépendante, les défis liés à la session, l'expiration, les compteurs et la révocation, puis les preuves request/vote/launch et le bail lié à la cible cryptographique exacte.

Les fixtures `TrustFixture` / `VirtualAuthenticator` peuvent construire des tests cryptographiques synthétiques, sans conférer une attestation humaine réelle. Un `approved=True` injecté en base, un booléen MFA ou un rôle PostgreSQL supplémentaire ne remplace aucune de ces cérémonies. Le bail local ne prouve pas une connexion SSH/RDP ; une qualification de transport nécessite les fixtures de serveurs locaux et ses propres preuves de connexion et capture.

## Portes de livraison proposées

1. Conserver le présent contrat en CI PostgreSQL ; revue indépendante des assertions et vérification de l'absence de réseau hors boucle locale.
2. Après qualification F, introduire uniquement les liens/actions manquants dans les interfaces existantes, avec autorisation revalidée au service, CSRF et dépendances de modules. Ne pas créer un second journal d'autorité.
3. Ajouter des scénarios headless sur une pile Docker synthétique séparée : demande, décision par autre principal, worker, observation, retrait et preuves. Aucun contrôle du navigateur du PC utilisateur.
4. Étendre aux politiques versionnées, substitutions d'acteurs, révocations concurrentes et pagination/troncature. Exécuter les régressions P0, les gates de migration/restauration et la revue contradictoire avant publication.
5. Qualifier séparément le chemin PAM par cérémonies synthétiques réelles et transport SSH/RDP local, puis les frontières P2 ; ne pas revendiquer l'isolation Web/Worker→Broker→Vault sur la seule base d'un parcours d'interface.

Aucune migration, route, modification produit, publication ou connexion NAS n'appartient à cette préparation.

## Résultats locaux du 11 novembre 2026

Commande : `.venv\Scripts\python.exe C:\Users\Cy24\Documents\PAM\output\run_p1f_tests.py --label journey_validated tests.test_identity_journey_contract`.

Résultat : **8 tests PostgreSQL réussis en 3,856 s**, aucune erreur et aucun test ignoré. Le journal privé est `C:\Users\Cy24\Documents\PAM\output\p1-f-journey_validated.log`. La base éphémère a été créée puis détruite par Django ; aucun nettoyage de volume n'a été exécuté. Ruff et vérification du format passent sur le nouveau fichier.

Une dernière correction de fixture a aussi conservé une protection existante : `retry_change` est réservé à l'administrateur avec MFA récente. Le test affirme maintenant le refus de l'opérateur, puis la reprise explicite par l'administrateur. Les premiers journaux d'essai sont conservés hors dépôt ; ils ne constituent pas des vulnérabilités reproduites.

Non exécutés dans ce sous-lot : suite P0 complète, nouveaux tests de concurrence P1-G, nouvelles migrations/restaurations (aucune modification de schéma), navigateur headless, politique organisationnelle publiée personnalisée et parcours PAM/SSH/RDP. Les preuves antérieures de ces composants ne sont pas comptabilisées comme nouveaux résultats P1-G. Une revue indépendante de ces nouveaux tests reste à organiser avant leur livraison.
