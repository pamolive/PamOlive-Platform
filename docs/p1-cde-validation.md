# P1-C / P1-D / P1-E — livraison locale et publication en revue

11 novembre 2026. Références : AGENTS.md, roadmap Architecture 2026–2029, ADR-013 à ADR-016, rapports P0 et P1-A/B1. L'inventaire des onze produits n'a pas été recommencé. Les changements sont ciblés sur les parcours existants, sans nouveau bus, service IAM concurrent ou réécriture du PAM.

## Résultat fonctionnel

**Identity** : inventaire et fiche 360° HTML/API/export, contrats versionnés, personnes et identités non humaines, comptes, responsabilités déclarées, droits locaux/ressources, rôles de mobilité vérifiés, références de groupes/sources, historique et JML. Le signalement d'orphelins décrit précisément les comptes actifs sans responsabilité active selon les champs disponibles ; il ne prétend pas inventorier un annuaire distant. Les prévisualisations AD/LDAP/Entra acceptent seulement des fixtures avec UUID stables et correspondances explicites : aucune connexion ni écriture, aucun rapprochement par e-mail faisant autorité.

**Governance** : catalogue dérivé des rôles métier signés, cockpit demandes/votes/SoD/revues/campagnes, retrait local distinct de sa confirmation fournisseur et de son état distant actuel. Le registre d'exceptions est un suivi signé, borné et immuable ; il n'accorde aucun droit et n'est pas consommé comme dérogation. Sa revue par un autre compte n'est pas présentée comme une garantie de personnes indépendantes. Les formulaires et politiques IAM/IGA existants restent les chemins d'action.

**Observe** : entrée par observation, y compris sans intention liée, chronologie et contrat transverse lorsque le lien est vérifié, évaluation V7 et provenance V8 séparées, trois verdicts et export de lecture avec lien vers la preuve vérifiable. Une dernière preuve absente/invalide donne indéterminé, sans ancienne conformité de secours. Comparer PC-991 à INC-47294 ne prouve pas l'absence d'une autre autorisation.

**Démonstrateur** : deux organisations, modules différents et mêmes identifiants distants ; demande/approbation/provisioning en attente/exécution simulée/observations PC-483 conforme, PC-991 en écart et identité non résolue indéterminée. Manuel et collecteur de même identifiant coexistent. Expiration, retrait demandé, panne simulée/retry puis confirmation de retrait utilisent les services existants et un transport mémoire sans réseau. La commande exige une base synthétique neuve et ne supprime aucune donnée. Les comptes créés ont des mots de passe inutilisables ; pour une démonstration humaine ultérieure, préparer explicitement un compte et une MFA synthétiques sur cette seule instance, jamais réutiliser un compte existant réel.

Les projections bornées indiquent les sections désactivées et la troncature, rechargent acteur/organisation sous verrou, puis vérifient rôles et dépendances. Elles ne deviennent ni une autorité PAM ni un reçu signé nouveau. Voir [Identity](p1-c-identity360.md), [Governance](p1-d-governance.md), [Observe](p1-e-observe.md).

## Corrections issues de la confrontation

Les revues indépendantes ont reproduit une autorité administrative périmée dans des parcours préexistants : rôles métier, publication de politiques et planifications, activation de planning et campagnes manuelles. Les gardes réutilisent désormais l'acteur rechargé sous verrou et conservent MFA, rôles et modules. L'activation/désactivation des modules du noyau suit le même principe, en conservant le bootstrap explicite et la restriction fédérée. Les tâches planifiées sans acteur gardent leur propre vérification de publication ; aucun faux acteur interactif n'est créé.

La simulation refuse une taille HTTP malformée avec 400 et une taille valide excessive avec 413. Le préflight N0 refuse namespaces hôte, périphériques et capacités ajoutées. Le nom de base de test est compatible avec le garde du démonstrateur, sans élargir ce garde. Les rapports indépendants [Red Team](p1-cde-redteam.md) et [crypto/PAM](p1-cde-crypto-review.md) décrivent preuves, corrections et limites ; absence de constat supplémentaire n'est pas preuve d'absence de faille.

## Modèle, migration et récupération

Seule migration de schéma P1 : `governance.0003_exception_register`. Deux tables vides, `ExceptionCase` et `ExceptionDecision`, contraintes de durée/décision/unicité, clés composites de tenant, triggers d'immutabilité et refus d'auto-revue. Aucun ancien fait n'est réécrit. Identity et Observe n'ajoutent aucun schéma.

Le plan contrôlé ajoute explicitement cette migration : vingt-deux migrations depuis la fixture historique, trente-sept nouveaux modèles dans cette comparaison. Les tests vérifient schéma, colonnes/lignes historiques et journal des migrations. Le retour arrière d'un registre vide est possible ; une preuve présente bloque le downgrade destructeur. Les limites P0-4 restent indépendantes.

La restauration vérifie aussi les attestations d'exception, ancres, acteurs/MFA historiques, tenants, période/chronologie et absence de preuve orpheline, sans réactiver d'autorité. Conserver exactement `PAMOLIVE_ENCRYPTION_KEY` : les attestations du noyau utilisent cette clé, distincte de `SECRET_KEY` et du trousseau V7/V8. Aucune rotation/réécriture cryptographique n'est introduite. Voir [ADR-016](adr-016-governance-exception-evidence.md), [mise à niveau](controlled-upgrade.md), [restauration](backup-restore.md).

## Tests et contrôles

| Campagne | Résultat observé |
| --- | --- |
| Identity, simulateurs, autorités Mover et régression Mover | 48/48 PostgreSQL, 45,058 s, aucun ignoré |
| Governance, restauration, autorités et recertification existante | 81/81 PostgreSQL, 129,042 s, aucun ignoré |
| Observe et démonstrateur | 15/15 PostgreSQL, 6,801 s, aucun ignoré |
| Plateforme, activation et isolation modules | 36/36 PostgreSQL, 59,555 s, aucun ignoré |
| Migration/rollback réel avec rôle PostgreSQL restreint | 12/12, 194,043 s ; préparation et contrôle de rôle aussi réussis |
| Revue Red Team élargie | 121/121 PostgreSQL, 115,865 s, aucun ignoré |
| Dernière requalification indépendante des corrections | 69/69 PostgreSQL, 39,721 s, aucun ignoré |
| Revue crypto/PAM, V7/V8, rotation, restauration et Observe | 30/30 PostgreSQL, 5,602 s, aucun ignoré |
| Parseur Compose réel sans Engine | 5/5, sans connexion NAS ni conteneur lancé |
| Campagne locale complète, régressions P0 incluses | 903 tests : 863 réussis, 40 ignorés ; 1046,723 s |
| Correction de fixture HA P0-3, après campagne complète | 19/19 PostgreSQL, 2,456 s ; relecture indépendante 19/19 en 2,435 s |

Les 40 exclusions locales sont explicites : 19 tests de l'image avec extension signée, un test du signal périodique V3 signé installé séparément, 10 tests de relais SSH natif, 9 tests RDP de l'image dédiée et un test SQLite de suppression de reçu V8 que PostgreSQL interdit par trigger. Les gates Linux séparées ont passé sur 802d560 ; elles devront repasser sur le candidat final. Aucune de ces exclusions n'est comptée comme un test réussi.

Les campagnes se recouvrent : ne pas additionner leurs nombres pour annoncer une couverture unique. Le rôle restreint est réellement NOSUPERUSER/NOCREATEDB/NOCREATEROLE/NOINHERIT/NOREPLICATION/NOBYPASSRLS et propriétaire de sa seule base synthétique ; le garde d'exploitation a été appelé sans mock. Base et rôle ont été retirés après qualification. Un premier passage avait uniquement conservé une attente de compteur de modèles avant l'ajout des deux tables ; elle a été réconciliée, puis les douze tests ont été réexécutés avec succès. Les échecs adverses initiaux des gardes périmés sont documentés séparément, sans suppression de leurs assertions.

Les contrôles Ruff, Django, cohérence des migrations, dépendances et diff sont exécutés localement. Le scan applicatif Bandit ne rapporte aucun moyen/haut dans ce périmètre ; le scan deploy garde ses constats pour revue. Six nouvelles détections de fixtures négatives/MFA ont été relues indépendamment : baseline de 88 empreintes, sans élargissement de détecteur ou d'exclusion. Les outils ne vérifient aucun credential contre un réseau réel. Les nouveaux changements n'ajoutent aucune dépendance runtime.

## GitHub et état de qualification

Branche dédiée : [agent/p1-a-b1-review](https://github.com/pamolive/PamOlive-Platform/tree/agent/p1-a-b1-review). [PR de revue nº 1](https://github.com/pamolive/PamOlive-Platform/pull/1), en brouillon, sans merge. Les quatre commits locaux préexistants et le consolidé P0/P1-A/B1 sont déclarés dans la PR. Les deux fichiers de diagnostic indépendants restent locaux et préservés.

Le SHA `802d560` a passé le job sécurité, 804 tests PostgreSQL en 645,402 s (40 ignorés, testés par gates distinctes ou non applicables), OIDC/extensions, image et transports natifs SSH/RDP/WebSocket/captures puis séparation du runtime. Le scénario HA échoue sur une fixture qui ne commissionnait pas le registre PAM P0-3 ; le refus est légitime et ne doit pas être neutralisé. Cette exécution ne qualifie pas P1-C/D/E, qui seront associés au SHA publié exact. Le résultat GitHub final doit être consigné sans appeler verte une CI partielle.

Le commit fonctionnel local `c66a1cf` contient les 67 fichiers P1-C/D/E et N0 listés ci-dessous. Un changement indépendant corrige ensuite la qualification HA : autorités et authentificateurs logiciels privés sur l'hôte, enveloppes/assertions par pipes privés, checkpoints publics frais en montage readonly exact dans les deux nœuds, véritables vérificateurs P0-3 conservés. La simulation ne prouve pas l'indépendance de personnes physiques, un navigateur réel ou TLS. Les compteurs du gate d'upgrade sont réconciliés avec les 22 migrations et 37 nouveaux modèles réellement vérifiés. Voir [qualification HA](ha-p0-trust-qualification.md) ; aucun fichier du contrôle PAM produit n'est modifié par cette adaptation.

## Synology : N0 seulement

La [préparation dédiée](synology-p1-preparation.md) contient Compose, exemples sans secrets, SQL d'initialisation d'une base neuve et préflight. Elle réutilise Web/API + worker comme processus du runtime existant et propose PostgreSQL/réseau/volume dédiés, port loopback, limites obligatoires, logs bornés et secrets privés. Elle n'est pas appliquée au projet NAS existant.

Docker Engine local est indisponible : les tests effectifs sont ceux du parseur Compose, pas un démarrage de cette topologie ni une qualification de son secret UID 999. Superviseur root limité, ACL réelles, digests, ressources/IO/stockage/durée et seuils restent des portes avant N2. La demande courante interdit tout nouveau contact NAS avant confirmation de périmètre/accès et toute écriture avant plan approuvé. Aucun nouveau contact, copie, migration, arrêt ou déploiement NAS dans ce lot. Aucune donnée de production n'est modifiée.

## Risques et prochain lot

Restent : contention du verrou d'organisation, vérifications par ligne sur des listes bornées, limites de charge/rétention et quota dédié d'écriture des exceptions, dépendance aux clés applicatives et au propriétaire PostgreSQL. Les propriétaires sont déclaratifs, les groupes référencés ne sont pas un inventaire d'appartenance distant ; les adaptateurs AD/LDAP/Entra ne parlent pas leurs protocoles réels. Le commissionnement PAM indépendant et un témoin courant restent obligatoires avant usages réels. Aucun HSM/coffre/broker nouvellement isolé, garantie post-quantique ou accessibilité navigateur complète n'est revendiqué.

Prochain lot proposé **P1-F** : qualifier Connect/Audit sur serveurs synthétiques locaux, contrats de rapprochement read-only persistants avec provenance/revue des collisions, pagination et budgets des files, API/export de preuves vérifiables et reprise/retrait SCIM/TeamViewer. Réutiliser les outbox et gardes P0-2/P0-4 ; ajouter tests de rotation/révocation, concurrence/déduplication, deux tenants et restauration. Aucun connecteur réel obligatoire.

Puis **P1-G** : parcours natif Identity → demande → approbation → exécution → Observe, démonstration navigable avec comptes synthétiques explicitement provisionnés, tests navigateur par rôle, clavier/accessibilité et état des modules, documentation d'installation/opération et image par digest qualifiée. Les modifications NAS restent un chantier approuvé séparément, jamais une conséquence du merge ou d'une CI verte.

## Fichiers

Fichiers du lot C/D/E et preparation N0 (par rapport a 802d560 ; les adaptations de qualification HA/upgrade sont consignees separement) :

```text
.dockerignore
.github/workflows/ci.yml
.gitignore
.secrets.baseline
config/urls.py
deploy/controlled_upgrade.py
deploy/prepare_upgrade_fixture.py
deploy/restore_application_check.py
deploy/synology-test/application.example
deploy/synology-test/compose.yml
deploy/synology-test/config.example
deploy/synology-test/init-test-db.sql
deploy/synology_preflight.py
docs/adr-016-governance-exception-evidence.md
docs/architecture-decisions.md
docs/backup-restore.md
docs/ci-readiness.md
docs/controlled-upgrade.md
docs/implementation-status.md
docs/p1-c-identity360.md
docs/p1-cde-crypto-review.md
docs/p1-cde-redteam.md
docs/p1-cde-validation.md
docs/p1-d-governance.md
docs/p1-e-observe.md
docs/synology-p1-preparation.md
platform_core/management/commands/pamolive_observe_demo.py
platform_core/services.py
platform_modules/access/observe.py
platform_modules/access/observe_demo.py
platform_modules/access/observe_views.py
platform_modules/governance/exception_models.py
platform_modules/governance/exceptions.py
platform_modules/governance/migrations/0003_exception_register.py
platform_modules/governance/models.py
platform_modules/governance/services.py
platform_modules/governance/workspace.py
platform_modules/governance/workspace_views.py
platform_modules/identity/directory_simulation.py
platform_modules/identity/directory_simulation_views.py
platform_modules/identity/identity360.py
platform_modules/identity/identity360_views.py
platform_modules/identity/mover.py
platform_modules/recertification/campaigns.py
platform_modules/recertification/schedules.py
templates/governance/exception_form.html
templates/governance/list.html
templates/governance/policies.html
templates/governance/workspace.html
templates/identity/directory_simulation.html
templates/identity/home.html
templates/identity/identity360.html
templates/identity/identity360_inventory.html
templates/intelligence/index.html
templates/observe/detail.html
templates/observe/index.html
tests/test_controlled_upgrade.py
tests/test_governance_exception_restore.py
tests/test_governance_workspace.py
tests/test_governance_workspace_concurrency.py
tests/test_identity360.py
tests/test_identity360_concurrency.py
tests/test_module_activation_authority.py
tests/test_mover_authority.py
tests/test_observe_concurrency.py
tests/test_observe_story.py
tests/test_synology_preparation.py
```

Diagnostics preserves hors publication : `.github/workflows/diagnose-partition.yml` et `deploy/Dockerfile.partition-probe`.

Fichiers de qualification et documentation complémentaires : `deploy/active_active_fixture.py`, `deploy/active_active_rdp.py`, `deploy/active_active_ssh.py`, `deploy/active_active_trust.py`, `deploy/check_active_active.py`, `deploy/check_upgrade_ci.py`, `tests/test_active_active.py`, `tests/test_active_active_trust.py`, `docs/active-active.md`, `docs/ha-p0-trust-qualification.md`, `README.md`, `docs/api.md` et mise à jour de ce rapport. La baseline ne reçoit que des métadonnées de ligne pour les empreintes déjà approuvées, sauf nouvelle revue explicite.
