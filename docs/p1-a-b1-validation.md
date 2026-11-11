# P1-A / P1-B1 — Consolidation et contrat transverse

11 novembre 2026. Lot autorisé localement par le responsable du projet. Références : AGENTS.md, dossier Architecture & Roadmap 2026–2029 (43 pages), ADR-013/014, rapports P0 et inventaire des onze produits. Ce lot ne réalise pas le démonstrateur PC-483/PC-991 et ne crée pas de Vault, de nouveau bus ou de microservice.

## Résultat fonctionnel

Le contrat `pamolive.access-contract/1` est implémenté dans `platform_core/access_contract.py`. L'écran, l'API de session et l'export partagent ce lecteur : intention, décision, droit demandé, droit local, effet fournisseur enregistré, exécution confirmée, observation et preuves restent distincts. Les résultats bornés exposent disponibilité/troncature ; les origines d'exécution sont les références du changement enregistré, sans re-routage vers le connecteur courant. Une origine absente reste inconnue. Le contrat n'est pas une nouvelle preuve signée ni une autorisation. Voir [ADR-015](adr-015-access-read-contract.md) et [API](api.md).

La correspondance des onze produits avec les huit applications et services du noyau est versionnée dans `platform_core/product_modules.py`. Cette table ne remplace pas le registre technique et n'active aucune capacité planifiée.

Les contrôles de permissions sont relus après verrou d'organisation, avec compte et organisation actifs rechargés. Les actions d'attribution IAM, de vote et de revue utilisent ce même principe ; les tests couvrent la révocation d'appartenance ou la désactivation pendant l'attente. Les consommateurs asynchrones restent en attente quand leurs dépendances sont désactivées. Les nouvelles publications d'un émetteur technique enregistré requièrent sa capacité. Les détails opérationnels Connect/PAM sont masqués lorsqu'ils sont indisponibles. Les contraintes de sécurité publiées, expirations et révocations obligatoires continuent ; les preuves historiques restent sous les permissions de leur domaine Access/Audit.

## Préservation et consolidation

Le relevé [p1-preexisting-state.json](p1-preexisting-state.json) conserve HEAD, statut et empreintes des **65 fichiers suivis modifiés et 46 fichiers non suivis** présents à l'entrée. Aucun de ces 111 fichiers n'a été supprimé. Les fichiers inchangés sont contrôlés par SHA-256 ; les intégrations intentionnelles dans les fichiers déjà modifiés sont listées ci-dessous. Aucun reset, nettoyage de données ou remplacement de checkout n'a été effectué.

Les récits ADR-013/014 et le rapport P0-3 indiquent désormais correctement leur périmètre historique et la réalisation P0-4. Sept noms de méthodes de tests quorum ont été renommés pour exprimer les refus déjà vérifiés ; leurs assertions sont conservées. `implementation-status.md` distingue les qualifications historiques des portes encore requises pour ce checkout. Il n'existait pas de rapport autonome P0-1/P0-2 à requalifier : leurs tests et leurs preuves sont référencés par les rapports P0-3/P0-4 et les guides provisioning/PAM.

P1 ne crée **aucune migration**. Les migrations P0 restent présentes ; les tests de migration/restauration/retour arrière synthétiques sont inclus dans la campagne. Le garde de retour arrière P0-4 continue de refuser un retour destructeur après création d'événements, reçus, conflits ou quotas nouveaux.

## Vérifications

| Campagne | Résultat observé |
| --- | --- |
| Contrat/UI/API/export SQLite après origine enregistrée et tests des rôles | 18/18 réussis |
| Courses PostgreSQL indépendantes Red Team | 18/18 réussis, sans exclusion |
| Campagne intégrée PostgreSQL avant mise à jour des dépendances | 438 exécutés, 437 réussis, 1 ignoré ; 674,052 s |
| Campagne après Django/cryptography corrigés | 440 exécutés, 439 réussis, 1 ignoré ; 658,390 s |
| Dernière qualification PostgreSQL du contrat et du filtre de rapports | 39/39 réussis ; 15,827 s |

Le seul test ignoré est `test_restore_rejects_a_missing_v8_receipt_and_keeps_v7_verifiable`, réservé à SQLite ; PostgreSQL vérifie séparément le refus de suppression par trigger. Les transports natifs Linux et la CI hébergée n’ont pas été exécutés localement.

Les suites intégrées comprennent les quatre nouvelles suites P1 (`test_access_contract`, `test_access_contract_views`, `test_access_contract_concurrency`, `test_p1_module_isolation`), les régressions P0-1 à P0-4, SCIM/provisioning, quorum/WebAuthn/registre/PAM, preuves/certificats/TeamViewer, migrations contrôlées et restauration, notifications/dépendances, plateforme, gouvernance et recertification. Les tests utilisent un PostgreSQL 17.11 nouvellement initialisé sur loopback et des bases `test_pamolive_*` jetables ; aucune connexion d'application vers le NAS, un annuaire ou un collecteur réel n'est utilisée.

Commande des nouveaux contrôles :

```powershell
# DATABASE_URL doit désigner le cluster synthétique loopback, jamais une base en service.
.venv\Scripts\python.exe manage.py test tests.test_access_contract tests.test_access_contract_views tests.test_access_contract_concurrency tests.test_p1_module_isolation --noinput
.venv\Scripts\python.exe manage.py check
.venv\Scripts\python.exe manage.py makemigrations --check --dry-run --noinput
.venv\Scripts\python.exe -m pip check
.venv\Scripts\ruff.exe check .
```

## Dépendances et contrôles de publication

L'analyse initiale a identifié trois avis distincts dans Django 5.2.16 et cryptography 49.0.0 (le rapport brut répétait des alias). Les usages GeoDjango et déchiffrement PKCS7 concernés n'ont pas été trouvés dans le code inspecté ; cette absence ne corrige pas les versions affectées. Les versions sont mises à jour de manière ciblée vers **Django 5.2.19 et cryptography 50.0.2**, avec bornes correspondantes dans pyproject et conservation des autres dépendances P0/WebAuthn. Les exigences de pyOpenSSL, AsyncSSH et WebAuthn sont compatibles. Aucun changement d'algorithme, ré-enchiffrement ni réécriture des anciennes preuves n'est effectué.

Le nouvel audit des 26 dépendances runtime verrouillées ne rapporte aucun avis connu à sa date d'exécution ; un SBOM CycloneDX a été produit hors dépôt. Ce résultat n'est pas une garantie d'absence de vulnérabilité inconnue. Les références et outils épinglés figurent dans [la préparation CI](ci-readiness.md).

Bandit : aucun HIGH, 15 MEDIUM dans les outils de déploiement ont été relus indépendamment (identifiants SQL validés, métadonnées citées, option tmpfs de Docker, URL loopback fixe et écoute ASGI voulue). Aucun chemin nouveau d'injection n'a été confirmé ; les règles ne sont pas désactivées globalement. Aucun MEDIUM/HIGH n'est signalé dans le périmètre applicatif scanné. Les rapports complets restent des éléments de revue.

Detect-secrets : **82 signalements sur 45 chemins** relus, tous classés en fixtures synthétiques, placeholders ou empreintes publiques. Aucun candidat restant à un secret réel dans ce rapport. `.secrets.baseline` ne contient que les empreintes exactes et les chemins normalisés de ces exceptions ; un nouveau hash doit échouer avant revue. Les répertoires d'environnement et caches ainsi que le manifeste d'empreintes sont exclus comme artefacts, sans suppression générale d'un détecteur. Les clés NAS et les rapports locaux ne sont pas copiés dans le dépôt.

## Revue indépendante et limites

La revue Red Team a détecté les autorisations relues trop tôt avant verrou et l'ambiguïté d'origine des confirmations ; elles sont corrigées et couvertes. Les accès UI/API/export excluent secrets et payloads non filtrés. Les suites indépendantes de lecture et de concurrence sont vertes dans le périmètre examiné. La revue des 82 empreintes confirme uniquement des fixtures/exemples/références publiques ; le nouveau signalement est un test négatif synthétique. Le filtre des rapports Bandit exclut code, diagnostics libres et champs inconnus avant upload, avec trois tests indépendants réussis et refus d’upload en cas d’échec.

Restent : contention possible du verrou d'organisation sur les lectures transverses, limites de charge/rétention, garanties dépendant des clés applicatives et du propriétaire PostgreSQL, confirmation fournisseur comme fait enregistré non authentifié indépendamment. Le témoin P0-3, le commissionnement réel, le coffre/broker isolés et la qualification native Linux restent des portes d'exploitation séparées. Les transports natifs de l'image et la CI hébergée ne sont pas validés par une exécution Windows des tests métier.

## Fichiers du lot

- Noyau : `platform_core/access_contract.py`, `access_contract_views.py`, `product_modules.py`, `services.py`, `events.py`.
- Services/UI : `platform_modules/access/ui.py`, `platform_modules/identity/services.py`, `platform_modules/approvals/services.py`, `platform_modules/recertification/services.py`, `config/urls.py`, `templates/governance/access_contract.html`, `templates/governance/detail.html`.
- Tests : `tests/test_access_contract.py`, `test_access_contract_views.py`, `test_access_contract_concurrency.py`, `test_p1_module_isolation.py`, renommages dans `test_pam_quorum_reproduction.py`, `test_security_report_redaction.py`.
- Configuration/CI : `.github/workflows/ci.yml`, `requirements.lock`, `pyproject.toml`, `requirements-security.lock`, `.secrets.baseline`, filtre `deploy/redact_security_reports.py`.
- Documentation : ADR-013/014 réconciliés, `docs/p0-3-validation.md`, `implementation-status.md`, `api.md`, `adr-015-access-read-contract.md`, `ci-readiness.md`, `p1-preexisting-state.json` et ce rapport.

## Publication et NAS

Le responsable a ensuite demandé de retrouver les accès du projet et de préparer GitHub/NAS. L'historique a été consulté ; le dépôt distant et l'accès NAS ont été retrouvés. Une **lecture N1 séparée** a identifié le modèle/DSM, le RAID affiché, la capacité, la mémoire, les conteneurs en cours et les permissions du dossier existant. Le constat détaillé reste local hors dépôt. Aucun chmod, redémarrage, installation ou déploiement NAS n'a été effectué. Le dossier en service n'est pas un laboratoire jetable ; les gates N2/N3 exigent encore zone, budget, sauvegarde/restauration et fenêtre précis.

La publication ne doit pas mélanger silencieusement quatre commits locaux antérieurs au lot, le P0 non commité, P1 et les deux fichiers de diagnostic indépendants. Le candidat doit déclarer cette ascendance et son manifeste. `main`, publication de code, publication d'image et déploiement NAS sont quatre opérations distinctes. La CI est préparée pour tous les branches/PR et lancement manuel ; sa réussite hébergée reste une preuve à obtenir après autorisation de publication.

## Prochain lot proposé : P1-E1, démonstrateur transverse

1. Construire un scénario réinitialisable uniquement dans une base synthétique neuve : organisations A/B, identifiants externes identiques, PC-483 autorisé et PC-991 hors périmètre.
2. Réutiliser AccessIntent/ApprovalDecision/ExternalChange/ExecutionEvidence/AccessEvent et le contrat v1 ; ajouter une présentation temporelle demande/décision/exécution/observation, sans nouveau bus ni nouvelle autorité.
3. Montrer provisioning en cours puis confirmé, retrait demandé, fournisseur indisponible, reprise et confirmation de retrait ; conserver l'origine P0-2.
4. Montrer manuel/collecteur au même identifiant, verdicts conforme/écart/inconnu et preuves V7/V8 accessibles ; aucune simulation ne sera présentée comme connexion réelle.
5. Livrer tests navigateur par rôle, cas deux tenants et modules différents, tests négatifs et concurrence PostgreSQL, guide démonstration/opérateur et revue contradictoire. Ce lot ne démarre pas sans décision distincte.
