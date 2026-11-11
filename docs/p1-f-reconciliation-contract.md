# P1-F3 — contrat de revue annuaire et histoire des comptes

Statut : service en développement local, livraison distincte de F1/F2. Pas de nouveau modèle, migration, journal d’exécution ou opération distante. La qualification de ce lecteur ne constitue pas celle d’un annuaire réel. Référence de confrontation : [revue indépendante](p1-f-reconciliation-review.md).

## Entrée et permissions

`platform_modules.connectors.directory_reconciliation.directory_account_review(source_id, actor=..., organization=..., limit=100, cursor=None, history_limit=20)`.

Contrat `pamolive.directory-account-review/1`. Lecteur tenant-scoped, rôle admin/operator/reviewer/auditor rechargé sous verrou d’organisation, modules Identity et Connect actifs avec leurs dépendances. Absence de module, acteur désactivé ou appartenance retirée : refus avant lecture des domaines cachés. Aucune MFA interactive n’est fabriquée pour la lecture et aucun droit d’exécution n’est conféré.

Le service réutilise `directory_inventory` et son curseur opaque signé, organisation/source/run et phase facts/absent. `limit` et `history_limit` sont chacun compris entre1 et100. Une page peut contenir la fin des faits et le début des absences selon le contrat existant ; ce n’est pas une pagination de droits IAM. La limite s’applique à chaque phase : au plus `limit` faits et `limit` absences, soit `2*limit` lignes de revue. `page_limits` expose ces bornes explicitement dans le contrat F3 ; les pages F1/F3 les affichent. Le curseur et le payload de source restent ceux de F1, sans réinterprétation d’une absence comme suppression. Les comptes sélectionnés viennent uniquement de décisions explicites de correspondance actives de cette source, jamais d’un login, email ou UUID distant commun à deux systèmes.

## Sortie whitelistée

| Champ | Sens et limites |
| --- | --- |
| `source` | Identité de destination et état de la source, repris du lecteur d’inventaire vérifié |
| `run` | ID, heure d’acceptation serveur, audit, provenance, complétude et limites ; référence à une preuve vérifiée, sans signature publique ou nouveau reçu |
| `items[].observation` | Faits observés ou absence incertaine, y compris `enabled=null` ; jamais une suppression certaine |
| `items[].mapping` | Décision administrative signée vérifiée, date et audit ; pas une attestation indépendante de personne |
| `items[].local_account` | Compte et propriétaire IAM **actuels**, explicitement séparés de toute authentification historique |
| `items[].scim_*_ids` | Références aux opérations/résultats/créations de la section bornée, pas une nouvelle commande |
| `items[].review_reasons` | Motifs explicables : différences d’état, état inconnu, absence, histoire partielle, opération non confirmée, résultat tardif ou preuve invalide |
| `scim_history.operations` | Commandes et statuts locaux enregistrés, avec le binding et la destination conservés sur chaque opération |
| `scim_history.results` | Confirmation ou échec **historique enregistré** ; aucune signature distante autonome n’est inventée pour ExecutionEvidence |
| `scim_history.creations` | Preuves de création initiale SCIM vérifiées avec leur chaîne demande/dispatch ; compte confirmé initialement inactif, sans droit activé implicite |
| `teamviewer_history` | Références de sessions et résolutions datées lorsque la relation explicite de compte opérateur TeamViewer existe ; sinon disponibilité non établie |
| `next_cursor` | Continuation des faits/absences d’inventaire, pas un jeton d’autorisation |
| `page_limits` | Bornes de faits, d’absences, du total maximal et de l’histoire par section ; aucun nouveau droit |

`current_provider_state=not_asserted` et `same_destination_relation=not_established` restent explicites. Le service ne possède aucune association revue des realms LDAP/Graph/SCIM/TeamViewer. Même hôte ou même identifiant ne produit pas une équivalence de destinations ; des labels/DN de groupe identiques ne confirment aucun droit effectif.

## Histoire SCIM et preuves

L’origine utilise le binding enregistré sur `ExternalChange`, jamais un AccountBinding courant retrouvé à partir du compte. Les identifiants binding/connecteur et la révision enregistrée sont conservés. L’URL et les références distantes ne sont attribuées à cette origine que lorsque le sceau P0-2 de destination est vérifiable. Les connecteurs legacy précédemment révisés et laissés sans sceau par la migration0011 donnent `unverified_historical_destination` avec URL et références distantes inconnues : leur configuration actuelle ne reconstruit pas une route historique. Un renommage ordinaire d’un connecteur scellé ne change pas sa destination immuable ni la révision enregistrée sur l’opération. Les références incohérentes ou inter-organisations sont refusées ; une URL contenant des identifiants ou composants non exportables n’est pas affichée.

Pour une création SCIM, l’URL provient du scope signé de sa demande vérifiée, pas du champ URL actuel du connecteur. Cette trace de destination est distincte de l’état réseau actuel et d’une association de realm avec l’annuaire Directory.

Les résultats tardifs écartés restent tels, même si un booléen contradictoire apparaît dans des données de test. Une opération en retry/attente ne devient pas un droit provisionné. Un résultat signé de création porte uniquement sur la création initiale inactive. Une preuve invalide reste visible comme invalide sans exporter son payload, et ne produit ni confirmation ni origine supposée vérifiée.

Les résultats SCIM ne sont pas des observations actuelles de l’annuaire Directory. Un résultat enregistré avant l’acceptation d’un run est signalé comme antérieur à cette réception, sans supposer l’ordre réel des changements distants ou une causalité. Aucune note fournisseur, réponse `observed`, clé/token/ciphertext, capsule ou hash de justificatif n’est exporté.

## Relation TeamViewer typée

Un compte opérateur TeamViewer n’est pas le compte OS de la machine distante. Le lecteur ne cherche des références TeamViewer que pour les comptes explicitement liés dont le système typé est TeamViewer, puis via `TeamViewerMapping(kind=account)` vers ce même compte local. Il vérifie la preuve du mapping, borne les candidats et réutilise `resolve_session` ainsi que le vérificateur du lien normalisé/V8.

La relation exposée est `operator_account_reference`. `os_account` et `historical_person_authentication` restent `not_asserted`. Aucun propriétaire actuel de compte IAM n’est imputé rétroactivement comme acteur de session. Une correspondance ou une session ambiguë, partielle, en attente ou invalide reste dans cet état ; sa présence ne crée pas de ligne d’exécution confirmée.

`provenance_link` indique uniquement l’intégrité du lien signé de normalisation TeamViewer. Le helper P0-4 qualifie séparément `event_provenance` et `provenance_receipt_verified`, avec référence de reçu quand il est valide. Un ancien lien vérifiable peut accompagner `legacy_unknown` sans reçu V8 : son intégrité ne reclassifie jamais l’origine. Un lien invalide ne fournit aucune référence d’événement vérifiée.

Au plus10sessions sont résolues **globalement par page**, jamais dix pour chacun des cent comptes. Les statements de mapping et lignes d’histoire sont eux aussi bornés ; les variantes et correspondances internes du résolveur existant conservent leurs propres limites.

## Bornes, erreurs et absence d’effets

Opérations SCIM, résultats et preuves de création ont chacun un budget global `history_limit` sur la page ; les plus récents sont sélectionnés et la troncature reste visible. Ce budget n’est pas un export exhaustif de toute l’histoire d’un compte. Une section vide mais tronquée ne doit pas être affichée comme une preuve d’absence. Les preuves d’annuaire non vérifiables font refuser le lecteur ; les autorités SCIM/TeamViewer ne sont pas utilisées pour « réparer » silencieusement cette preuve.

La transaction de lecture conserve le verrou d’organisation partagé avec les changements de rôle/module/mapping. Les tests de concurrence vérifient le refus ou l’utilisation de la révocation nouvellement commise. Les écritures des transporteurs conservent leurs propres transactions ; la projection ne promet pas une photographie globale des systèmes distants.

La lecture ne crée, ne réessaie et ne révoque aucun Grant, ExternalChange, ScimCreationRequest, événement d’accès, vote, bail ou session. Aucun appel réseau ou provisioning n’est effectué. Dans la préparation locale du portail F3, `config.urls` inclut les trois routes canoniques HTML/API/export du lecteur. La fiche F1 de source relie sa revue en conservant limite et curseur validés. Identity360 propose l’index des sources lorsque Connect et ses dépendances sont actifs ; ce lien de navigation ne prétend pas associer rétroactivement une observation d’annuaire à une personne. Il n’ajoute aucune jointure d’autorité ou opération métier.

Les tests d’interface utilisent désormais le véritable URLconf produit, sans ajouter les routes via un URLconf de test. Les29méthodes d’attaque indépendantes sont conservées à l’identique ; seuls leur branchement d’URLconf et les imports correspondants ont changé. Les exports restent des relectures actualisées, bornées, avec date/run et leurs propres niveaux d’assurance. L’activation locale des routes ne vaut ni publication ni qualification de l’image native de base.

## Réception locale

Tests dédiés : `tests.test_directory_reconciliation` et `tests.test_directory_reconciliation_concurrency`. Ils couvrent références vérifiées et horodatées, source/tenant/collisions, mapping retiré, état nullable/absent, propriétaire courant réattribué, origine historique, résultat tardif, création inactive, preuve invalide, labels sans équivalence, sortie sans secrets, limites/curseurs, aucune écriture et refus après révocations concurrentes. Les résultats PostgreSQL exacts seront ajoutés au rapport de livraison ; une exclusion PostgreSQL sur SQLite n’est pas une réussite.
