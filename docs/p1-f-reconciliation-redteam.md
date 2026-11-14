# P1-F3 — revue indépendante des rapprochements et de leur provenance

État : contre-exemples backend et export corrigés, contre-validation indépendante locale réussie. Le reviewer a créé uniquement `tests/test_directory_reconciliation_redteam.py` et ce rapport pour F3. Aucun code développeur, contrôle P0, NAS, système réel ou donnée de production n’a été modifié par ce reviewer. Ce résultat ne vaut pas CI du commit livré ni déploiement.

## Périmètre

Lecture du contrat et du service `directory_reconciliation`, des lecteurs d’inventaire, de la liaison de destination SCIM P0-2, des vérificateurs de création SCIM, des mappings/résolutions TeamViewer et de la provenance V8. Les tests attaquent les raccourcis entre autorités ; ils n’exécutent aucune opération distante.

Les fixtures utilisent les services autorisés pour créer les sources, mappings d’annuaire et connecteurs SCIM scellés. Les données SCIM historiques non signées sont explicitement construites comme telles. Les destinations restent `.invalid` ; l’allowlist de configuration est limitée au seul hôte synthétique. Une origine historique qui ne peut pas être établie n’est pas réparée en ouvrant la politique réseau.

## F3-RT-01 — destination SCIM historique non établie présentée comme certaine

Sévérité : moyenne pour l’intégrité des revues et exports ; aucune remise de secret, autorisation ou exécution distante n’est démontrée.

La migration P0-2 `connectors.0011_scim_destination_binding` scelle seulement les connecteurs historiques de première révision. Une destination déjà révisée peut rester sans `destination_seal`, parce que l’URL d’origine n’est pas reconstructible. Le service d’exécution refuse correctement ce credential non vérifiable et PostgreSQL empêche les futures réécritures de destination.

Le nouveau lecteur `_origin` utilisait pourtant `binding.connector.base_url` avec `state=recorded_operation_origin`, sans qualifier cette incertitude. Une opération ancienne liée au même connecteur pouvait donc être présentée avec l’URL actuellement conservée comme s’il s’agissait de son annuaire d’origine attesté. Le contrat d’accès précédent n’exporte que les identifiants de référence, sans cette nouvelle affirmation d’URL.

Reproduction : source d’annuaire liée explicitement à un compte, connecteur synthétique historique révisé sans sceau, opération et résultat SCIM enregistrés. Le test conserve les références binding/connecteur mais exige une origine non vérifiée et aucune URL affirmée comme destination historique. Le scénario final précise une opération en première révision devant un connecteur conservé en seconde révision.

Correction demandée : distinguer la référence enregistrée de la destination dont l’identité est vérifiable. Pour le legacy non réconcilié, exposer l’incertitude et conserver les références utiles sans donner à l’URL stockée l’autorité d’une origine historique. Une preuve signée de création peut fournir son propre contexte figé ; ne jamais le remplacer par un mapping courant. Aucune donnée ancienne ne doit être réécrite pour rendre l’export certain.

## F3-RT-02 — intégrité d’un lien TeamViewer et provenance d’événement confondues à l’affichage

Sévérité : moyenne pour la qualification des preuves ; aucune création d’événement `legacy_unknown` ni attribution d’un compte Windows n’est démontrée.

Le vérificateur `teamviewer_access.verify_observation` accepte intentionnellement les anciens liens signés dont l’événement reste `legacy_unknown`. Cette compatibilité préserve les preuves antérieures à P0-4 ; elle ne leur attribue aucun reçu V8. Le service `verified_origin_status` conserve séparément cet état inconnu.

F3 exposait seulement `provenance_link=verified`, sans préciser le canal effectivement vérifié ni le statut du reçu de provenance. Une vérification d’intégrité du lien normalisé risquait ainsi d’être lue comme une provenance authentifiée V8.

Reproduction : le test construit une représentation historique **en mémoire** à partir d’un lien signé synthétique réel. Le snapshot source gelé ne contient pas le nouveau canal, donc sa signature historique reste réellement vérifiable. L’objet historique n’a pas de reçu ; `verify_observation` retourne vrai et `verified_origin_status` retourne `legacy_unknown`. Aucun INSERT/UPDATE de ligne legacy, désactivation de trigger ou faux retour de vérificateur n’est utilisé. Seule la sélection du lien renvoie cette représentation historique, afin d’exercer le lecteur sans créer un ancien événement par un rédacteur ordinaire.

Correction demandée : exposer séparément intégrité du lien, canal de provenance vérifié et présence/validité du reçu V8. Le lien historique peut rester vérifié, tandis que l’événement demeure `legacy_unknown` et `provenance_receipt_verified=false`. Ne jamais le reclasser automatiquement. Un lien altéré ne doit exporter aucun identifiant d’événement présenté comme vérifié.

## Protections challengées

Les autres tests exigent :

- Même UUID distant ou même nom sur deux sources : aucune association SCIM héritée sans mapping explicite de la source considérée.
- Mêmes identifiants de groupe : aucune équivalence LDAP/SCIM, aucun droit effectif ou Grant créé.
- Destination SQL réécrite : refus réel par le trigger P0-2 PostgreSQL.
- Propriétaire IAM réattribué : propriétaire courant seulement, jamais authentification historique d’une nouvelle personne.
- Résultat tardif avec booléen confirmé contradictoire : demeure écarté ; opération en retry non confirmée.
- Source désactivée, membership retirée, dépendance Identity désactivée ou contexte d’organisation contradictoire : aucune jointure d’histoires cachées ou accès cross-tenant.
- Compte Windows au même nom qu’un opérateur TeamViewer : aucune requête de session TeamViewer ni attribution au compte OS.
- État LDAP nullable, collecte incomplète ou absence dans une collecte déclarée complète : revue/état inconnu, sans révocation.
- Budget global d’histoire : troncature explicite, sans transformer les éléments non lus en absence.
- Aucune écriture métier/audit, aucun appel réseau, credential/token/ciphertext ou champ fournisseur brut dans la projection.

## Résultats et limites

Premier passage : **15 tests PostgreSQL en5,542s :3 réussis,2 échecs,10 erreurs**. Les erreurs provenaient de la fixture SCIM dont l’allowlist de configuration n’était pas renseignée. Le second échec initial de préparation historique gardait encore le cache du reçu actuel ; le test a été corrigé pour représenter un vrai événement historique sans reçu. Aucune permission produit n’a été modifiée.

Après correction des fixtures : **15 tests PostgreSQL en6,479s :13 réussis,2 échecs, aucune erreur, aucune exclusion**. Ces deux échecs reproduisent les constats ci-dessus. Le journal initial est conservé hors dépôt dans `output/p1-f-recon-red-reproduction.log` ; il ne constitue pas une validation du lot.

Trois tests supplémentaires complètent la campagne backend : contexte cross-organisation même avec superutilisateur, lien normalisé altéré et labels de groupe identiques sans droit effectif. Après les correctifs du développeur, contre-revue indépendante fraîche : **18/18 tests PostgreSQL en9,433s, aucune exclusion**. Les deux assertions de reproduction sont inchangées. Le journal est conservé hors dépôt dans `output/p1-f-recon-red-backend-fixed.log`.

## F3-RT-03 — un export élargit silencieusement la page revue

Sévérité : faible pour la sécurité, défaut fonctionnel d’export et de minimisation. Aucune lecture hors des droits du lecteur n’a été obtenue.

Les liens « Exporter cette page » des interfaces F1 et F3 ne conservaient que `cursor`. Les paramètres `limit` et, pour F3, `history_limit` étaient omis. Après une page affichant un objet avec `limit=1`, cliquer le lien exportait trois objets dans la fixture, parce que le lecteur reprenait sa limite par défaut. L’export ne correspondait donc pas au périmètre présenté à l’opérateur.

Reproduction HTTP indépendante : **9 tests PostgreSQL en4,992s :6 réussis,3 échecs, aucune erreur ou exclusion**. Les échecs comparent le contenu réel exporté à celui rendu en HTML pour F1/F3, et vérifient les paramètres du lien F3. Les réussites couvrent origine SCIM legacy inconnue sur HTML/API/export, distinction TV lien/canal/reçu, échappement des labels/hrefs, paramètres malveillants non réfléchis, session d’un autre tenant, module désactivé et curseurs/budgets invalides. Journal de reproduction : `output/p1-f-recon-ui-red-reproduction.log`, hors dépôt.

Correction appliquée par le coordinateur : les limites validées et le curseur encodé sont conservés dans les liens d’export et API des deux interfaces. Un dixième test HTTP contrôle une continuation réellement signée, ses deux budgets et les mêmes objets/run via export et API. Les trois assertions ayant reproduit l’élargissement de page sont conservées sans assouplissement.

Ces lecteurs restent des vues vivantes : conserver un curseur de run n’immobilise pas les mappings ou propriétaires actuels. Une première page sans curseur peut aussi lire un nouveau run au moment d’une requête ultérieure. La décision d’architecture du coordinateur est de l’indiquer explicitement, sans ajouter un modèle de snapshot : libellé « Exporter l’état actualisé » et notice « Les données sont relues au moment de l’export ; les dates et les références du fichier décrivent cet état. » Les deux interfaces affichent cette notice. Un onzième test HTTP accepte une nouvelle collecte entre l’affichage et le clic, puis vérifie que l’export décrit le nouveau run, sa date et ses nouveaux faits ; il ne prétend pas figer les mappings ou propriétaires courants.

## Contre-validation finale

**29/29 tests PostgreSQL en15,108s, aucune erreur, aucun échec, aucune exclusion.** Cette exécution indépendante comprend les18tests backend inchangés et11tests HTTP, via `run_p1f_tests.py --label recon_red tests.test_directory_reconciliation_redteam`. Le journal est `output/p1-f-recon_red.log`, hors dépôt. Les résultats initiaux restent consignés ci-dessus, sans être additionnés comme des tests uniques.

Les tests HTTP utilisent les routes produit réelles dans un URLconf de test qui inclut le noyau. Ils exercent les services et templates effectifs, puis analysent les liens et le contenu rendu ; ils ne simulent pas le retour du lecteur de rapprochement. La sélection du seul lien historique TV est remplacée dans son test dédié, avec vérificateurs cryptographiques réels inchangés. Il s’agit d’une qualification serveur Django/HTML, pas d’une exécution graphique ou JavaScript dans un navigateur.

Le reviewer ne relève plus de blocage dans son périmètre testé. Les régressions P0 complètes, la concurrence multi-connexion du développeur, les restaurations et la qualification de l’image exacte restent leurs gates distincts. L’intégration/publication finale dépend de leurs résultats ;29tests verts ne suffisent pas à annoncer la qualification du programme complet.

Ruff et contrôle de diff du périmètre reviewer réussis. Les essais de concurrence du développeur et les migrations/restaurations P0/P1 restent des campagnes distinctes. La représentation historique en mémoire ne remplace pas une restauration complète de base antérieure ; elle vérifie précisément le contrat de conservation des preuves de ce lecteur. Aucun transport ou fournisseur commercial n’est qualifié par cette campagne.

## Préparation d’intégration canonique du12novembre2026

Dans le worktree séparé `agent/p1-f3-portal`, les routes sont activées dans `config.urls`. Les deux URLconf additionnels de tests ont été retirés ; les29méthodes Red Team restent identiques selon une comparaison AST enregistrée hors dépôt. Les assertions de sécurité n’ont pas été adaptées pour faire passer l’intégration. Les nombres ci-dessus décrivent les campagnes historiques ; le nouveau résultat du portail canonique est rapporté séparément après exécution.
