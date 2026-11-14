# P1-F3 — rapprochement des observations et des exécutions

Revue indépendante en lecture seule du code courant. Cette note propose un lot ciblé ; elle ne déclare pas son implémentation ni sa qualification. Aucun annuaire réel, compte réel ou NAS n’a été utilisé.

## Capacités présentes

| Domaine | Chemins existants | Garanties à conserver |
| --- | --- | --- |
| Inventaire d’annuaire | `connectors.directory_inventory.directory_inventory`, vérificateurs `verify_directory_source`, `verify_directory_run`, `verify_directory_mapping` | Source/destination immuables, runs et faits signés, association explicite de compte, provenance et complétude, pagination facts/absent ; aucune attribution |
| Identity 360 | `identity.identity360.build_identity360` | Comptes et droits locaux séparés des confirmations externes ; références SCIM configurées dans `sources` et `directory_groups`, sections bornées et modules relus |
| Histoire d’accès | `platform_core.access_contract.build_access_contract` | Intention, votes, droit local, opérations, confirmations historiques et observations distincts ; origine via `ExternalChange.binding`, jamais remappée avec le binding courant |
| Provisioning SCIM | `connectors.outbound._claim`, `_check_dispatch`, `_finish`, `process_changes` | Destination P0-2, revalidation, résultat tardif distinct, reprise, compensation ; confirmations datées après lecture de la cible |
| Création SCIM | `connectors.creation.verify_request`, `verify_dispatch`, `verify_proof`, `process_creations` | Autorisation signée, dispatch réservé une seule fois, confirmation initiale inactive et activation séparée |
| TeamViewer | `teamviewer_mapping.resolve_sighting`, `teamviewer_sessions.resolve_session`, `teamviewer_access.verify_observation`, `resolve_observation`, `related_events` | Correspondances datées et signées, révisions et variantes, refus des ambiguïtés, V7/V8 ; opérateur TeamViewer distinct du compte OS |

L’inventaire F1 n’est pas encore exposé dans Identity 360 ni rapproché dans un lecteur transverse avec les confirmations SCIM/TeamViewer. Le contrat d’accès existant fournit déjà l’histoire d’une intention ; le recopier comme un nouveau journal d’exécution serait une duplication.

## Limites d’équivalence à ne pas masquer

`DirectoryMapping` associe explicitement un objet d’une source à un compte local. `AccountBinding` associe ce compte à un utilisateur d’un connecteur SCIM. Ces deux décisions ne prouvent pas que les deux destinations constituent le même annuaire. Les protocoles, realms, scopes, identifiants et autorités peuvent différer. Une égalité de nom, d’UUID distant ou de hostname ne crée pas cette preuve.

Les groupes de l’inventaire sont des labels/DN observés, sans correspondance de groupe stable actuellement enregistrée avec `GroupBinding.remote_id`. Leur égalité textuelle avec un intitulé d’habilitation ne confirme aucune appartenance ni aucun privilège effectif.

`ExecutionEvidence.confirmed` est un résultat fournisseur enregistré et audité par PamOlive ; ce modèle ne possède pas une signature autonome de l’annuaire distant. Il ne faut pas lui attribuer le même niveau de preuve qu’un reçu V8 vérifié, qu’une preuve signée de création SCIM, ou qu’une chaîne signée TeamViewer. Le lecteur existant utilise justement `provider_result_recorded` et `current_provider_state=not_asserted`.

Une observation plus récente peut suivre une révocation confirmée sans que l’une soit fausse : changement externe ultérieur, autre système, collecte partielle ou association administrative erronée restent possibles. Une session TeamViewer ne prouve ni l’identité Windows, ni le privilège OS, ni la validité d’un ticket mentionné dans une note.

Enfin, la correspondance d’inventaire contient un identifiant de compte local, sans snapshot d’identité humaine historique. Si le propriétaire du compte est réattribué ultérieurement, il ne faut pas imputer rétroactivement l’ancienne observation à cette nouvelle personne. Une projection Identity 360 doit qualifier ce rattachement comme une association au compte courant, pas comme une preuve historique d’authentification de la personne.

## Plus petit lot fonctionnel recommandé

Créer un lecteur versionné **centré sur une page d’inventaire d’une source**, sans nouvelle table ni nouvelle opération distante. Exemple de contrat : `pamolive.directory-account-review/1`.

1. Réutiliser `directory_inventory` pour la page et ses preuves. Revalider acteur, organisation et modules sous le verrou existant.
2. Pour les seuls comptes explicitement liés sur cette page, charger par lots les références SCIM, opérations et confirmations pertinentes. Borner également les preuves et signaler toute troncature ; éviter une boucle appelant cent contrats d’accès complets.
3. Exposer des sections distinctes : observation de source, association administrative, état local, origine des opérations SCIM, résultat historique enregistré, preuve signée de création éventuelle, observations TeamViewer dont la chaîne et la résolution ont été vérifiées.
4. Qualifier explicitement la relation entre destinations : `not_established` en l’absence d’une association de realm distincte et revue. Ne jamais déclarer une confirmation croisée sur la seule égalité des identifiants.
5. Produire uniquement des motifs explicables de revue : compte local actif alors que la source le rapporte désactivé ; compte local inactif observé actif ; état inconnu ; correspondance absente/révoquée ; preuve non vérifiable ; résultat fournisseur ancien ou opération en attente. Aucun de ces motifs ne publie une décision, une révocation ou un retry.
6. Ajouter une vue/API/export réutilisant ce lecteur et un lien depuis Identity 360. Les contextes de destination, dates, niveaux d’assurance et limites restent visibles dans l’export.

Le résultat n’est pas une nouvelle preuve cryptographique ni une décision de politique. Chaque référence expose son niveau d’assurance propre ; aucun booléen `verified` global ne fusionne les autorités.

Une comparaison d’appartenance effective entre LDAP/Graph et SCIM nécessiterait ensuite une association explicite et versionnée des realms et des groupes stables. Elle doit être qualifiée séparément. Il n’est pas nécessaire d’ajouter cette autorité pour livrer le lecteur de revue proposé.

## Réception falsifiable

- Deux sources et deux organisations partagent les mêmes identifiants distants : seules les associations locales explicites sélectionnent les références pertinentes.
- Une opération de retrait reste reliée à son binding et à sa destination historiques après un remapping courant.
- Une confirmation SCIM ne devient jamais une attestation de l’état LDAP courant, et un groupe LDAP de même nom ne devient pas un groupe SCIM.
- Une observation partielle, un état nullable, un vieux run ou une preuve invalide produisent un résultat inconnu ou une revue, jamais une absence certaine ou une suppression.
- Un résultat SCIM tardif écarté, une opération en retry et une création inactive ne deviennent pas des droits effectivement provisionnés.
- Une association TeamViewer non résolue, une preuve invalide ou un opérateur connu sans compte OS restent non attribués dans les dimensions concernées.
- Une réattribution d’identité locale ne fabrique aucune authentification historique de la nouvelle personne.
- Désactivation d’un module, rôle retiré ou UUID étranger bloquent les voies HTML/API/export et services ; aucune requête vers un domaine désactivé n’est effectuée pour remplir une section vide.
- Les limites et curseurs bornent observations et preuves, y compris les absences ; aucun secret, header, capsule chiffrée ou payload fournisseur brut n’apparaît dans la sortie.
- La lecture ne crée aucun `Grant`, `ExternalChange`, `ScimCreationRequest`, `AccessEvent`, vote ou bail PAM. Le test doit vérifier ces compteurs avant et après.

## Packaging et analyse des dépendances

Le Dockerfile prépare les wheels OpenLDAP dans un builder séparé, avec bibliothèques de compilation absentes du runtime. Le runtime installe les bibliothèques partagées LDAP/SASL et les paquets du lock applicatif, puis `pip check`. `requirements-directory.lock` est admis dans le contexte Docker et les versions ASN.1 sont alignées avec `requirements.lock`. Le marqueur Linux du lecteur évite une installation Windows impropre ; l’image Linux doit en revanche prouver l’import et les tests wire, sans transformer une dépendance manquante en exclusion réussie.

Le scan Python/SBOM de CI doit inclure le lock résolu sur Linux, donc python-ldap et ses dépendances. Il ne remplace pas une analyse des paquets Debian, d’OpenLDAP/SASL ou du moteur natif. Un résultat sans avis Python connu ne signifie pas que toute l’image est sans vulnérabilité.

Les versions Python sont épinglées, mais les fichiers actuels ne verrouillent pas chaque artefact par hash ; les dépôts apt peuvent également évoluer entre deux builds. La promotion de l’image exacte qualifiée sans reconstruction protège la livraison observée ; elle ne garantit pas la reproductibilité d’une construction future. Les digests, plateformes et attestations doivent toujours être relevés sur chaque image effectivement publiée.
