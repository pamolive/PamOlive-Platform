# Faits source et interprétations des accès

Un événement d’accès conserve ce qu’une source a déclaré. L’interprétation rapproche ensuite ses références d’objets gouvernés et compare le périmètre à une intention ou à un droit. Les deux couches restent distinctes : corriger une attribution ne réécrit ni les faits ni les analyses précédentes.

## Contrat des adaptateurs

Le module d’accès expose `register_provider` dans `platform_modules.access.observations`. Un fournisseur se déclare depuis son `AppConfig.ready`, avec une clé technique, son module, un résolveur et une sélection bornée d’événements candidats pour le graphe. Ces fonctions proviennent du code livré et vérifié au déploiement, jamais d’un chemin enregistré dans un formulaire ou d’un script téléversé.

Le résolveur reçoit l’événement et l’organisation. Il retourne un `ObservationContext` contenant une copie de l’événement, un snapshot JSON de son interprétation, les constats de provenance et un éventuel blocage. Seules les références `identity`, `account` et `resource` peuvent être rapprochées dans cette copie. Les dates, méthode, privilège, origine et autres faits ne peuvent pas être remplacés par l’adaptateur. Les objets doivent appartenir à la même organisation.

Le module de l’adaptateur doit être actif pour l’organisation. Un module absent ou désactivé, une preuve invalide ou un résultat incompatible produit un contexte bloqué et inconnu, pas un retour implicite aux propriétaires de l’inventaire. Le registre n’est pas une sandbox : les paquets Python installés restent du code de confiance de l’application et nécessitent une revue avant déploiement.

## Provenance de la normalisation

L’espace `managed:` est réservé. Les événements ordinaires reçus par jeton gardent l’UUID de leur source, imposé côté serveur ; la console ne peut pas usurper un nom de collecteur interne. Un nom ou un identifiant identique n’est jamais une preuve de provenance.

Pour TeamViewer, `TeamViewerAccessObservation` relie de manière unique et signée une session regroupée à son `AccessEvent`. Les références, dates et signatures de la session source sont revérifiées. Si le couple source et identifiant existe déjà sans ce lien, le normaliseur conserve la donnée et refuse de l’adopter. Le dossier affiche un refus d’audit sans exposer de secret.

Les UUID locaux d’acteur, de compte et de ressource restent vides dans ce fait source. L’interprétation les résout depuis les attestations datées. Sa provenance reste `administrative_attestation_not_authentication_proof` : la propriété d’un compte n’est pas une preuve que son propriétaire a agi. Un compte opérateur TeamViewer n’est pas un compte Windows distant.

## Analyses signées et historique

`access-context/7` conserve dans `AccessEvaluation` les constats, le contexte utilisé, son empreinte sémantique et une signature liée à l’audit. Le corps signé lie également l’analyse à l’événement et aux champs source du schéma versionné dans `EVENT_FACT_FIELDS`. Ajouter un champ à ce schéma exige une évolution explicite du format, afin de ne pas invalider silencieusement les preuves historiques.

Le contexte complet conserve les témoins de lecture. Son empreinte sémantique exclut seulement ce qui varie lors d’une lecture identique, notamment l’identifiant du nouveau témoin. Le normaliseur peut ainsi éviter une analyse identique tout en conservant chaque observation source. Une nouvelle attestation, un conflit ou une variante de rapport modifiant l’interprétation provoque une nouvelle analyse.

Une ancienne évaluation non signée reste une donnée historique. La vérification de restauration peut accepter sa forme antérieure, sans la compter comme preuve signée ; elle ne satisfait pas le contrôle d’une conclusion actuelle vérifiée. La migration ne complète pas ses constats et ne la signe pas rétroactivement.

## Informations absentes et écarts établis

La comparaison distingue trois situations :

| Données disponibles | Résultat de comparaison |
|---|---|
| Toutes les restrictions nécessaires sont observées et concordent | Le périmètre peut être rapproché, sous réserve des autres règles |
| Un champ nécessaire manque | Contexte insuffisant, sans compléter le champ depuis l’intention |
| Une valeur observée diffère d’une restriction applicable | Écart connu à examiner |

Cette règle concerne notamment le compte utilisé, le privilège, l’origine, la méthode et le placement réseau. Une intention exigeant « Administrator » ne prouve pas ce privilège dans un rapport qui ne le fournit pas. À l’inverse, une machine identifiée hors périmètre reste un écart même si d’autres champs manquent.

## Lecture et exploitation

Le détail et l’export gardent les faits source et l’interprétation dans des blocs séparés. Le graphe et la chronologie utilisent le même résolveur vérifié. Les sélections d’événements candidats ne constituent pas des attributions : leur identité est contrôlée après résolution, avec indication des limites de parcours.

Si l’interprétation actuelle diffère du snapshot de la dernière analyse, celle-ci reste consultable comme historique et n’est pas affichée comme une conclusion actuelle. Une réévaluation ajoute une version. Les changements de politique sans changement d’interprétation nécessitent également une réévaluation explicite ; le traitement de normalisation n’est pas une surveillance universelle de toutes les règles métier.

Le normaliseur TeamViewer utilise le worker et les verrous PostgreSQL existants. Son curseur signé est un cache réinitialisable, sans valeur d’autorisation ni de preuve source. Il parcourt les dossiers par lots de cinq ; aucun conteneur supplémentaire n’est ajouté et aucun challenge MFA n’est injecté dans une session SSH ou RDP ouverte.
