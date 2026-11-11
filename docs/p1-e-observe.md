# P1-E — Observe et démonstrateur synthétique PC-483 / PC-991

Le lot complète la lecture transverse P1-B1 par une entrée centrée sur **l’observation**. Une observation sans demande liée reste visible : elle n’est pas exclue parce que le contrat d’accès a une intention comme racine. Les références sources, évaluations V7 et reçus V8 restent les modèles existants. Aucune migration, seconde autorité d’ingestion ou nouvelle signature n’est créée.

## Lecture et garanties

`platform_modules.access.observe.observation_story` produit `pamolive.observation-story/1`. Le service requiert le contexte organisationnel, verrouille l’organisation, recharge l’acteur actif et ses permissions, puis exige Identity, Access et Intelligence. La lecture d’une observation collector/internal exige aussi Connect. Les interfaces HTML, API de session et export utilisent le même service, exclusivement en GET, avec `no-store` et `nosniff`.

La dernière évaluation est vérifiée avant de publier sa conclusion. Si elle est absente ou invalide, le résultat est **Indéterminé**, sans reprise silencieuse d’une ancienne conformité. Un reçu V8 invalide interdit également une présentation conforme. Les anciennes observations conservent `legacy_unknown` ; elles ne reçoivent aucune attestation rétroactive. Une évaluation historique V7 vérifiable reste lisible, avec l’incertitude de provenance exposée séparément.

Les trois libellés sont **Conforme** (`expected`), **Non conforme** (`deviation`) et **Indéterminé** (`unknown`). « Non conforme » signifie écart dans l’évaluation enregistrée et son périmètre, pas preuve indépendante d’un accès illicite. La date et la règle de cette évaluation sont affichées ; la lecture ne relance pas une évaluation sous la politique actuelle.

Le contrat v1 est joint uniquement lorsqu’une évaluation vérifiée contient une référence explicite à une intention. Il sépare demande, votes, droit local, opérations, confirmations, observation et preuves. Une chronologie ordonne les dates des objets enregistrés ; elle n’invente ni causalité, ni moment d’exécution distant à partir de l’heure d’enregistrement d’une preuve. Les sections désactivées restent indisponibles dans le contrat.

L’option `compare_intent` permet une comparaison explicite dans le même tenant. Elle ne lie pas rétroactivement l’événement à la demande. Les dimensions exposent correspondance, divergence ou valeur inconnue. PC-991 peut diverger d’INC-47294 et disposer d’un autre accord valable ; le moteur existant recherche cet accord et le test le vérifie. Les noms, payloads de fournisseur et secrets ne servent jamais d’identifiant d’association.

L’index borne son examen aux 100 dernières observations disponibles. Les filtres de verdict vérifient les preuves ; ils ne constituent pas une recherche exhaustive sur l’historique. Une troncature est explicite. Cette première version privilégie un nombre de lectures borné ; l’index réalise des vérifications par observation et n’est pas une qualification de débit.

## Interfaces

- `/observe/` : liste et filtres `expected`, `deviation`, `unknown`.
- `/observe/events/<uuid>/` : détail et chronologie.
- `/observe/events/<uuid>/export/` : export JSON de lecture.
- `/api/v1/observations/<uuid>/story/` : même projection, authentification de session.

Le reçu V8 atteste l’acceptation des faits par PamOlive. Il ne certifie pas la vérité de la télémétrie distante ni l’indépendance de l’opérateur du collecteur. Une saisie manuelle au même identifiant externe possède un autre canal et un autre principal.

## Démonstrateur sans réseau

La commande `pamolive_observe_demo --synthetic-only` exige `PAMOLIVE_SYNTHETIC_DEMO=1`, une base nommée `test_pamolive_*` (ou mémoire de tests Django), **sans organisation ni compte existant**. Elle ne comporte aucun reset, suppression ni mode force. Le CLI n’est exposé par aucune route. La création est transactionnelle.

À utiliser exclusivement après migrations sur une base synthétique neuve désignée explicitement par `DATABASE_URL`. Ne jamais désigner la base de l’installation existante. La commande refuse le nom SQLite opérationnel et toute base déjà peuplée. Son manifeste ne contient aucun jeton, mot de passe, graine MFA ni ciphertext. Les comptes créés ont des mots de passe inutilisables ; aucune connexion réelle n’est préparée.

Le scénario crée deux organisations avec les mêmes identifiants de comptes/groupes distants ; A dispose en plus de Recertification, B ne l’a pas. Il crée une demande temporaire INC-47294 sur PC-483, une décision par un autre compte, un droit local et une opération en attente. Le worker SCIM existant traite cette opération avec un adaptateur mémoire, puis produit sa preuve d’exécution. Les destinations autorisées sont temporairement limitées aux deux noms `.invalid` de la fixture ; aucun socket ou client HTTP n’existe dans cet adaptateur, et aucun repli réseau n’est prévu. Ces confirmations sont des **résultats du simulateur**, pas des confirmations d’un fournisseur réel. L’assurance interactive et les données cryptographiques sont elles aussi synthétiques dans cette base jetable ; elles ne constituent pas le commissionnement PAM P0-3.

Le collecteur synthétique authentifié rapporte PC-483, PC-991 et une identité non résolue : les résultats attendus sont respectivement conforme, écart, indéterminé. Un événement manuel réutilise le texte de source et l’identifiant PC-483 sans remplacer celui du collecteur. Les reçus V8 restent distincts.

Enfin, l’horloge du processus de fixture avance après expiration du droit : le service d’expiration existant demande son retrait, un fournisseur simulé indisponible laisse une tentative en retry sans confirmation de retrait, puis la reprise confirme le retrait vers sa destination d’origine. Le manifeste conserve les étapes « en attente », « confirmé », « retrait demandé », « fournisseur indisponible » et « retrait confirmé ». Cette avance ne s’applique qu’au processus isolé de démonstration.

## Validation et limites

Les tests `tests.test_observe_story` couvrent les trois verdicts, autre autorisation valable, preuves invalides, rôles/modules désactivés, tenants, UI/API/export en GET, filtres et démonstrateur complet sans réseau. `tests.test_observe_concurrency` exige PostgreSQL et provoque un lecteur bloqué derrière le verrou pendant une désactivation de module ou révocation d’appartenance : il doit être refusé après libération. Les résultats exacts et la revue indépendante sont consignés dans le rapport consolidé de livraison.

Les tests ne qualifient ni un collecteur TeamViewer réel, ni AD/LDAP/Entra, ni une cible PAM réelle. L’export de parcours est une lecture non signée référant les preuves existantes ; il ne remplace pas leur export vérifiable. Aucun retour à un binaire pré-P0-4 contre la base migrée n’est autorisé par ce lot.

Qualification locale du 11 novembre 2026 : `manage.py test tests.test_observe_story tests.test_observe_concurrency --noinput` a exécuté **15 tests PostgreSQL en 6,801 s, tous réussis, aucun ignoré** sur `test_pamolive_p1e` jetable, détruite en fin de campagne. Ruff est vert sur les fichiers du lot. Un premier lancement PostgreSQL n’a pas pu se connecter au port attendu ; il a échoué avant les tests et a été relancé après correction du cluster local. Les erreurs de préparation des fixtures MFA/allowlist apparues dans les premiers passages SQLite ont été corrigées sans modifier les contrôles de production. La qualification finale inclut l’appel réel de la commande opt-in, le refus de base non synthétique et les deux courses PostgreSQL.
