# P1-F — revue indépendante Connect / Audit

Périmètre : inventaire persistant d’annuaires et correspondances explicites, avec adaptateurs de laboratoire. Références : AGENTS.md, P0-2, ADR-014, contrats P1 et services SCIM/TeamViewer existants. La revue n’autorise aucun accès à un annuaire réel ou au NAS. Les scénarios ci-dessous sont des exigences vérifiables ; ils ne constituent pas des vulnérabilités confirmées avant reproduction.

## Frontières d’autorité

Une source possède un UUID propre à une organisation et une destination immuable. Un objet distant est identifié par cette source et son identifiant stable canonique ; un nom, un e-mail, un DN LDAP ou un identifiant identique dans une autre source ne permettent pas d’adopter une identité locale.

Une fixture importée reste `synthetic_fixture`. La réception par un serveur authentifié ne transforme pas une saisie humaine en collecte authentifiée. `authenticated_lab_directory` indique les contrôles de transport réalisés par l’adaptateur de laboratoire ; cette provenance ne prouve ni la vérité des faits, ni l’identité indépendante d’une personne. Aucune de ces projections ne crée une habilitation, une attestation PAM, une approbation, une confirmation de provisioning ou une révocation distante.

Le modèle conserve les sources, runs, faits et décisions historiques. Un changement incompatible exige une nouvelle source et de nouvelles correspondances. La rotation d’un secret ne réattribue pas l’identité historique ; elle invalide les opérations préparées sous une révision devenue incompatible.

## Attaques et résultats attendus

| Scénario adverse | Résultat attendu |
| --- | --- |
| Même UUID distant, même nom et même e-mail dans deux sources ou organisations | Objets indépendants ; aucune correspondance automatique ni réutilisation de mandat |
| Objet dont le nom correspond à un compte local privilégié | Revue explicite ; aucun rattachement ni changement de propriétaire automatique |
| Import d’une fixture avec un nom de source évoquant un collecteur | Provenance de fixture conservée ; aucun événement V8 collector fabriqué |
| Modification d’hôte, de port, de base DN, d’identité de bind, de pin ou de tenant Graph | Ancienne source immuable ; nouveau secret explicitement configuré pour la nouvelle destination |
| Mauvais certificat ou pin, redirection HTTP, DNS rebinding, métadonnées ou IPv4 mappée | Refus avant émission des credentials ; aucun repli TLS permissif |
| Jeton du tenant Graph B configuré pour une source déclarant A | Tenant effectivement authentifié différent : refus, même si les UUID utilisateurs sont identiques |
| Graph nextLink du bon hôte mais d’un autre chemin ou périmètre | Refus ; aucune extension d’autorisation par pagination |
| Referral LDAP, DN mutable présenté comme identifiant, groupe AD tronqué | Aucun suivi implicite ni identifiant adopté ; résultat refusé ou explicitement incomplet |
| Cookie de pagination répété, page malformée, total variable, limite dépassée ou panne au milieu | Arrêt borné, complétude non affirmée et aucune suppression inférée |
| Objet absent d’une collecte, même annoncée complète | Absence observée à une date ; jamais preuve de suppression ou autorisation de retrait |
| Même clé d’idempotence et mêmes faits canoniques | Même run, sans double écriture ni double effet |
| Même clé d’idempotence avec faits, provenance ou révision divergents | Conflit audité, original inchangé et transaction de conflit conservée |
| Désactivation du module, révocation du compte ou rotation après début de collecte | Revalidation après I/O et avant commit ; aucun résultat courant fondé sur une autorité périmée |
| Mapping vers un compte d’une autre organisation | Refus du service et contraintes PostgreSQL ; aucun droit indirect accordé |
| Réutilisation d’un curseur d’export dans un autre tenant, source ou filtre | Refus ; pas de fuite d’objets ni de reprise d’un autre périmètre |
| Champs supplémentaires contenant token, mot de passe ou payload HTTP | Refus ou projection en liste blanche ; aucune réflexion dans l’export ou le journal public |
| Écriture SQL directe modifiant un fait ou une décision historique | Refus par les contraintes d’immutabilité ; vérification de restauration bloquante en cas d’altération |
| Downgrade après apparition de preuves | Refus du retour arrière destructeur ; données historiques et clé de vérification conservées |

La collecte doit borner pages, objets, octets, temps et répétitions de curseurs. Une borne de sortie n’est pas une borne de lecture : le lecteur doit aussi limiter le travail effectué avant de produire son export. Les reprises doivent porter l’organisation, la source, sa révision et son périmètre de recherche, sans exposer un token ou un nextLink sensible.

## Points soumis à confrontation

Le tenant Graph constitue une identité logique distincte du seul hostname : l’URL `/users` est commune à plusieurs annuaires. Une valeur de scope fournie par l’administrateur ne prouve pas le tenant du jeton. L’adaptateur doit vérifier le tenant effectif par une réponse authentifiée appropriée ou une validation cryptographique complète du token ; décoder un JWT sans vérifier sa signature ne suffit pas.

Le contrôle LDAP doit précéder le bind : vérification TLS, hostname et pin sur la connexion réellement utilisée. Les referrals restent désactivés. Un contrôle du certificat réalisé sur une autre connexion ne protège pas le secret transmis ensuite.

Décision de transport F1 : le lecteur natif utilise `ldap://` avec StartTLS obligatoire sur le descripteur connecté et épinglé. L’API publique python-ldap retenue ne fournit pas le chemin nécessaire pour initialiser le TLS implicite LDAPS de façon qualifiée sur ce même descripteur. `ldaps://` est donc refusé à la normalisation, avant connexion ou émission de secret ; aucun contournement ctypes, seconde connexion de contrôle ou repli non chiffré n’est utilisé. Les fixtures des tests indépendants utilisent désormais `ldap://…:389`. LDAPS ne fait pas partie du périmètre qualifié.

Les champs exportés doivent distinguer inventaire, correspondance proposée ou acceptée, droit local et exécution distante confirmée. Les sources et filtres restent visibles même quand les mêmes identifiants distants apparaissent ailleurs. Une signature locale authentifie l’acceptation par PamOlive, pas l’origine externe de chaque assertion.

## Préparation P2, hors garantie P1-F

L’image actuelle sépare les UID de l’application et du moteur natif ; Django peut encore déchiffrer les secrets techniques avec la clé applicative. Cette limite existante ne doit pas être présentée comme un Vault indépendant.

L’évolution recommandée est un contrat versionné Web/Worker → Broker → Vault/KMS : identités de service authentifiées mutuellement, autorisation par opération, capabilities liées au tenant, au bail, à la destination cryptographique, à la version du credential, au nonce, à l’audience et à une expiration courte. Un flag `approved` transmis par le Web n’est pas une autorité indépendante. Broker et Vault doivent vérifier les garanties P0-3 et le périmètre autorisé ; le broker ne reçoit aucune clé maîtresse et le navigateur PAM aucun credential technique.

Le chemin historique peut être conservé pendant une migration explicitement qualifiée, sans repli automatique vers le déchiffrement legacy lors d’une panne du nouveau Vault. Coffre utilisateur et coffre technique restent des domaines de clés et de permissions distincts. Un serveur qui déchiffre un secret n’est pas zero knowledge. Un témoin installé sur le même hôte Docker ne fournit pas l’indépendance de production attendue entre hôtes.

## Résultats de validation

Première campagne indépendante sur le code en cours : **15 tests SQLite, 0,668 s : 5 réussis, 1 échec, 9 erreurs**. Ces résultats initiaux sont conservés comme preuves de reproduction, pas présentés comme une validation.

L’échec confirme un défaut à la frontière d’émission des credentials : une révocation du module pendant un handshake simulé était détectée au retour de lecture, mais le callback de revalidation avant bind/Authorization n’était pas transmis à l’adaptateur. Le contrôle après I/O ne peut pas annuler une émission déjà survenue. Le backend transmet désormais un callback qui recharge acteur, organisation, modules, activation de source, révision et sceau avant l’authentification. Deux tests indépendants couvrent révocation du module et rotation pendant cette fenêtre. La simulation ne contacte aucun serveur et ne journalise qu’un indicateur d’émission, jamais le credential. Le périmètre d’exécution est borné au laboratoire ; ce défaut devait être fermé avant tout élargissement.

Les neuf erreurs avaient une cause fonctionnelle commune : l’import d’une fixture produisait une identité de transport vide, refusée par `full_clean`. Le modèle et sa migration autorisent explicitement cette absence, sans attribuer d’authentification à une fixture. Le test de provenance maintient cette distinction.

Contre-validation après corrections : **19 tests SQLite en 0,886 s, OK, 2 exclusions PostgreSQL explicites**. Les deux exclusions concernent les contraintes SQL de destination immuable et de rattachement inter-organisation ; elles ne sont pas comptées comme réussites. Ruff est réussi sur le fichier de tests.

Le challenge de tenant Graph a été accepté dans le contrat : la destination déclarée doit être comparée au tenant retourné par une requête authentifiée `/organization`, avant lecture des utilisateurs. Les tests de transport TLS, pagination, referrals et realm mismatch relèvent aussi de la campagne infrastructure indépendante de ces tests de services.

Contre-validation PostgreSQL isolée, rôle de test non superuser : **19/19 tests, 4,587 s, aucune exclusion**, via `run_p1f_tests.py --label redteam`. Les deux scénarios SQL réellement exécutés refusent la réécriture de destination et l’insertion d’un fait rattaché à un run d’une autre organisation. Le journal local est `output/p1-f-redteam.log`, hors dépôt.

Les tests adverses indépendants sont placés dans `tests/test_directory_redteam.py`. Cette campagne ne démontre ni concurrence réelle à plusieurs connexions, ni restauration complète, ni exécution LDAP native : ces qualifications restent distinctes et doivent être consignées par leurs campagnes dédiées.

Extension après normalisation de l’inventaire nullable : **23/23 tests PostgreSQL en 5,304 s, aucune exclusion**, avec le même rôle isolé. Elle vérifie que l’état LDAP inconnu reste `None` en stockage et `unknown` dans l’export, sans désactivation d’un compte local ni création de droit ; que les bearer Graph contenant espace, Unicode ou DEL sont refusés à la configuration ; et que tous les mappings absents se parcourent par pagination bornée, même avant une première collecte. Un passage intermédiaire de 22 tests comptait une erreur de contrat de test : le normaliseur v2 renvoie `DirectoryFailure` pour un UUID dupliqué, au lieu de `ValidationError`. L’assertion a été adaptée à cette exception de domaine, en conservant les vérifications d’absence de run et de fait écrit.

Le test de saturation DNS ne réalise aucune résolution réseau : quatre fonctions simulées restent bloquées après expiration de leurs appelants ; une cinquième est refusée immédiatement, puis les fonctions sont libérées. Les slots ne sont pas rendus disponibles alors que leur résolution continue, évitant une file de tâches non bornée. Ce test ne prétend pas annuler le resolver système lui-même ni qualifier une panne DNS de production.

Le contrôle de taille LDAP intervient après décodage OpenLDAP : le budget de faits conservés ne suffit pas à démontrer un plafond mémoire avant décodage. Cette limite reste à prendre en compte dans l’isolation et la qualification de charge des lecteurs. La lecture paginée doit aussi revalider son autorisation entre les pages ; la vérification finale seule évite un commit mais ne peut annuler les lectures réseau déjà effectuées.

## Revue indépendante des interfaces

La lecture de `directory_views.py`, des routes et des templates a conduit à trois corrections complémentaires : borner les octets effectivement lus même sans Content-Length, traiter un JSON excessivement imbriqué comme une erreur client, et exiger une liste de faits explicite au lieu de convertir toute valeur fausse en snapshot vide. La borne applicative est de 65 536 octets, avant la conservation d’une action pour reprise MFA. Un champ de formulaire dédié applique la même désérialisation stricte aux fixtures HTML, notamment pour les clés JSON dupliquées et les imbrications profondes.

Premier passage indépendant d’interface : **14 tests PostgreSQL en 4,152 s : 12 réussis, 1 échec, 1 erreur**. L’échec confirmait que la liste JSON vide explicite était rejetée par le traitement `empty_values` du champ Django : la correction conserve maintenant `[]` tout en refusant objet, null, false, zéro ou champ absent. L’erreur concernait la fixture de test du tenant B, dont le module Connect avait été activé sans sa dépendance Access ; elle a été corrigée en activant explicitement la dépendance, sans modifier les permissions du produit.

Contre-validation finale : **19/19 tests PostgreSQL en 5,018 s, aucune exclusion**, via `run_p1f_tests.py --label viewsred`. Le journal est `output/p1-f-viewsred.log`, hors dépôt. Le fichier indépendant est `tests/test_directory_views_redteam.py` ; Ruff est réussi.

La campagne vérifie le budget réel sur une requête ASGI sans Content-Length, les deux formats JSON et formulaire HTML, les duplications et imbrications, la reprise MFA sans écriture préalable, le refus des modules désactivés sur HTML/API/export/mutations, le 404 d’une source étrangère après changement de tenant, les actions réservées aux administrateurs, les contrôles masqués pour un lecteur, la rotation sans divulgation, le conflit 409 audité sans mutation de l’original et la protection CSRF. Les réponses d’erreur et formulaires invalides ne reflètent pas les secrets synthétiques soumis. Aucun contrôle du navigateur ou du NAS n’a été réalisé par cette revue.

Après passage explicite des fixtures à StartTLS obligatoire et refus du LDAPS non qualifié, les deux suites indépendantes ont été exécutées ensemble : **42/42 tests PostgreSQL en 11,495 s, aucune exclusion**, journal `output/p1-f-redteam.log`. Cette campagne remplace les anciens résultats séparés comme dernière contre-validation du périmètre, sans les additionner à leurs répétitions.
