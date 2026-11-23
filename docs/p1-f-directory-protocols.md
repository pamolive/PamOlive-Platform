# P1-F — protocoles d'inventaire d'annuaire

Le reader est un adaptateur de lecture, distinct du service de persistance et des opérations SCIM existantes. Il ne crée ni droit local, ni mandat PAM, ni écriture dans un annuaire. Le service d'inventaire scelle destination et justificatif, vérifie organisation/modules/acteur et conserve les observations ; les labels de groupes ne deviennent pas des habilitations effectives.

## Contrat et identités

`normalize_destination(provider, endpoint, certificate_sha256, scope)` construit
hors réseau `pamolive.directory-destination/1`. Le scope LDAP/AD contient
`base_dn` et `bind_dn`. Celui d'Entra contient `tenant_id` et admet l'option
`collect_direct_groups: true` à la création. L'URL canonique, le port, le scope
et l'empreinte SHA256 du certificat feuille forment l'identité de la source.
Un changement de périmètre exige une nouvelle configuration explicite.

`read_directory(..., secret, synthetic=True, before_auth=...)` retourne `ReadResult(records, complete, page_count, synthetic, transport_identity, limitations)`. Les justificatifs sont des dictionnaires stricts : `bind_dn/password` pour LDAP, `token` pour Entra. Le hook interne `before_auth` revalide la source après TLS et avant transmission ; LDAP le rappelle avant chaque page, Graph avant chaque requête. L'I/O ne doit pas garder une transaction PostgreSQL ouverte. Le service revalide encore au moment d'accepter le résultat.

`normalize_directory_records` fournit le contrat de faits v2. `enabled=None` signifie état inconnu ; il n'est jamais converti en désactivation. Le prévisualiseur P1 précédent conserve son contrat strictement booléen. Le LDAP générique lit `entryUUID/uid/memberOf` sans inventer un attribut universel enabled. AD lit `objectGUID` binaire, converti avec l'ordre `bytes_le`, `sAMAccountName/userAccountControl/memberOf`. Aucun DN, login ou e-mail ne remplace l'identifiant stable. Un identifiant dupliqué invalide la lecture.

`complete=True` indique la fin de la pagination demandée sous le principal
lecteur. LDAP sans état de compte connu, appartenance inconnue ou plage AD
incomplète conserve les limitations explicites. Graph reste partiel avec
ou sans les appartenances directes. Les exports des groupes contiennent
uniquement les UUID visibles avec le jeton de lecture, avec les limites
`graph_direct_groups_only` et, le cas échéant, `graph_group_request_budget`
ou `directory_group_limit`. Les indices d'absence restent soumis à revue.
[Microsoft Graph — appartenances directes](https://learn.microsoft.com/graph/api/user-list-memberof?view=graph-rest-1.0)

## Réseau et TLS

La v1 refuse toute exécution `synthetic=False`, les hôtes hors localhost/loopback/`.invalid` et toute adresse résolue non loopback, même présente dans une allowlist. Les fixtures Linux utilisent un FQDN `.invalid`, un certificat éphémère SAN correspondant et une résolution de test vers leur seule socket loopback. Aucun NAS, AD, Graph ou compte réel n'est qualifié.

La politique d'adresses réutilise le garde SCIM existant sans le modifier. Un pool global de quatre résolveurs avec quatre places, sans file illimitée, borne l'attente DNS par le budget d'opération. Un appel OS bloqué n'est pas tué ; sa place reste occupée jusqu'à terminaison. Les lecteurs suivants sont refusés lorsque toutes les places sont occupées. Le réseau est connecté une seule fois vers l'adresse retenue en conservant le nom de référence TLS.

LDAP utilise `python-ldap==3.4.8` et OpenLDAP, sans implémentation BER maison. Le descripteur TCP déjà connecté est transféré à `ldap.initialize(..., fileno=...)` ; TLS1.2 minimum, CA, hostname/SAN et empreinte feuille sont exigés sur cette même connexion avant le bind. Les referrals et dereferencing d'alias sont désactivés, la trace LDAP reste désactivée et aucun reconnecteur automatique n'est utilisé. Le client n'appelle que StartTLS, bind, recherches paginées et unbind.

**Seul `ldap://` avec StartTLS obligatoire est qualifié. `ldaps://` est refusé par `directory_ldaps_not_qualified` avant réseau ou secret.** L'essai réel a montré que `ldap_init_fd` attache le TCP existant sans installer implicitement TLS ; une recherche RootDSE ne corrige pas cela. Python-ldap3.4.8 n'expose pas l'appel natif nécessaire. Aucun fallback par seconde connexion DNS, accès à un pointeur privé ou ctypes n'a été ajouté. OpenLDAP traite également localhost spécialement dans certains environnements : la fixture utilise un vrai SAN `.invalid`, sans désactiver la validation du nom.

Entra emploie HTTPS standard avec le connecteur TLS épinglé existant, CA/hostname et leaf pin vérifiés avant chaque en-tête Authorization. Le jeton Bearer doit être ASCII visible sans espaces ; les mots de passe LDAP Unicode restent supportés. Une première lecture authentifiée `/v1.0/organization?$select=id` exige exactement le tenant configuré, avant `/v1.0/users`. Un UUID de tenant déclaré seul ne constitue pas cette vérification. Le résultat expose le realm effectivement contrôlé ; le service le compare à la destination scellée. Cette préparation nécessite une permission de lecture de l'organisation à qualifier ultérieurement avec Entra réel.

Le lecteur Entra classe les réponses HTTP d'erreur avant de consommer leur corps. Les `429` et `5xx` restent récupérables. Pour une réponse réussie, il refuse une longueur déclarée supérieure à 1 Mio et applique le même plafond pendant la lecture. Une coupure avant la longueur déclarée est un échec réseau récupérable. [HTTP/1.1, RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3)

Les redirects sont refusés. Un nextLink doit conserver origine, port, chemin users exact, sélection et taille autorisées ; seuls les paramètres de pagination attendus sont permis. Cycles, paramètres dupliqués et changements de scope sont refusés. Aucune donnée d'une page invalide ne doit être acceptée partiellement par le service. Les cookies LDAP, nextLinks et justificatifs ne sont jamais inclus dans `ReadResult` ou dans les codes d'erreur.

## Bornes et limites

La collecte est limitée à 1 000 objets, 20 pages, 100 objets demandés par page et 32 groupes par compte. Le budget réseau de 45 s fixe le délai restant avant chaque opération réseau, plafonné à 8 s par attente. Le lecteur Entra le recalcule séparément avant TCP et TLS puis à chaque lecture sous-jacente du flux HTTPS, y compris pendant l'analyse des en-têtes et des trailers par `http.client`. Le résultat est contrôlé de nouveau après le décodage. L'inventaire décodé est limité à 4 Mio. Un dépassement produit une collecte incomplète ou un refus explicite, sans preuve d'absence.

La limite LDAP de4Mio s'applique **après décodage d'une page par OpenLDAP** : elle n'est pas une borne dure de mémoire contre une réponse native malveillante. Les limites de processus/conteneur et la future isolation du reader restent nécessaires. Les range AD non terminaux et membres tronqués restent incomplets ; cette v1 ne récupère pas tous les ranges ni tokenGroups. Une lecture sous ACL restreintes n'est pas un audit exhaustif d'AD.

Le lock [requirements-directory.lock](../requirements-directory.lock) et l'[image de tests isolée](../deploy/Dockerfile.directory-test) qualifient la dépendance native Linux. Le Dockerfile applicatif dispose d'un stage de compilation des wheels, puis des seules bibliothèques LDAP/SASL dans le runtime ; le lock principal installe python-ldap sous Linux. Sans cette bibliothèque ou les fonctions fd/TLS requises, le lecteur refuse l'opération. Sous Windows, cette dépendance native reste optionnelle et les tests simulés ne remplacent pas les essais OpenLDAP réels. La validation du build applicatif demeure distincte de celle de l'image de tests.

## Preuves de validation

Les tests `tests.test_directory_adapters` couvrent HTTPS réel loopback, realm tenant contradictoire, pin/CA incorrects, révocation avant émission, nextLinks malveillants, doublons, cycles, quotas, DNS borné, nullable v2 et ordre LDAP simulé. Le contrat P1 du prévisualiseur est conservé.

Le premier essai Linux a échoué sur localhost/SAN et sur LDAPS/fd ; il n'est pas compté comme succès. Après correction, **39 tests en11,206s, OK sans exclusion** ont exécuté les33 tests d'adaptateurs et les6 gates OpenLDAP réelles dans un conteneur Linux amd64 dédié, réseau none, CPU1/RAM1Gio. Les gates comprennent StartTLS réel avec UUID stable, mauvais pin/CA/hostname et révocation sans bind, et refus explicite de LDAPS ; elles ne prouvent pas un transport LDAPS fonctionnel.

Ce passage utilise l'image native de tests puis une copie contrôlée des fichiers corrigés dans le conteneur jetable, pas une image de production reconstruite ou promue. Le journal local est `output/p1-f-directory-wire-final.log` hors dépôt. Les empreintes des sources et la qualification de l'image finale/CI doivent compléter cette preuve avant publication. Aucun AD Windows, fournisseur Entra, SSO ou provisioning réel n'a été contacté.

Un build local distinct du target `production` a ensuite réussi avec le stage de wheels et les seules bibliothèques natives dans le runtime. Dans cette image Linux amd64, import `ldap==3.4.8`, disponibilité de `initialize_fd` et `pip check` ont réussi ; gcc/g++/cc/make/pkg-config et les wheels intermédiaires sont absents. La sonde tournait en réseau none et rootfs readonly. Il s'agit d'un snapshot contrôlé du working tree, pas du futur commit main qualifié. Le manifeste d'archive et les empreintes sont conservés hors dépôt dans `output/p1-f-production-qualification.json`. Cette sonde n'est pas un test de démarrage complet Web/worker/PAM ; la CI du SHA livré doit encore le vérifier.

Portabilité de la fixture : un premier run Ubuntu CI a refusé le démarrage des six serveurs synthétiques, sans qualifier ces gates. Le cas publié par Ubuntu [bug2156801](https://lists.ubuntu.com/archives/foundations-bugs/2026-July/550853.html) décrit un refus AppArmor sur les fichiers hérités sous `/tmp`, tandis que `/var/tmp` possède déjà les droits du profil. La fixture Linux utilise donc un répertoire privé0700 neuf sous `/var/tmp`, sans changer le profil ni désactiver AppArmor. Les erreurs de démarrage exposent seulement une catégorie fixe et un code de sortie, jamais les logs privés. Après cette modification, **41/41 tests Linux en10,176s** et **6/6 gates wire sous UID1000 en5,307s**, réseau none, ont réussi localement. Cela ne prouve pas encore la cause exacte du runner Ubuntu : la nouvelle CI doit confirmer ou réfuter l'hypothèse. Aucun test ni garde n'a été ignoré pour contourner ce refus.

Sources primaires consultées : [python-ldap3.4.8](https://pypi.org/project/python-ldap/), [API fd et TLS](https://python-ldap.org/en/latest/reference/ldap.html), [initialisation OpenLDAP](https://github.com/openldap/openldap/blob/OPENLDAP_REL_ENG_2_6/libraries/libldap/open.c), [binding Python natif](https://github.com/python-ldap/python-ldap/blob/python-ldap-3.4.8/Modules/LDAPObject.c), [pagination Graph](https://learn.microsoft.com/en-us/graph/paging).
