# Provisioning et confirmation des effets externes

Le module Connecteurs possède désormais un client SCIM 2.0 et une file durable dans PostgreSQL. Le traitement s’exécute dans le conteneur applicatif existant, sans conteneur supplémentaire. La cible doit déjà exposer une API SCIM ; ce client ne transforme pas LDAP ou Microsoft Graph en serveur SCIM.

## Configuration sans interruption

1. L’exploitant autorise les destinations au niveau du déploiement.
2. Dans **Connecteurs → Exécution externe**, créer une configuration inactive avec son URL HTTPS et son jeton.
3. **Tester la connexion** effectue uniquement des lectures : `ServiceProviderConfig` et une liste d’utilisateurs. Il vérifie l’authentification de lecture et la capacité PATCH annoncée ; il n’écrit pas un compte réel pour tester les droits d’écriture.
4. Activer la configuration testée, puis relier chaque compte local à son identifiant utilisateur SCIM et chaque droit local à un groupe SCIM.
5. Les nouvelles attributions, révocations, recertifications et départs créent des opérations traçables. Une opération déjà bloquée ou sans correspondance nécessite une relance explicite après configuration.

Modifier l’URL ou le jeton désactive la configuration et exige un nouveau test. Tester une configuration déjà active ne la désactive pas en cas de panne transitoire. Aucun mot de passe de compte cible n’est requis ; le jeton de provisioning est chiffré avec la clé de l’installation et n’est jamais renvoyé dans les formulaires de consultation.

## Politique de sortie

Dans `.env`, utiliser des hôtes et ports exacts, sans wildcard :

```dotenv
PAMOLIVE_CONNECTOR_HOSTS=scim.example.net:443,annuaire.example.net:8443
# Pour des adresses privées autorisées explicitement par l’exploitant :
PAMOLIVE_CONNECTOR_NETWORKS=10.42.5.0/24
# Facultatif : autorité de certification d’entreprise montée en lecture seule.
PAMOLIVE_CONNECTOR_CA_BUNDLE=/run/certificates/enterprise-ca.pem
```

Le conteneur doit être recréé pour prendre ces paramètres en compte. Le certificat TLS et le nom de serveur sont vérifiés. Les IP sont validées puis utilisées directement par la connexion TLS, avec le nom original conservé pour SNI. Une nouvelle résolution est effectuée pour chaque requête, sans seconde résolution pendant la connexion. Les adresses privées ou de boucle locale nécessitent un réseau explicitement autorisé ; les adresses link-local, de métadonnées et multicast restent interdites. Les redirections HTTP ne sont pas suivies et les proxies d’environnement ne sont pas utilisés.

L’URL ne contient ni identifiants ni paramètres arbitraires. Les chemins de requête et opérations PATCH sont construits par le client ; l’interface ne peut pas envoyer une commande HTTP libre.

## Parcours approbation → attribution → expiration

Une intention propose trois suites : observation, attribution temporaire d’un droit IAM, ou autorisation de session privilégiée. Le choix IAM exige un compte et un droit précis. Lorsque le seuil d’approbation et la condition du responsable du contrat sont satisfaits, la décision crée un droit daté et une opération d’ajout au groupe correspondant. Une attribution future n’est envoyée qu’au début de sa fenêtre ; une opération relancée ne peut pas avancer cette date. À l’échéance, le droit local est révoqué et une opération de retrait est créée. Sans correspondance, l’état reste « à configurer ».

La recertification et le départ utilisent cette même file. Le départ demande la désactivation des comptes reliés et le retrait des droits correspondants. Une opération sans compte lié reste manuelle ; elle ne provoque pas la désactivation d’un autre compte par supposition.

Le retrait d’un contrat ou d’un intervenant utilise également cette file. Il révoque les droits liés au contrat et conserve les autres droits. Une désactivation globale du compte n’est demandée que si celui-ci a été explicitement déclaré dédié à ce contrat. Une révision plus restrictive est réconciliée par le processus de tâches. Ces contrôles continuent même si l’interface du module Contrats et politiques est désactivée.

## Garanties d’exécution et limites

- L’opération est créée dans la même transaction que la décision locale, avec une clé d’idempotence par objet, état et révision.
- Plusieurs workers coordonnent leurs prises de travail dans PostgreSQL. Un seul bail par compte permet un envoi à la fois. Les appels réseau n’immobilisent pas la transaction de décision.
- Avant un PATCH, le worker revalide son bail, la configuration et l’état souhaité. Les retraits tiennent compte des droits locaux se projetant sur un même groupe distant : un droit encore actif peut maintenir cette appartenance.
- Chaque écriture est suivie d’une lecture. Une réponse PATCH positive seule ne vaut pas confirmation. Les groupes doivent renvoyer un tableau `members`, même vide ; un attribut absent reste insuffisant pour conclure.
- Une reprise après panne relit l’état cible avant d’écrire. Les délais d’erreur réseau et les reprises sont bornés ; les erreurs de configuration ou d’autorisation demandent une intervention.
- L’exécution est asynchrone et converge vers l’état souhaité. Elle n’est pas une transaction distribuée « exactement une fois » avec le fournisseur. Une coupure après envoi peut avoir produit un effet distant ; la reprise et la relecture servent à le vérifier.
- Un résultat d’un ancien bail n’écrase pas le traitement courant. Les observations et décisions sont conservées comme preuves séparées et auditées.

Le worker peut aussi créer un compte initial selon le parcours ci-dessous. Les groupes doivent déjà exister ; la synchronisation complète d’inventaire et les extensions propres à chaque fournisseur restent distinctes.

## Création initiale et activation

Dans **Connecteurs → Exécution externe → Créer un compte SCIM**, un administrateur prépare le compte d’une intention IAM déjà approuvée et actuellement valable. Le compte local, son identité bénéficiaire et son droit doivent correspondre exactement à cette intention. Le groupe distant associé au droit doit être configuré au préalable. La demande ne crée ni nouveau droit local ni nouvelle approbation.

1. Choisir l’intention et le connecteur testé et actif. L’identifiant distant reprend celui du compte local.
2. **Vérifier la destination et prévisualiser** vérifie les capacités de lecture, de filtrage et de PATCH et recherche un nom existant. Ce contrôle ne crée aucun utilisateur et ne prouve pas le droit d’écriture du jeton. Un nom existant demande une vérification puis une correspondance manuelle ; il n’est jamais adopté automatiquement.
3. Examiner le périmètre et les droits implicites du fournisseur, puis confirmer avec une MFA personnelle récente. Le compte sera d’abord créé avec `active=false`, sans mot de passe, groupe ou rôle injecté dans la requête de création.
4. L’option **Activer après confirmation du droit approuvé** reste décochée par défaut. Si elle est choisie, le worker relie uniquement le droit déjà approuvé, confirme l’appartenance sur la cible, la relit avant l’activation puis confirme `active=true`. Sans cette option, la préparation s’arrête au compte désactivé ; aucune attribution n’est envoyée par ce parcours.

Le traitement utilise le processus de tâches et la base existants. L’autorisation conserve le périmètre de l’intention, la configuration exacte du connecteur, l’identifiant, le groupe et la preuve MFA personnelle. Ces éléments sont signés et liés à l’audit. Une modification du périmètre, une révocation ou une configuration différente interdit une nouvelle écriture positive. La validation personnelle n’est pas redemandée dans le worker.

### Résultats incertains et doublons

Avant l’envoi, PostgreSQL conserve une réservation append-only unique de la commande `POST /Users`. Une fois cette réservation créée, ce travail ne peut plus envoyer de second POST, même si le fournisseur répond `503`, si la réponse est perdue ou si l’instance tombe avant l’envoi réel. Il ne s’agit pas d’une garantie de livraison exactement une fois : une réservation peut ne jamais atteindre la cible.

Les reprises recherchent uniquement la référence technique unique de la demande et le nom attendu, puis relisent l’utilisateur par son identifiant serveur. Les deux recherches doivent être complètes, uniques et concordantes, et la relecture doit confirmer le compte désactivé. Une liste partielle, un autre propriétaire, une réponse JSON ambiguë ou un fournisseur ignorant `active=false` ne produit aucune confirmation. Après cinq traitements sans conclusion, l’état reste à examiner. **Réexaminer sans second POST** permet de nouvelles lectures, jamais une nouvelle création réservée. Une configuration de destination modifiée exige une investigation manuelle.

Le détail et l’export JSON distinguent l’autorisation, la réservation, la confirmation historique du compte désactivé et l’état courant du travail. La preuve historique ne garantit pas l’état actuel du fournisseur. Les preuves sont conservées lors des corrections et leur lecture nécessite une MFA personnelle récente.

### Retrait des droits et départ

L’expiration du droit retire l’appartenance approuvée ; elle ne désactive pas nécessairement le compte de base, qui possède son propre cycle de vie. Les droits implicites attribués par le fournisseur doivent donc être examinés avant activation. Le départ de l’identité désactive le compte et retire ses droits via la file existante. Si le départ arrive avant la confirmation de la création, les retraits déjà demandés sont reliés à la nouvelle correspondance pour être confirmés sur la cible, sans réactiver le compte.

Création, attribution, activation et révocation ne constituent pas une transaction distribuée. Une révocation intervenant pendant un appel externe peut nécessiter un traitement compensatoire ultérieur ; l’interface distingue la demande locale de l’effet distant confirmé. Aucun mot de passe cible n’est généré ou envoyé par ce parcours.

La dernière vérification du bail et de l’autorisation intervient après résolution DNS et négociation TLS, avant l’envoi HTTP. Un résultat positif tardif d’un ancien bail reste dans l’historique sans écraser le travail courant. Si ce résultat réintroduit une appartenance révoquée ou réactive un compte localement désactivé, une nouvelle relecture et un retrait sont demandés à périmètre cible inchangé. Un changement de destination ou de correspondance demande une investigation, sans retrait automatique sur une cible différente.

## Vérification

`python manage.py test tests.test_provisioning tests.test_scim_creation` utilise des serveurs SCIM HTTPS éphémères : certificat, authentification, lectures, création et PATCH réels. Les scénarios couvrent approbation, création désactivée, activation, recertification, départ, expiration, réponse perdue, préexistence, données ambiguës et limites réseau. Les tests PostgreSQL vérifient les prises concurrentes, la réservation unique, les relations organisationnelles et l’immutabilité des preuves. Ces pairs ne certifient pas un fournisseur commercial.

Références de protocole : [RFC 7644, création](https://www.rfc-editor.org/rfc/rfc7644.html#section-3.3), [opérations PATCH](https://www.rfc-editor.org/rfc/rfc7644.html#section-3.5.2) et [RFC 7643, schéma utilisateur](https://www.rfc-editor.org/rfc/rfc7643.html#section-4.1.1).
