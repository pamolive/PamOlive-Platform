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

Une intention propose trois suites : observation, attribution temporaire d’un droit IAM, ou autorisation de session privilégiée. Le choix IAM exige un compte et un droit précis. L’approbation par une autre personne crée un droit daté et une opération d’ajout au groupe correspondant. À l’échéance, le droit local est révoqué et une opération de retrait est créée. Sans correspondance, l’état reste « à configurer ».

La recertification et le départ utilisent cette même file. Le départ demande la désactivation des comptes reliés et le retrait des droits correspondants. Une opération sans compte lié reste manuelle ; elle ne provoque pas la désactivation d’un autre compte par supposition.

## Garanties d’exécution et limites

- L’opération est créée dans la même transaction que la décision locale, avec une clé d’idempotence par objet, état et révision.
- Plusieurs workers coordonnent leurs prises de travail dans PostgreSQL. Un seul bail par compte permet un envoi à la fois. Les appels réseau n’immobilisent pas la transaction de décision.
- Avant un PATCH, le worker revalide son bail, la configuration et l’état souhaité. Les retraits tiennent compte des droits locaux se projetant sur un même groupe distant : un droit encore actif peut maintenir cette appartenance.
- Chaque écriture est suivie d’une lecture. Une réponse PATCH positive seule ne vaut pas confirmation. Les groupes doivent renvoyer un tableau `members`, même vide ; un attribut absent reste insuffisant pour conclure.
- Une reprise après panne relit l’état cible avant d’écrire. Les délais d’erreur réseau et les reprises sont bornés ; les erreurs de configuration ou d’autorisation demandent une intervention.
- L’exécution est asynchrone et converge vers l’état souhaité. Elle n’est pas une transaction distribuée « exactement une fois » avec le fournisseur. Une coupure après envoi peut avoir produit un effet distant ; la reprise et la relecture servent à le vérifier.
- Un résultat d’un ancien bail n’écrase pas le traitement courant. Les observations et décisions sont conservées comme preuves séparées et auditées.

Le worker n’effectue aucune création initiale de compte dans cette version. Il sait désactiver un utilisateur existant (`active=false`) et ajouter/retirer une appartenance à un groupe existant. Les connecteurs spécifiques, la réconciliation périodique des dérives et les scénarios de création font partie de la suite.

## Vérification

`python manage.py test tests.test_provisioning` lance un vrai serveur SCIM HTTPS éphémère dans le processus de tests : certificat, authentification, lectures et PATCH réels. Le scénario vérifie l’approbation, la recertification, le départ, l’expiration, les pannes, la reprise sans seconde écriture et les limites réseau. Les tests PostgreSQL vérifient également les prises concurrentes, les relations inter-organisations et l’immutabilité des preuves.

Références de protocole : [RFC 7644, opérations PATCH](https://www.rfc-editor.org/rfc/rfc7644.html#section-3.5.2) et [RFC 7643, schéma utilisateur](https://www.rfc-editor.org/rfc/rfc7643.html#section-4.1.1).
