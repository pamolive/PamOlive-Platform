# Connexions OIDC par organisation

Le noyau propose plusieurs domaines OpenID Connect par organisation, sans module IAM
obligatoire ni service Docker supplémentaire. OIDC authentifie un **compte de portail** ;
ce n’est ni une identité IAM, ni un compte privilégié de cible, ni un moteur de provisioning.
Une connexion fédérée n’invente jamais une personne, des groupes ou des permissions.

## Préparer le déploiement

Sur Linux, macOS, Windows/PowerShell et NAS Synology, les mêmes variables sont placées dans
le fichier `.env` lu par Compose. La syntaxe reste `NOM=valeur`, sans `export`.

```dotenv
PAMOLIVE_OIDC_PUBLIC_ORIGIN=https://pamolive.example.com
PAMOLIVE_OIDC_HOSTS=idp.example.com:443,login.example.com:443
```

Ces noms sont des exemples, pas les paramètres d’Infomaniak ou d’Entra.
L’origine est l’URL réellement utilisée par les navigateurs, sans chemin.
Elle n’est pas calculée depuis l’IP locale, `Host` ou un en-tête transmis arbitrairement.
Configurer aussi `ALLOWED_HOSTS`, `CSRF_TRUSTED_ORIGINS`, les cookies sécurisés
et le [proxy de confiance](pam-transport.md) lorsque celui-ci termine TLS.

Chaque hôte/port de découverte, autorisation, jetons et JWKS doit être approuvé
explicitement. Les IP publiques sont permises après validation DNS ; les IP privées
exigent aussi `PAMOLIVE_OIDC_NETWORKS` avec des CIDR précis. Les adresses de métadonnées
cloud, link-local et multicast restent interdites. Aucun joker, proxy sortant implicite,
redirection HTTP, URL fournie dans un JWT ou désactivation de TLS n’est accepté.
Un IdP interne peut utiliser une CA approuvée, montée en lecture seule et indiquée
par `PAMOLIVE_OIDC_CA_BUNDLE`. Ne pas mettre sa clé privée dans l’image.

Après modification du `.env`, depuis le dossier d’installation :

```sh
docker compose up -d --build web
```

Conserver les fichiers Compose supplémentaires et le nom de projet utilisés à l’installation
(par exemple `-f deploy/compose.nas.yml` sur le NAS). Ne pas lancer un deuxième projet.
Sur Synology, si Docker n’est pas dans le PATH, utiliser `/usr/local/bin/docker`.
Cette commande ne supprime ni base ni volume. Sauvegarder données et clés avant une mise à niveau.
Sans configuration OIDC, la connexion locale fonctionne.

## Configurer sans couper le service

1. Garder une connexion locale d’administration opérationnelle, avec MFA et codes de récupération.
   Ouvrir **Paramètres → Domaines de connexion OIDC → Nouveau domaine** dans l’organisation voulue.
2. Choisir un identifiant stable, par exemple `infomaniak` ou `entra-infrastructure`.
   Le callback HTTPS exact apparaît dès la saisie, avant le Client ID et le secret.
   Il comprend l’UUID de l’organisation et le slash final ; le copier, ne pas le reconstruire
   depuis un ancien PAM ou une autre installation.
3. Chez le fournisseur, créer un **client confidentiel Web**, autoriser ce callback exact et
   le flux Authorization Code avec PKCE S256. Un token API personnel ne remplace pas ce client.
   Relever son `issuer` exact, son Client ID et son secret. Suivre sa documentation actuelle
   plutôt que choisir un émetteur supposé à partir du nom commercial.
4. Dans PAM-olive, renseigner ces valeurs et la méthode du client acceptée
   (`client_secret_basic` ou `client_secret_post`). Signatures admises : RS256 ou ES256.
   Cliquer **Tester la découverte avant d’enregistrer** : seulement un brouillon
   privé chiffré, lié au navigateur et à son auteur, valable 15 minutes est créé.
5. Cliquer **Tester la connexion complète**. Se connecter et consentir chez le fournisseur.
   Le retour vérifie code, secret, PKCE, signature, issuer, audience et nonce.
   Il n’ouvre aucune session fédérée, ne crée aucun compte et ne change pas la session locale.
6. Cliquer **Enregistrer le domaine testé**, puis **Activer** séparément depuis la liste.
   L’activation exige un test complet de moins d’une heure. Tout changement doit être retesté ;
   un contrat modifié est enregistré inactif et invalide les anciennes sessions.

Le test complet est obligatoire **avant l’enregistrement**. La découverte seule ne suffit pas.
Si le brouillon expire ou le navigateur change, recommencer. Le secret n’est jamais réaffiché.
L’identifiant, l’issuer et le Client ID sont immuables : créer un autre domaine pour les changer.

## Associer un compte puis se connecter

Un administrateur crée d’abord un compte local et son appartenance à l’organisation.
Chaque titulaire configure sa MFA locale, se connecte localement, puis ouvre
**Ma sécurité → Mes connexions fédérées OIDC → Associer**. Après MFA récente et connexion
chez le fournisseur, le `sub` vérifié est associé à **ce titulaire uniquement**.
Un administrateur ne peut pas attribuer arbitrairement un sujet externe à une autre personne.

Ensuite, la page de connexion présente le formulaire local **et** les domaines activés,
avec leurs organisations. Un utilisateur peut avoir des associations dans plusieurs
organisations ; chaque session fédérée reste limitée au domaine et à l’organisation choisis,
même pour un superutilisateur. Se déconnecter pour utiliser une autre autorité.
Les noms des organisations et domaines actifs sont donc visibles publiquement.

La MFA locale configurée reste requise après OIDC. Les claims `amr`, `groups`, `roles`,
`email` ou `email_verified` ne créent aucun droit et ne remplacent pas cette MFA.
Aucune association automatique par e-mail : un homonyme externe ne récupère pas un compte.
Les comptes sans mot de passe local et le provisioning automatique par OIDC ne sont pas proposés.

Les actions sensibles conservent la fenêtre personnelle MFA 2/5/10/15 minutes.
Aucun challenge n’interrompt une session SSH/RDP ouverte. En revanche, désactiver
le domaine, révoquer l’association ou retirer l’appartenance à l’organisation retire
l’autorité de la session fédérée, y compris pour les transports PAM qui en dépendent.
Une session locale indépendante n’est pas supprimée par la désactivation d’un IdP.

## Journaux, sécurité et restauration

Les états sont persistés dans PostgreSQL : deux instances peuvent traiter les deux étapes,
sans état OAuth local au processus. State, navigateur et nonce sont liés, PKCE utilise S256
et un état expire après cinq minutes avec consommation unique.
La MFA finale expire après deux minutes au plus, sans dépasser la validité du parcours.
Des preuves HMAC et des clés étrangères composites conservent le périmètre d’organisation ;
PostgreSQL interdit le réarmement d’un état et le déplacement d’une association.
Ce n’est pas une protection contre un administrateur détenant les clés et capable de réécrire le code.

Les secrets clients et capsules temporaires sont chiffrés. Aucun ID token, access token,
refresh token ou code d’autorisation n’est stocké. Les capsules consommées sont effacées ;
le traitement existant efface par lots les capsules expirées. Les métadonnées des parcours
ne sont pas purgées automatiquement : prévoir une rétention contrôlée.
Les limites sont 100 départs par fournisseur/IP sur cinq minutes et cinq parcours simultanés
par navigateur ; ce n’est pas une qualification de capacité ou une protection DDoS globale.

Les pages OIDC sont `no-store`/`no-referrer`. Les journaux d’accès applicatifs masquent
les paramètres des callbacks. **Configurer aussi proxy, WAF, APM et exports pour ne jamais
journaliser `code`, `state`, secrets ou jetons.** Le noyau ne contrôle pas leurs journaux.
Préserver les clés de chiffrement et de signature : leur perte invalide aussi les preuves OIDC.
La [qualification de restauration](backup-restore.md) les vérifie hors ligne,
même pour un domaine désactivé, sans contacter l’IdP.

## Qualification et limites

```sh
python manage.py test tests.test_oidc tests.test_oidc_tls --noinput
```

Les tests HTTPS utilisent une CA et un IdP éphémères, un vrai échange HTTP de code,
des cookies sécurisés, CSRF, un JWKS et une signature RSA. Le pair vérifie effectivement
callback, secret et challenge PKCE avant de rendre le jeton.
Les tests PostgreSQL vérifient aussi les refus SQL et frontières d’organisation.
Ce n’est ni une certification d’Infomaniak/Google/Entra, ni un test automatisé dans un navigateur
graphique, ni une preuve de bascule de deux VM réelles. Chaque fournisseur doit être essayé
avec sa configuration actuelle avant activation. Logout fédéré, rotation automatique du secret,
groupes OIDC et MFA déléguée à l’IdP ne sont pas implémentés.

Références : [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html),
[validation PyJWT](https://pyjwt.readthedocs.io/en/stable/api.html),
[applications Infomaniak](https://developer.infomaniak.com/getting-started#applications).
