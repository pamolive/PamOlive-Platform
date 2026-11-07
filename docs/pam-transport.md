# Transport PAM : périmètre, exploitation et preuves

Le module PAM comprend une autorisation temporaire et un relais SSH utilisable depuis le navigateur. **Un bail seul n’est pas une connexion.** RDP est compilé et sa sonde d’identité existe, mais son activation reste refusée tant que le parcours natif complet, NLA et les scénarios de redirection malveillante ne sont pas qualifiés. Il n’existe pas de commutateur d’environnement pour contourner cette porte.

## Parcours administrateur puis opérateur

1. Autoriser côté déploiement un couple exact `hôte:port` dans `PAMOLIVE_TARGET_HOSTS` et son réseau dans `PAMOLIVE_TARGET_NETWORKS`. Préférer une IP `/32` ou `/128`. Les deux listes sont obligatoires ; elles sont vides initialement. Les destinations de métadonnées, link-local, multicast et les contournements IPv4-mappés sont refusés.
2. Activer PAM pour l’organisation. Créer une identité, une ressource serveur/appareil/cloud et son compte externe de type privilégié. Le compte du portail reste un autre objet.
3. Dans **Accès privilégiés → Cibles**, configurer le DNS/IP, le port, la clé publique SSH d’hôte attendue obtenue par un canal indépendant et le secret distant. Une clé privée SSH peut être fournie ; sa phrase de déverrouillage n’est utilisée qu’à l’import. Les secrets sont chiffrés en base et ne sont jamais réaffichés dans le formulaire.
4. Enregistrer la cible inactive, tester l’identité réseau puis l’activer dans les 15 minutes suivant ce test. Le test vérifie la clé d’hôte avant toute authentification, **pas la validité du mot de passe ou de la clé de compte**. Chaque modification invalide le test et désactive la cible.
5. L’opérateur crée une intention avec suite **PAM**, méthode SSH, identité, compte, ressource, motif, référence et fenêtre. Des approbateurs distincts valident selon la politique applicable. Une intention destinée seulement à l’observation ne permet pas d’ouvrir le relais.
6. L’opérateur ouvre l’intention approuvée après MFA récente personnelle. Un ticket de 30 secondes, à usage unique, est lié à son compte technique, son organisation, sa session navigateur, son adresse d’origine, sa cible et son périmètre approuvé. Il est envoyé dans le premier message WebSocket, jamais dans une URL.
7. Le serveur vérifie à nouveau l’autorisation et l’identité de la cible, épingle l’IP résolue puis injecte les identifiants dans le moteur local. Le navigateur ne reçoit ni secret distant, ni arguments de connexion, ni identifiant permettant de rejoindre une connexion native.

L’interface ne donne pas accès au presse-papiers, aux fichiers, à SFTP, à l’agent SSH, aux lecteurs, à l’impression ni à l’audio. Seuls clavier, souris et commandes d’affichage bornées sont autorisés. Les flux de paramètres natifs sont supprimés avant transmission **et avant capture**.

## MFA, expiration et révocation

La fraîcheur MFA est personnelle : 2, 5, 10 ou 15 minutes. Elle est exigée pour une nouvelle ouverture ou la consultation d’une capture. **Son expiration ne déclenche jamais de challenge au milieu d’une session SSH/RDP.** Fermer son propre relais ne demande pas de MFA.

L’autorisation reste toutefois contrôlée environ chaque seconde : session navigateur encore valide, rôle, organisation/module actifs, compte et identité actifs, intention, votes, contrat, fenêtre et révision de cible. Une impossibilité de vérifier ces éléments ferme le transport. Les appels de vérification sont bornés ; le contrôle n’est pas une garantie de coupure à la milliseconde. Déconnexion du portail, retrait de rôle, départ, expiration, désactivation de cible ou fermeture demandée font perdre l’autorisation.

Une coupure de relais n’atteste pas un logoff Windows, l’arrêt d’un processus distant ou le retrait d’un droit directement sur un autre système. L’audit dit « relais ouvert, authentification distante non attestée » : un affichage natif ne constitue pas à lui seul une preuve d’authentification de l’OS.

Limites actuelles : 4 relais simultanés par compte technique, 16 par organisation ; durée plafonnée à 4 heures et toujours limitée par l’intention/bail. L’admission WebSocket est bornée à 10 tentatives par compte sur 5 minutes ; les entrées ont des limites de débit, taille et opcodes. Les valeurs ne sont pas encore des champs de politique modifiables dans l’interface.

## HTTPS, proxy et origine réelle

En exploitation, utiliser HTTPS, `SECURE_COOKIES=true`, `DEBUG=false`, un `ALLOWED_HOSTS` précis et l’origine exacte dans `CSRF_TRUSTED_ORIGINS`. Le proxy doit prendre en charge WebSocket sur `/ws/pam/` et conserver le `Host` public.

Si le proxy termine TLS, définir `PAMOLIVE_PUBLIC_ORIGIN=https://pamolive.example.com`. Autoriser uniquement ses IP dans `PAMOLIVE_TRUSTED_PROXY_NETWORKS`. Ce dernier proxy doit **écraser**, non concaténer, `X-Forwarded-For` avec une seule adresse cliente et définir `X-Forwarded-Proto`. Les en-têtes fournis par un client direct non approuvé sont ignorés. Une chaîne ambiguë est refusée. Le port doit être conservé dans l’origine lorsqu’il n’est pas standard.

`PAMOLIVE_NETWORK_CONTEXT` peut associer des CIDR à un lieu/pays vérifié par l’exploitant. Le préfixe le plus précis gagne. Sans correspondance, l’IP est connue mais le pays reste inconnu ; le lieu ou pays déclaré dans une intention n’est jamais réutilisé comme preuve de l’origine du client. Cet inventaire n’est pas une géolocalisation automatique.

## Captures, accès et conservation

L’enregistrement est le **flux d’affichage Guacamole**, pas du MP4 et pas un journal de frappes brutes. Un mot de passe ou une donnée affichés dans le terminal peuvent néanmoins figurer dans la capture. Le contenu est donc sensible.

Les blocs sont chiffrés, chaînés par HMAC et enregistrés dans PostgreSQL **avant** de transmettre l’affichage au navigateur. Une erreur d’écriture ou un dépassement de quota coupe le relais. Limites : 64 Mio de contenu clair par relais et 1 Gio par organisation, sans purge automatique. Les octets chiffrés, index et sauvegardes consomment davantage d’espace. Surveiller la base ; une politique de rétention/purge contrôlée reste à concevoir.

La fin est scellée dans l’audit append-only avec le nombre de blocs, la taille, la chaîne et le périmètre figé. Les écritures/mutations de blocs et les références inter-organisations sont protégées aussi par PostgreSQL. Cela détecte une altération en base sans les clés applicatives ; ce n’est pas une preuve inviolable face à un administrateur qui contrôle l’hôte et ces clés.

Après fermeture, le détenteur de la session, ou un administrateur/auditeur de son organisation, peut consulter la capture après MFA. Le droit de lecture est lié à la session navigateur pendant 10 minutes et revérifié par lots ; les réponses ne sont pas mises en cache. Le lecteur charge la capture bornée puis la rejoue localement. Une capture partielle est explicitement signalée. Une perte de processus ne la transforme jamais en capture complète.

Sauvegarder **la base et la clé `PAMOLIVE_ENCRYPTION_KEY`** (ou `SECRET_KEY` si aucune clé séparée n’a été configurée). Les perdre rend secrets et captures illisibles. Ne pas changer la clé sans procédure de ré-encryption ; ne pas la publier dans GitHub. Une rotation automatisée, un stockage WORM externe et un export MP4 ne sont pas encore livrés.

## Vérifications de livraison

Les tests de service couvrent l’isolation organisationnelle, le nonce, les rôles/sessions, l’expiration, les révisions, le chiffrement, les quotas, les chaînes et les captures orphelines. La CI exécute PostgreSQL et l’image Linux réelle. `tests.test_pam_relay_e2e` traverse le formulaire, le WebSocket, le moteur natif et un serveur SSH éphémère sans shell système : clavier aller-retour, absence de rechallenge MFA, déconnexion du portail, expiration du bail, désactivation de cible, entrée interdite, dépassement de quota, authentification par clé Ed25519 et relecture des blocs. Les scénarios vérifient la fermeture réellement constatée côté serveur SSH. L’import d’une clé OpenSSH protégée par phrase secrète est testé séparément. `deploy.check_runtime` vérifie les UID, les capacités et l’absence de secrets applicatifs dans l’environnement natif.

Ces preuves ne valent pas qualification de charge, compatibilité de tous les serveurs SSH, HA des sessions ni qualification RDP. Les cibles restent refusées tant que leurs listes de déploiement et leur vérification explicite n’ont pas été configurées.
