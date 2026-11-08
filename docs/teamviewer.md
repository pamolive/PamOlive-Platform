# Collecte des rapports TeamViewer

Le module Connecteurs lit les rapports de sessions TeamViewer terminées et conserve leurs preuves source par organisation. Il fonctionne dans le conteneur applicatif existant : aucun worker Compose, Redis ou conteneur TeamViewer supplémentaire n’est nécessaire.

Ce parcours livre la collecte brute et sa consultation. Les correspondances avec les comptes, intervenants et ressources PAM-olive, puis la normalisation en événements corrélés, restent à implémenter. Les rapports ne constituent pas des captures vidéo de sessions.

## Préparer la destination et le jeton

L’exploitant autorise exactement `webapi.teamviewer.com:443` dans `PAMOLIVE_CONNECTOR_HOSTS`, en conservant les autres destinations nécessaires aux connecteurs existants. La destination de l’API n’est pas modifiable depuis le formulaire. Les redirections HTTP et les adresses non autorisées sont refusées ; TLS reste vérifié. La réponse est limitée à 2 Mio et son attente à 12 secondes après établissement de la connexion TLS. La résolution DNS dépend du résolveur du déploiement ; cette limite n’est pas un délai global DNS et connexion.

Le jeton doit permettre la lecture des rapports de connexions, avec les droits minimaux nécessaires au périmètre choisi. Vérifier les possibilités et la visibilité de ce jeton dans l’offre TeamViewer utilisée. Le configurer depuis une instance PAM-olive en HTTPS ; ne pas le transmettre par messagerie ou l’inscrire dans Git. Le test constate une lecture autorisée, pas la visibilité de toutes les sessions de l’entreprise.

## Configurer depuis l’interface

1. Activer **Connecteurs** pour l’organisation concernée et utiliser son rôle administrateur.
2. Ouvrir **Connecteurs → Collecte TeamViewer → Nouveau collecteur**.
3. Saisir le nom, le jeton et la première date de fin de session à collecter, avec fuseau et secondes entières, par exemple `2026-11-01T00:00:00Z`.
4. Laisser les notes désactivées sauf besoin explicite : elles peuvent contenir des informations personnelles ou métier.
5. Choisir **Tester la connexion avant d’enregistrer**. Le test lit une page dans une fenêtre récente ; il ne crée ni collecteur ni rapport et ne modifie pas une configuration existante.
6. Après succès, choisir **Enregistrer cette configuration testée — inactive**. Le brouillon chiffré est valable 15 minutes et lié au compte, à l’organisation, au navigateur et à la révision testée. Modifier des champs dans une requête d’enregistrement ne modifie pas cette configuration testée.
7. Activer séparément la collecte avec une MFA personnelle récente. Le test doit dater de moins d’une heure.
8. Examiner les passages et les rapports conservés. La consultation détaillée demande également une MFA récente ; le jeton n’est jamais affiché.

Une modification exige un nouveau test et remet le collecteur inactif. Un jeton laissé vide lors du test d’une configuration existante conserve le secret enregistré. Un échec de test ne modifie pas le collecteur en service. Pour interrompre les passages, utiliser **Désactiver** ; les preuves historiques restent conservées.

## Fenêtres et reprises de collecte

L’API est interrogée en lecture seule sur `GET /api/v1/reports/connections`. Le paramètre `from_date` filtre le début des sessions : le collecteur l’omet pour conserver une session longue ayant commencé avant la fenêtre. Il fige `to_date`, parcourt les pages par `offset_id` et applique localement la borne de fin minimale. Le contrat est décrit dans la [documentation officielle TeamViewer](https://webapi.teamviewer.com/api/v1/docs/index) et le [client officiel TeamViewerPS](https://github.com/teamviewer/TeamViewerPS/blob/a15ec4e55af7d17ce338aa9b4dbcce4db9e81eeb/Cmdlets/Public/Get-TeamViewerConnectionReport.ps1).

Chaque tâche traite une page au maximum, jusqu’à 1 000 rapports. Le curseur, la borne supérieure et le dernier horodatage sont conservés et signés en base. Une interruption du processus reprend le même parcours après expiration du bail de 90 secondes. Les verrous PostgreSQL et le jeton de tentative empêchent un ancien traitement de finaliser une nouvelle tentative.

Après un parcours terminé, le passage suivant commence cinq minutes plus tard et reparcourt l’historique depuis la date configurée. Ce choix permet de revoir les corrections de notes et les rapports apparus tardivement. Un historique volumineux allonge le cycle et doit être dimensionné avant exploitation ; il n’y a pas de promesse de fraîcheur de cinq minutes. L’API ne fournit pas ici une preuve de snapshot immuable entre pages.

Les erreurs transitoires, dont HTTP 429, libèrent le bail et prévoient une reprise après une minute avec le même curseur. Une erreur permanente suspend le collecteur. Les boucles de curseurs, réponses invalides ou preuves locales altérées ne sont pas traitées comme une fin de collecte réussie. Une désactivation, un changement de configuration ou une perte d’autorisation du module pendant une lecture font écarter le résultat sans importer ses rapports.

## Preuves et interprétation

Chaque version sémantique d’un rapport conserve l’identifiant source, les références de compte et de machine, le début, la fin, la réception et sa signature. Les notes sont chiffrées seulement si leur collecte est activée. Une relecture identique est dédupliquée ; une correction crée une nouvelle version. Lorsque les notes sont désactivées, une modification des seules notes ne crée pas une nouvelle preuve.

Les passages disposent d’un manifeste signé des rapports, relié à l’audit chaîné. PostgreSQL refuse les modifications et suppressions des rapports et passages ; le périmètre d’un collecteur ne peut pas être déplacé vers une autre organisation. La qualification de restauration vérifie hors ligne les secrets et preuves, y compris ceux des collecteurs inactifs, sans contacter TeamViewer.

Les limites d’interprétation sont importantes :

- `userid` reste une référence de compte source, pas une preuve de l’identité humaine intervenante. Un propriétaire de compte ou de machine n’est pas automatiquement l’acteur.
- Les identifiants inconnus restent conservés pour un rattachement ultérieur ; ils ne créent aucune identité IAM.
- Une note est une déclaration de la source, pas un ticket vérifié, une approbation ou une preuve de privilèges Windows.
- L’état `complete` signifie seulement que la pagination de la fenêtre est terminée. Il ne déclare pas une couverture complète de l’organisation.
- L’interface montre les 100 derniers passages et les 100 dernières versions de rapports, sans purge automatique des preuves.

Les tests incluent un serveur HTTPS éphémère et le parcours formulaire avec CSRF, MFA, activation et tâche de collecte. La qualification d’un compte TeamViewer réel et de son périmètre de visibilité reste une étape d’intégration distincte.
