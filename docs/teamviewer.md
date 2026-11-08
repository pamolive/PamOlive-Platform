# Collecte des rapports TeamViewer

Le module Connecteurs lit les rapports de sessions TeamViewer terminées et conserve leurs preuves source par organisation. Il fonctionne dans le conteneur applicatif existant : aucun worker Compose, Redis ou conteneur TeamViewer supplémentaire n’est nécessaire.

Ce parcours relie la collecte brute, les correspondances explicites et les observations regroupées à un événement d’accès et à ses évaluations. Une association administrative n’est pas une preuve d’authentification : la conformité exprime uniquement une concordance avec le périmètre documenté. Les rapports ne sont pas des captures vidéo de sessions.

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

## Associer les identifiants aux objets gouvernés

Les trois associations sont distinctes :

| Identifiant source | Association explicite | Ce qui ne doit pas être supposé |
|---|---|---|
| `userid` | Compte externe dont le système est `TeamViewer` | Ce n’est pas le compte Windows distant |
| `userid` | Identité humaine ou non humaine attestée par l’administrateur | Le propriétaire du compte n’est pas automatiquement l’intervenant |
| `deviceid` | Ressource serveur ou appareil | Son propriétaire, son emplacement et ses privilèges ne sont pas des faits observés |

Créer les objets nécessaires dans IAM, puis ouvrir un rapport et choisir **Publier ou corriger cette association**. Le formulaire reprend l’identifiant exact et la période de la session. Il nécessite le rôle administrateur et une MFA personnelle récente. Renseigner une référence non secrète permettant de vérifier l’affectation ; cette référence administrative ne certifie pas l’authentification TeamViewer et ne vérifie pas un ticket externe.

Une publication concerne le collecteur, sa révision de configuration et une période début inclus, fin exclue. Elle ne change ni le propriétaire du compte, ni le cycle de vie de l’identité, ni ses droits. Une identité inactive peut donc être associée pour l’analyse d’un rapport historique sans être réactivée. Les identités de services et de machines ne sont pas transformées en personnes.

Les observations signées relient chaque version de rapport au passage précis qui l’a lue. Une modification de configuration, y compris du jeton, crée une autre révision : ses identifiants ne réutilisent pas automatiquement les correspondances de la précédente. Le détail permet de sélectionner une observation antérieure et de publier une association pour sa révision source exacte. L’indexation des passages historiques utilise le traitement de tâches existant sans modifier leurs dates ou données.

La publication la plus récente applicable l’emporte sur sa période. Pour corriger une erreur, publier une nouvelle association ; pour retirer une affectation, cocher le retrait et laisser la cible vide. Les attestations et rapports précédents restent conservés. Un retrait débutant aujourd’hui n’efface pas une affectation antérieure ; corriger une attribution historique exige une période portant explicitement sur cette histoire, sans approbation rétroactive d’un accès.

Le détail affiche les périodes et leurs preuves. Une identité n’est attribuée à toute la session que si son association couvre toute la durée. Des cibles différentes ou une couverture partielle restent signalées, sans choix arbitraire du propriétaire du compte. Une résolution complexe est bornée à 64 attestations chevauchantes ; une nouvelle attestation vérifiable couvrant toute la période peut remplacer les précédentes sans les supprimer.

## Regroupement des sessions

Ouvrir **Connecteurs → Collecte TeamViewer → Sessions regroupées**, puis choisir une session. Le détail demande une MFA personnelle récente et affiche les observations source, leurs révisions et les attestations d’affectation. Depuis un rapport déjà indexé, le lien **Examiner la session regroupée et ses autres sources** mène au même dossier.

Le traitement de tâches existant regroupe progressivement les observations par identifiant de session TeamViewer, à l’intérieur d’une organisation. Plusieurs collecteurs, une relecture identique ou une correction de note ne créent pas plusieurs sessions. Chaque observation conserve cependant son propre lien signé vers le dossier ; aucune date de lecture, note ou version source n’est remplacée. Un identifiant identique dans une autre organisation reste un dossier distinct.

Le rapprochement distingue les faits source des associations administratives. Des références de compte ou de machine différentes, ou des horaires différents, constituent un conflit. Une référence absente reste inconnue dans son périmètre, sans être traitée comme la preuve d’un autre compte ou d’une autre machine. Si les versions se contredisent, le dossier les conserve sans désigner automatiquement la bonne. Une correction structurelle n’efface donc pas le conflit antérieur ; son arbitrage reste un parcours à livrer.

Pour chaque dimension — compte opérateur, identité attribuée et machine — toutes les révisions source examinées doivent disposer de correspondances concordantes. Une affectation connue pour un collecteur ne remplit pas celle qui manque chez un autre, ni celle d’une révision utilisant un nouveau jeton. Le propriétaire du compte n’est jamais utilisé pour compléter l’intervenant.

| État du dossier | Interprétation |
|---|---|
| `resolved` | Les trois correspondances concordent sur la période dans chaque périmètre examiné ; cela n’accorde aucun droit et ne signifie pas « accès autorisé » |
| `unresolved` | Les faits source concordent, mais une association manque, est partielle, retirée ou contradictoire ; chaque dimension garde son état propre |
| `pending` | Des observations déjà collectées attendent leur indexation ; les seules anciennes données ne sont pas présentées comme un résultat complet |
| `conflict` | Les versions divergent sur les références source ou les horaires ; aucune attribution consolidée n’est affichée |
| `invalid` ou `limit` | Une preuve n’est pas vérifiable ou la résolution dépasse sa borne ; aucun résultat complet n’est déclaré |

La résolution examine au maximum 64 variantes distinctes de rapport et de révision de configuration. Les relectures identiques ne consomment pas cette borne, même si toutes leurs preuves restent conservées et vérifiées pendant une restauration. L’indexation traite au plus dix observations par passage ; elle n’ajoute ni service Docker ni processus de tâches supplémentaire. La liste montre les 100 derniers dossiers créés, sans purge automatique.

## Expliquer une session sans modifier ses preuves

Depuis le détail d’une session regroupée, choisir **Expliquer cet accès et consulter son historique d’évaluation**. Le traitement existant crée un seul événement `managed:teamviewer` par session de l’organisation, même après plusieurs collecteurs ou relectures. Son début et sa fin proviennent du rapport d’origine ; les autres versions restent liées au dossier. Un désaccord sur ces faits bloque leur interprétation au lieu de désigner silencieusement une version correcte.

L’événement conserve les faits source sans remplir artificiellement les UUID d’identité, de compte ou de ressource locale. Une ressource non résolue reste vide. Sa réception est celle de la version de rapport d’origine ; la date du lien de normalisation est conservée séparément, pour ne pas présenter le temps de traitement comme un retard de la source. L’interprétation vérifie les liens signés, les observations et les attestations datées, puis transmet leurs objets rapprochés au moteur d’accès. Celui-ci compare toute la période aux intentions et droits applicables, avec le cycle de vie, les approbations et les restrictions disponibles.

Par exemple, une attestation associe l’opérateur TeamViewer à Cyriel et la machine à PC-123. Une intention approuvée avant la session prévoit cette personne, ce compte, cette machine, la méthode TeamViewer et la période. L’explication peut rapprocher cette intention et sa référence métier. Si elle exige aussi un privilège Windows « Administrator », que le rapport ne fournit pas, ce champ reste inconnu : il n’est ni recopié de l’intention ni traité comme une valeur différente observée. Une machine différente effectivement identifiée reste en revanche un écart de périmètre connu.

Chaque nouvelle évaluation conserve son contexte, ses témoins et une signature liée à l’audit et aux faits source. Corriger une association ajoute une analyse sans changer l’événement ni l’ancienne conclusion. Le traitement parcourt les dossiers par lots de cinq avec un curseur réinitialisable ; une simple relecture identique ne crée pas une nouvelle analyse si l’interprétation n’a pas changé. Ce parcours ne garantit pas une analyse immédiate d’un historique volumineux. Les changements de politique sans nouvelle interprétation nécessitent une réévaluation explicite.

Le détail, l’export, le graphe et la chronologie distinguent les faits de leur interprétation actuelle. Lorsqu’elle diffère de celle de la dernière analyse, cette conclusion historique n’est pas affichée comme le résultat actuel. Le bouton de réévaluation conserve une nouvelle analyse après les contrôles habituels. Les anciennes évaluations non signées restent dans l’historique ; elles ne deviennent pas des preuves signées rétroactivement.

L’espace de source `managed:` est réservé aux adaptateurs du déploiement. Une saisie manuelle ne peut pas préremplir un événement censé venir d’un collecteur. Si une ancienne donnée utilise déjà le même identifiant sans lien signé, la normalisation refuse de l’adopter, conserve les preuves et affiche le refus dans le dossier de session. Le [contrat technique des interprétations](observation-context.md) détaille cette séparation.

## Fenêtres et reprises de collecte

L’API est interrogée en lecture seule sur `GET /api/v1/reports/connections`. Le paramètre `from_date` filtre le début des sessions : le collecteur l’omet pour conserver une session longue ayant commencé avant la fenêtre. Il fige `to_date`, parcourt les pages par `offset_id` et applique localement la borne de fin minimale. Le contrat est décrit dans la [documentation officielle TeamViewer](https://webapi.teamviewer.com/api/v1/docs/index) et le [client officiel TeamViewerPS](https://github.com/teamviewer/TeamViewerPS/blob/a15ec4e55af7d17ce338aa9b4dbcce4db9e81eeb/Cmdlets/Public/Get-TeamViewerConnectionReport.ps1).

Chaque tâche traite une page au maximum, jusqu’à 1 000 rapports. Le curseur, la borne supérieure et le dernier horodatage sont conservés et signés en base. Une interruption du processus reprend le même parcours après expiration du bail de 90 secondes. Les verrous PostgreSQL et le jeton de tentative empêchent un ancien traitement de finaliser une nouvelle tentative.

Après un parcours terminé, le passage suivant commence cinq minutes plus tard et reparcourt l’historique depuis la date configurée. Ce choix permet de revoir les corrections de notes et les rapports apparus tardivement. Un historique volumineux allonge le cycle et doit être dimensionné avant exploitation ; il n’y a pas de promesse de fraîcheur de cinq minutes. L’API ne fournit pas ici une preuve de snapshot immuable entre pages.

Les erreurs transitoires, dont HTTP 429, libèrent le bail et prévoient une reprise après une minute avec le même curseur. Une erreur permanente suspend le collecteur. Les boucles de curseurs, réponses invalides ou preuves locales altérées ne sont pas traitées comme une fin de collecte réussie. Une désactivation, un changement de configuration ou une perte d’autorisation du module pendant une lecture font écarter le résultat sans importer ses rapports.

## Preuves et interprétation

Chaque version sémantique d’un rapport conserve l’identifiant source, les références de compte et de machine, le début, la fin, la réception et sa signature. Les notes sont chiffrées seulement si leur collecte est activée. Une relecture identique est dédupliquée ; une correction crée une nouvelle version. Lorsque les notes sont désactivées, une modification des seules notes ne crée pas une nouvelle preuve.

Les passages disposent d’un manifeste signé des rapports, relié à l’audit chaîné. Les liens d’observation, attestations de correspondance, dossiers de session et liens de regroupement sont également signés. PostgreSQL refuse les modifications et suppressions de ces preuves et impose des références dans la même organisation. Les observations restent liées à leur collecteur et les liens de regroupement au même identifiant de session source. Le périmètre d’un collecteur ne peut pas être déplacé vers une autre organisation. La qualification de restauration vérifie hors ligne les secrets et preuves historiques, y compris ceux des collecteurs inactifs, sans contacter TeamViewer.

Les limites d’interprétation sont importantes :

- `userid` reste une référence de compte source, pas une preuve de l’identité humaine intervenante. Un propriétaire de compte ou de machine n’est pas automatiquement l’acteur.
- Les identifiants inconnus restent conservés pour un rattachement ultérieur ; ils ne créent aucune identité IAM.
- Une note est une déclaration de la source, pas un ticket vérifié, une approbation ou une preuve de privilèges Windows.
- L’état `complete` signifie seulement que la pagination de la fenêtre est terminée. Il ne déclare pas une couverture complète de l’organisation.
- L’interface montre les 100 derniers passages, les 100 dernières versions de rapports et les 100 dernières publications de correspondances par collecteur, sans purge automatique des preuves. Le détail d’une version propose ses 20 dernières observations.

Les tests incluent un serveur HTTPS éphémère et le parcours formulaire avec CSRF, MFA, activation, collecte, publication des trois associations, événement normalisé et détail d’explication. Ils distinguent l’intervenant du propriétaire du compte partagé, conservent les anciennes analyses et refusent les collisions de provenance. La qualification d’un compte TeamViewer réel et de son périmètre de visibilité reste une étape d’intégration distincte.
