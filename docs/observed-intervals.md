# Évaluation de la durée des accès observés

Un accès terminé peut être décrit par son début et sa fin. Depuis `access-context/6`, l’évaluation compare toute cette période aux éléments de gouvernance datés, au lieu de déclarer la session conforme après le seul contrôle de son début. `access-context/7` conserve ce calcul et ajoute un contexte d’interprétation signé, distinct des faits source. Cette capacité ne crée aucun nouveau conteneur et n’ajoute pas de challenge MFA pendant un flux SSH ou RDP.

## Fait instantané ou période terminée

`occurred_at` reste la date source obligatoire. `ended_at` est facultatif :

- absent ou `null`, il décrit un fait instantané ; une fin inconnue ne signifie pas une session autorisée indéfiniment ;
- égal au début, il conserve la sémantique d’un fait instantané de durée déclarée nulle ;
- postérieur au début, il décrit un intervalle début inclus, fin exclue.

Les deux dates nécessitent un fuseau explicite. Une fin antérieure au début ou située à plus de cinq minutes dans le futur est refusée. L’export conserve les deux dates et une durée informative en secondes ; les décisions temporelles utilisent les dates, pas un arrondi de cette durée.

## Comparaison par périodes de contexte stable

L’évaluation découpe la période aux changements applicables : approbations, débuts et fins des autorisations, révocations, états de l’identité, révisions de contrat, inscriptions des intervenants, politiques, séparation des tâches, placements réseau et hôtes attendus de certificats. Chaque période utilise les éléments datés qui lui sont applicables. Les horaires d’un contrat sont contrôlés sur toute la période examinée, avec leur fuseau, y compris un intervalle traversant une fermeture nocturne.

Par exemple, une session dure de 10 h à 10 h 30. L’identité est active au début et à la fin, mais suspendue de 10 h 10 à 10 h 20. La suspension apparaît dans l’évaluation globale ; deux vérifications limitées aux extrémités l’auraient manquée. Le fait source reste unique : trois périodes d’explication ne deviennent pas trois sessions.

Plusieurs autorisations adjacentes peuvent couvrir des parties successives. Les références métier sont conservées dans chaque constat de justification. Un lien vers une intention unique n’est affiché comme rapprochement global que si cette même intention couvre toutes les périodes. Les investigations signalent aussi une référence métier manquante sur une partie seulement de la session.

## Verdict et limites

Un écart connu sur une période produit un verdict global d’écart. Sans écart établi, une période insuffisamment documentée maintient le verdict global « contexte insuffisant ». La seule absence d’autorisation dans les données n’est pas une preuve universelle d’accès illégitime. Une approbation obtenue au milieu de la session ne justifie pas son début rétroactivement.

Le calcul est borné à 31 jours et 32 périodes par événement. Au-delà, le fait est conservé mais la conformité globale n’est pas déclarée. L’évaluation porte sur les dates et informations rapportées ; elle ne certifie pas l’horloge de la source. Une incertitude déclarée recouvrant une borne de l’autorisation rapprochée reste signalée, pour une intention comme pour un droit temporaire.

Les métadonnées d’inventaire non historisées, notamment les libellés et propriétaires actuels, restent du contexte courant. L’identité enregistrée tardivement dans PAM-olive n’est pas présentée comme une personne déjà partie avant son enregistrement : sans état historique applicable, son cycle de vie reste inconnu. Aucun acteur n’est déduit du propriétaire d’un compte ou d’un certificat.

## Chronologie et conservation

Une recherche temporelle inclut les périodes qui la chevauchent, même si leur début est antérieur à la fenêtre affichée. La chronologie affiche début et fin. Pour un accès terminé, le retard de réception est mesuré après la fin observée, sans compter la durée normale de la session comme retard de collecte.

La migration ajoute une fin vide aux anciens faits. Elle ne complète pas leurs dates et ne réécrit pas les évaluations précédentes. Une réévaluation ajoute une explication versionnée ; les anciens résultats, références et preuves d’audit restent conservés. L’identifiant source continue de désigner un fait immuable : le rejouer ne permet pas de compléter sa fin après coup.

Le [collecteur TeamViewer](teamviewer.md) conserve les rapports et relie les sessions regroupées à un événement unique. Son interprétation utilise des correspondances explicites, sans transformer les propriétaires en intervenants ni compléter les privilèges OS manquants. Des faits contradictoires ou en attente empêchent une conclusion complète.
