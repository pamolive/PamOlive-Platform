# Mobilité interne et rôles métier

Un changement de poste prépare les retraits de droits liés à l’ancienne fonction et les demandes d’accès de la nouvelle. Un approbateur indépendant valide le changement. Chaque nouvel accès suit ensuite le circuit IAM habituel : approuver le changement de poste n’accorde aucun droit à lui seul.

## Publier un rôle métier

Dans **Identités → Mobilité interne → Catalogue des rôles métier**, un administrateur publie un rôle avec sa MFA récente. Un rôle peut décrire jusqu’à vingt accès. Pour chacun, indiquez la ressource, la méthode, le droit demandé et sa durée, de 1 à 365 jours. Le compte n’est choisi qu’au moment du changement de poste, parmi les comptes actifs de la personne.

Une publication crée une révision immuable. Les affectations existantes gardent la révision d’origine. Retirer un rôle du catalogue empêche les nouvelles affectations et les nouvelles approbations de ses demandes pendantes ; cela ne révoque pas les droits déjà accordés. Pour les retirer, soumettez un changement de poste qui omet le rôle.

## Soumettre et examiner un changement de poste

1. Ouvrez la fiche de la personne et choisissez **Préparer un changement de poste**. Sélectionnez les rôles à conserver et les nouveaux rôles. Omettre un rôle existant prépare son retrait.
2. Pour chaque nouvel accès, choisissez le compte concerné. Renseignez l’équipe ou la fonction, le motif et une référence RH ou métier. La soumission avec MFA fige la proposition, sans modifier les accès.
3. Un approbateur ouvre la demande dans **Mobilité interne**, vérifie les accès à retirer et à demander, puis motive sa décision avec sa MFA. Le demandeur et la personne concernée ne peuvent pas approuver, même via un autre compte lié à la même personne.
4. Les nouvelles demandes apparaissent dans **Approbations**. Elles restent soumises aux règles IAM en vigueur, à la séparation des tâches et aux approbations par droit. La durée demandée commence à l’application du changement de poste ; attendre une approbation ne prolonge pas cette fenêtre.

Le demandeur et l’approbateur doivent disposer d’un lien explicite entre leur compte du portail et leur personne IAM dans cette organisation. Ce lien est distinct des comptes sur lesquels les droits seront attribués.

Une demande reste applicable pendant 48 heures. Si un poste, un rôle choisi, un compte ou un droit à retirer change après la soumission, préparez une nouvelle demande. Le refus ne change ni le poste ni les droits.

## Rattacher un dossier RH ou métier

Si un système RH ou de ticketing publie déjà ses lectures via l’[API multi-sources](business-api.md), ouvrez **Lectures RH et métier vérifiées** avant de soumettre le changement. Choisissez jusqu’à cinq dossiers par leur source et leur identifiant stable. Deux outils peuvent employer le même numéro ; aucune correspondance n’est déduite de la référence saisie en texte.

Cliquez sur **Examiner les lectures source**, puis vérifiez leur contenu avant de soumettre. Modifier le formulaire impose un nouvel examen. La proposition conserve la lecture sélectionnée et celle vérifiée à la soumission. L’approbateur consulte les preuves avec sa MFA personnelle avant de valider.

Une nouvelle lecture du même contenu, sous la même révision de source, peut maintenir la preuve à jour. Une modification du dossier, une rotation de la source, sa désactivation ou une lecture périmée bloque l’approbation. Soumettez une nouvelle demande avec les lectures actuelles ; le refus de l’ancienne reste possible. Après décision, les preuves et l’export distinguent les lectures conservées de la dernière déclaration connue. L’état source, même « approved », n’est pas une décision PAM-olive. Une modification ultérieure du dossier externe ne réécrit ni la décision ni ses droits.

Sans rattachement, la référence reste une déclaration manuelle. Le parcours n’exige pas de connecter un fournisseur particulier.

## Comprendre les retraits

Supposons que la personne quitte **Support** pour **Exploitation**, tout en gardant le rôle **Commun**. Le changement retire les demandes et droits issus de l’affectation **Support**, conserve **Commun** à sa révision actuelle et crée des demandes pour **Exploitation**. Un droit de support accordé indépendamment reste actif, même s’il désigne le même compte, la même ressource et le même privilège.

L’application du changement, les retraits locaux et la création des nouvelles demandes sont atomiques. Si une demande nouvelle enfreint une règle IAM, le changement entier est refusé. Le provisioning SCIM reste asynchrone : une révocation locale ne vaut pas confirmation du retrait à distance.

Si un ancien droit métier a fait l’objet d’une tentative SCIM, l’approbation du nouveau droit attend une relecture confirmant l’absence de l’ancienne appartenance, sur le connecteur, la destination, le compte et le groupe exacts. Le traitement vérifie de nouveau cette condition avant l’envoi. Une confirmation sur une autre destination ou un état « confirmé » sans preuve ne suffit pas. Si un autre droit actif autorise toujours la même appartenance externe, le connecteur la conserve.

Si le retrait bloque, ouvrez son opération dans **Connecteurs**. Rétablissez les correspondances vers la destination d’origine, puis relancez le retrait ou choisissez **Revérifier un retrait sur sa destination d’origine** si l’opération est déjà terminée. Cette vérification crée une nouvelle opération sans réécrire la preuve précédente. Une relecture reste datée : elle ne certifie pas les changements ultérieurs effectués hors plateforme.

La mobilité ne désactive ni le compte du portail ni les comptes externes. Elle ne retire pas les accès indépendants ou anciens dont l’origine métier n’est pas attestée. Le départ complet reste un autre parcours.

## Preuves et exploitation

Les publications, propositions, décisions, liens avec les demandes IAM et attributions effectives sont attestés et liés à l’audit. PostgreSQL empêche la réécriture de ces preuves et les relations entre organisations. Les affectations sont suivies par révision et par décision d’origine : retirer puis réattribuer le même rôle ne réactive pas ses anciennes demandes.

Lorsqu’une observation est rapprochée de l’intention ou du droit attribué, la [vue d’explication](business-api.md#utiliser-le-contexte-dans-lexplication-dun-accès) permet de retrouver les dossiers examinés à la mobilité. Elle ne déduit aucun lien à partir du numéro de ticket et n’étend pas le rapprochement à une partie de la session qui n’a pas été couverte.

La mobilité utilise l’application et le traitement de provisioning existants. Aucun conteneur supplémentaire n’est nécessaire. Le contrôle de restauration vérifie les preuves avec la clé de l’installation.
