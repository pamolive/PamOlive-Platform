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

## Comprendre les retraits

Supposons que la personne quitte **Support** pour **Exploitation**, tout en gardant le rôle **Commun**. Le changement retire les demandes et droits issus de l’affectation **Support**, conserve **Commun** à sa révision actuelle et crée des demandes pour **Exploitation**. Un droit de support accordé indépendamment reste actif, même s’il désigne le même compte, la même ressource et le même privilège.

L’application du changement, les retraits locaux et la création des nouvelles demandes sont atomiques. Si une demande nouvelle enfreint une règle IAM, le changement entier est refusé. Le provisioning SCIM reste asynchrone. La révocation locale ne vaut pas confirmation de retrait à distance, et la séparation des tâches locale ne certifie pas l’état des droits sur le système externe. Vérifiez les confirmations des connecteurs avant de considérer le transfert comme terminé. Lorsqu’un autre droit autorise toujours la même appartenance externe, le connecteur ne retire pas cette appartenance.

La mobilité ne désactive ni le compte du portail ni les comptes externes. Elle ne retire pas les accès indépendants ou anciens dont l’origine métier n’est pas attestée. Le départ complet reste un autre parcours.

## Preuves et exploitation

Les publications, propositions, décisions, liens avec les demandes IAM et attributions effectives sont attestés et liés à l’audit. PostgreSQL empêche la réécriture de ces preuves et les relations entre organisations. Les affectations sont suivies par révision et par décision d’origine : retirer puis réattribuer le même rôle ne réactive pas ses anciennes demandes.

La mobilité utilise l’application et le traitement de provisioning existants. Aucun conteneur supplémentaire n’est nécessaire. Le contrôle de restauration vérifie les preuves avec la clé de l’installation.
