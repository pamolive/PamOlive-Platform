# État réel de l’implémentation

Le document de vision décrit la cible complète. Cette branche construit progressivement cette cible ; elle ne constitue pas encore une version de production.

## Fonctionnel et testé

- Organisations, appartenances et rôles techniques distincts des identités gouvernées.
- MFA TOTP chiffrée, codes de récupération à usage unique et refus du rejeu de code.
- Validation récente personnelle de 2/5/10/15 minutes et reprise du formulaire conservé après challenge.
- Requêtes organisationnelles refusées sans contexte ; relations croisées refusées dans les modèles et par contraintes PostgreSQL.
- Activation indépendante des six modules livrés dans le même conteneur.
- Identités humaines, externes, machines, services, applications, workloads et API.
- Comptes externes séparés, ressources physiques/numériques, références publiques de certificats et badges, droits motivés.
- Intention datée avec méthode, ressource, compte, origine, privilège et justification.
- Approbation par un autre opérateur autorisé ; décision unique.
- Ingestion authentifiée par source, déduplication, conservation des faits source.
- Comparaison à une intention approuvée ou à un droit applicable ; résultats conformes, écarts ou contexte insuffisant.
- Détail des preuves et export JSON par événement.
- Campagnes de recertification et révocation des droits locaux.
- Départ d’une identité : désactivation locale des comptes, droits, intentions et autorisations temporaires liés.
- Baux PAM limités dans le temps et expiration exécutée par le processus de tâches du conteneur.
- Audit chaîné par organisation, verrous PostgreSQL et protections append-only des preuves.

## Travail requis pour la cible complète

- Étendre les contrôles MFA aux contrats des futurs services exécutant des actions externes ; ajouter WebAuthn et revue spécialisée des parcours d’authentification.
- Connecteurs réels AD/Entra, ticketing, accès physiques, PAM et collecte réseau/certificats ; confirmation du provisioning externe.
- Contrats fournisseurs, politiques horaires et séparation des tâches configurable.
- Passerelle SSH/RDP, coupure effective et enregistrement des sessions : le bail existant est une autorisation, pas un tunnel.
- Graphe inter-domaines complet, corrélation temporelle de plusieurs sources et couverture de collecte.
- Installation de paquets tiers par entry points, signature et entitlement commercial.
- Vérifications de restauration, mise à niveau, charge et actif-actif à plusieurs instances.

Une révocation interne n’est jamais présentée comme la preuve d’une révocation exécutée sur un système externe. Une absence d’intention dans les données collectées n’est pas présentée comme la preuve que l’accès est illégitime.
