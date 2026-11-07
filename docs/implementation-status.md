# État réel de l’implémentation

Le document de vision décrit la cible complète. Cette branche construit progressivement cette cible ; elle ne constitue pas encore une version de production.

## Fonctionnel et testé

- Organisations, appartenances et rôles techniques distincts des identités gouvernées.
- MFA TOTP chiffrée, codes de récupération à usage unique et refus du rejeu de code.
- Validation récente personnelle de 2/5/10/15 minutes et reprise du formulaire conservé après challenge.
- Requêtes organisationnelles refusées sans contexte ; relations croisées refusées dans les modèles et par contraintes PostgreSQL.
- Activation indépendante des sept modules livrés dans le même conteneur.
- Identités humaines, externes, machines, services, applications, workloads et API.
- Comptes externes séparés, ressources physiques/numériques, références publiques de certificats et badges, droits motivés.
- Intention datée avec méthode, ressource, compte, origine, privilège et justification.
- Approbations indépendantes configurables, responsable de contrat, séparation demandeur/approbateur et votes conservés.
- Ingestion authentifiée par source, déduplication, conservation des faits source.
- Comparaison à une intention approuvée ou à un droit applicable ; résultats conformes, écarts ou contexte insuffisant.
- Détail des preuves et export JSON par événement.
- Campagnes de recertification et révocation des droits locaux.
- Départ d’une identité : désactivation locale des comptes, droits, intentions et autorisations temporaires liés.
- Baux PAM limités dans le temps et expiration exécutée par le processus de tâches du conteneur.
- Audit chaîné par organisation, verrous PostgreSQL et protections append-only des preuves.
- Connecteur sortant SCIM 2.0 : test de lecture et capacité PATCH avant activation ; jeton chiffré et destinations HTTPS autorisées côté déploiement.
- Correspondances explicites comptes/utilisateurs SCIM et droits/groupes SCIM.
- File transactionnelle pour attribution, retrait de groupe et désactivation de comptes ; état confirmé seulement après relecture sur la cible.
- Branche IAM d’une approbation : droit temporaire, attribution externe puis retrait à l’échéance.
- Départs et recertifications câblés à la file externe ; correspondances absentes, échecs et reprises visibles dans l’interface.
- Reprises avec délais, nombre de tentatives borné, baux par compte et rejet des résultats d’une ancienne tentative ; preuves d’exécution append-only sous PostgreSQL.
- Fournisseurs distincts des identités ; contrats révisés, périmètres, participants, méthodes, horaires IANA, pays et accès physiques explicites.
- Politique d’approbation publiée par organisation ; parcours IAM obligatoire plutôt qu’une attribution directe pour éviter le contournement des validations.
- Séparation des tâches sur droits et intentions approuvées dont les fenêtres se chevauchent.
- Retrait ciblé des droits contractuels ; désactivation globale réservée aux comptes dédiés, conservation des comptes partagés et droits indépendants.
- Évaluation temporelle : révision applicable à la date source, absence de justification rétroactive, conservation des preuves avant départ/révocation et pays observé non inventé.
- Attribution SCIM différée au début de la fenêtre approuvée.

## Travail requis pour la cible complète

- Étendre les contrôles MFA aux contrats des futurs services exécutant des actions externes ; ajouter WebAuthn et revue spécialisée des parcours d’authentification.
- Adaptateurs spécifiques AD/Entra, ticketing, accès physiques, PAM et collecte réseau/certificats ; création initiale de comptes et synchronisation d’inventaire. Le client SCIM livré couvre des comptes existants et des groupes, pas tous les fournisseurs SCIM.
- Vérification des tickets/contrats dans leurs systèmes sources, catalogue de pays de confiance, gestion des délégations et escalades d’approbation. Les horaires sont vérifiés sur la fenêtre d’autorisation entière, pas appliqués nativement à chaque application SCIM.
- Passerelle SSH/RDP, coupure effective et enregistrement des sessions : le bail existant est une autorisation, pas un tunnel.
- Graphe inter-domaines complet, corrélation temporelle de plusieurs sources et couverture de collecte.
- Installation de paquets tiers par entry points, signature et entitlement commercial.
- Vérifications de restauration, mise à niveau, charge et actif-actif à plusieurs instances.

Une révocation interne n’est jamais présentée comme la preuve d’une révocation exécutée sur un système externe. Une confirmation SCIM cite une relecture datée ; elle ne garantit pas l’absence d’une modification ultérieure faite hors plateforme. Une absence d’intention dans les données collectées n’est pas présentée comme la preuve que l’accès est illégitime.
