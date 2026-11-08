# État réel de l’implémentation

Le document de vision décrit la cible complète. Cette branche construit progressivement cette cible ; elle ne constitue pas encore une version de production.

## Fonctionnel et testé

- Organisations, appartenances et rôles techniques distincts des identités gouvernées.
- MFA TOTP chiffrée, codes de récupération à usage unique et refus du rejeu de code.
- Validation récente personnelle de 2/5/10/15 minutes et reprise du formulaire conservé après challenge.
- Requêtes organisationnelles refusées sans contexte ; relations croisées refusées dans les modèles et par contraintes PostgreSQL.
- Activation indépendante des huit modules livrés dans le même conteneur.
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
- Graphe relationnel daté : comptes, ressources, certificats, fournisseurs, droits, intentions et observations ; liens de contexte avec provenance et confiance déclarée.
- Relations explicites de propriété, hébergement dans une zone, application gestionnaire d’une porte, hôtes attendus de certificat et topologie réseau. Un lien de contexte ne crée aucun droit.
- Chronologie physique/numérique d’une identité, arrivées tardives, précision d’horloge déclarée et ordre relatif incertain ; aucune attribution automatique d’une machine à son propriétaire.
- Comparaison switch/port/VLAN attendu et observé ; un déplacement doit être précisément inclus dans une intention approuvée pour expliquer l’écart.
- Écart d’hôte de certificat sans prétendre prouver une duplication de clé ; hôtes alternatifs datés et vérifiés par le déclarant.
- Rapports de collecte immuables par source et périmètre, déduplication, corrections séquencées et calcul de couverture par intervalles. Une source activée n’est pas considérée collectante sans rapport.
- Investigations datées : intersection accès physique/privilégié, fournisseurs vers production, comptes privilégiés sans intention ponctuelle et événements sans référence déclarée dans une intention rapprochée.
- Réévaluations append-only des événements, historique conservé et export JSON du graphe et des faits réseau/certificats.
- Les droits, intentions et liens sont datés ; les libellés, types de comptes et classifications de ressources restent leurs métadonnées actuelles, pas un inventaire historique complet.
- Transport PAM dans l’image unique : moteur natif Guacamole SSH/RDP compilé depuis une source épinglée et signée, sans Java/Tomcat ni service Compose supplémentaire. Runtime ASGI et moteur natif privé sous deux UID différents, environnement natif sans secrets applicatifs, capacités effectives nulles pour les processus enfants.
- Sondes pré-authentification SSH et RDP : clé d’hôte ou empreinte SHA-256 obligatoire, NLA/TLS exigés pour RDP, validité temporelle du certificat contrôlée, hôtes/ports et réseaux autorisés explicitement, résolution IP épinglée. Elles n’acceptent ni mot de passe ni clé privée et ne prouvent pas une connexion de compte réussie.
- Relais WebSocket SSH et RDP/NLA même origine, tickets courts à usage unique liés au détenteur/session/organisation/IP et périmètre approuvé scellé. Configuration de cible chiffrée, vérification explicite avant activation, résolution épinglée et injection des secrets côté serveur uniquement.
- Cadrage Guacamole UTF-8 borné et liste fermée d’entrées clavier/souris/affichage ; refus des arguments de connexion, flux montants, fichiers et presse-papiers côté client. Les flux de paramètres natifs sont retirés avant affichage et capture.
- Contrôle continu de l’autorisation avec fermeture du transport en cas de perte, sans rechallenge MFA au milieu du flux. Fermeture de son propre relais sans MFA. Connexions bornées, propriétaire de relais clôturé par jeton de fencing et captures orphelines marquées partielles.
- Capture d’affichage chiffrée dans PostgreSQL avant transmission, chaîne HMAC et fin scellée dans l’audit ; lecture après MFA avec droits revérifiés par lots. Format Guacamole, pas MP4 ni preuve de logoff de l’OS distant. Quotas sans purge automatique.
- Test natif SSH sur serveur factice éphémère : mauvaise clé refusée avant authentification, bon couple clé/identifiants accepté, aller-retour clavier et fermeture effective du canal constatés. Six scénarios d’image traversent formulaire, WebSocket et moteur avec PostgreSQL : expiration MFA sans interruption puis déconnexion, expiration de bail, cible désactivée, entrée interdite, quota et authentification par clé Ed25519. Fermeture constatée sur le serveur SSH et capture relue après MFA. Aucun compte système ni shell distant n’est installé par ces fixtures.
- Portes RDP séparées : pair FreeRDP/NLA factice, contrôle des identifiants délégués après vérification NTLM, refus natif des pins et mots de passe incorrects, clavier et pixels cibles vérifiés. Six scénarios WebSocket/PostgreSQL couvrent aussi la MFA périmée, la déconnexion, l’expiration, la désactivation et la redirection malveillante. Cette dernière exige un hook natif constaté et aucune connexion TCP vers la cible leurre. Les outils de test ne sont pas livrés dans l’image de production ; cela ne certifie pas toutes les versions Windows et politiques AD.

## Travail requis pour la cible complète

- Étendre les contrôles MFA aux contrats des futurs services exécutant des actions externes ; ajouter WebAuthn et revue spécialisée des parcours d’authentification.
- Adaptateurs spécifiques AD/Entra, ticketing, accès physiques, PAM et collecte réseau/certificats ; création initiale de comptes et synchronisation d’inventaire. Le client SCIM livré couvre des comptes existants et des groupes, pas tous les fournisseurs SCIM.
- Vérification des tickets/contrats dans leurs systèmes sources, catalogue de pays de confiance, gestion des délégations et escalades d’approbation. Les horaires sont vérifiés sur la fenêtre d’autorisation entière, pas appliqués nativement à chaque application SCIM.
- Étendre les matrices de compatibilité SSH et Windows/RDP, les politiques AD/Kerberos, les scénarios de panne et la charge. Les fermes RDS à redirection et RD Gateway ne sont pas prises en charge. Le bail seul reste une autorisation ; les sondes testent le serveur, pas les identifiants. Ajouter rétention contrôlée des captures, quotas configurables, restauration et rotation de clé sans perte de preuves.
- Résolution automatique des identifiants externes, groupes/roles métier transverses, preuves cryptographiques de possession de clé, ticketing vérifié et analyse de risque spécialisée. La chronologie rapproche des faits, pas des causes démontrées.
- Parcours de grand graphe et pagination haute volumétrie. La projection actuelle limite le contexte à deux sauts, 120 nœuds et 400 relations ; chronologie à 500 événements, investigations à 1000 droits examinés, couverture à 100 périmètres et 500 rapports par périmètre. Les limites sont signalées ; une couverture tronquée n’est jamais déclarée complète.
- Installation de paquets tiers par entry points, signature et entitlement commercial.
- Vérifications de restauration, mise à niveau, charge et actif-actif à plusieurs instances.

Une révocation interne n’est jamais présentée comme la preuve d’une révocation exécutée sur un système externe. Une confirmation SCIM cite une relecture datée ; elle ne garantit pas l’absence d’une modification ultérieure faite hors plateforme. Une absence d’intention dans les données collectées n’est pas présentée comme la preuve que l’accès est illégitime.
