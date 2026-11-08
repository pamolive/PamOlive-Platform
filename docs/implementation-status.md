# État réel de l’implémentation

Le document de vision décrit la cible complète. Cette branche construit progressivement cette cible ; elle ne constitue pas encore une version de production.

## Fonctionnel et testé

- Organisations, appartenances et rôles techniques distincts des identités gouvernées.
- Appartenances administrées dans les formulaires natifs de Paramètres : modification et désactivation limitées à l’organisation, service protégé par rôle/MFA récente et verrou PostgreSQL empêchant le retrait du dernier administrateur. Le rattachement d’un compte existant extérieur à l’organisation est réservé à l’administrateur de plateforme local ; une session OIDC n’hérite pas de cette autorité globale. Aucune réinitialisation de mot de passe ni désactivation globale n’est effectuée par ce formulaire.
- MFA TOTP chiffrée, codes de récupération à usage unique et refus du rejeu de code.
- Validation récente personnelle de 2/5/10/15 minutes et reprise du formulaire conservé après challenge.
- [OIDC multi-fournisseurs par organisation](oidc.md) : découverte et authentification HTTPS complète avant enregistrement, activation séparée, association explicite par le titulaire et secours local conservé. Les claims du fournisseur ne créent ni identité IAM ni permissions et ne remplacent pas la MFA locale. Les sessions fédérées sont limitées à leur organisation et invalidées par la révocation du domaine ou de l’association. Les tests utilisent un IdP éphémère, pas une certification des fournisseurs commerciaux.
- Requêtes organisationnelles refusées sans contexte ; relations croisées refusées dans les modèles et par contraintes PostgreSQL.
- Anciennes vues globales du prototype retirées : réponse 410 sans lecture ni mutation, permissions historiques inopérantes même pour un superutilisateur et contrôle de livraison `pamolive.E010` si leurs routes sont réintroduites. Les tables historiques restent conservées ; elles ne constituent pas des rôles organisationnels actifs.
- Activation indépendante des huit modules livrés dans le même conteneur.
- Extensions communautaires Python séparées : wheels signées Ed25519, inventaire des fichiers et manifeste vérifiés avant import, compatibilité du noyau et dépendances, routes HTTP propres au module avec garde du noyau. Livraison après migrations distincte de l’activation par organisation ; activation liée à l’empreinte exacte du paquet, MFA et audit. Exemple autonome sans modification du noyau, sans installation de code par l’interface et sans conteneur permanent supplémentaire.
- Notifications de modules V2 : outbox transactionnelle PostgreSQL, enveloppes/destinataires signés, consommateurs déclarés dans le manifeste signé, contexte par organisation et aucune MFA héritée. Effets locaux et accusé atomiques, reprises bornées, preuves append-only et suspension sans perte lors d’une désactivation. Création/départ d’identité exposés ; exemple de wheel réellement installée recevant des faits IAM et ses propres publications. Aucun nouveau worker Compose, aucune garantie d’exécution unique d’un effet externe.
- Identités humaines, externes, machines, services, applications, workloads et API.
- Comptes externes séparés, ressources physiques/numériques, références publiques de certificats et badges, droits motivés.
- Intention datée avec méthode, ressource, compte, origine, privilège et justification.
- Approbations indépendantes configurables, responsable de contrat, séparation demandeur/approbateur et votes conservés.
- Ingestion authentifiée par source, déduplication, conservation des faits source.
- [Collecte brute TeamViewer](teamviewer.md) : lecture HTTPS, test avant enregistrement, configuration chiffrée inactive puis activation séparée, MFA personnelle, reprises par page avec curseur signé, rapports versionnés immuables et passages liés à l’audit. Les observations identifient la révision exacte du collecteur ; les correspondances datées signées pour compte opérateur, identité attribuée et cible restent distinctes de la propriété. Les corrections conservent les attestations précédentes et les résolutions partielles ou ambiguës restent visibles. La normalisation en événements corrélés reste à implémenter. Aucun compte TeamViewer réel n’est qualifié par les fixtures.
- Acteur rapporté séparé du propriétaire du compte ou du credential : comptes partagés et certificats techniques observables sans attribuer leur activité à leur propriétaire. Acteur inconnu conservé ; aucune intention personnelle déduite par propriété. Intention d’observation bornée à l’intervenant et au compte précis, export et graphe distinguant activité rapportée et rattachement actuel d’inventaire. Départ d’un intervenant sans désactivation du compte partagé d’une autre identité ; retrait du propriétaire désactivant ses comptes et les intentions qui les utilisent.
- Sessions TeamViewer regroupées par identifiant source et organisation : relectures, collecteurs multiples et corrections de notes conservent un dossier unique avec liens signés. Les références ou horaires contradictoires empêchent une attribution consolidée ; les correspondances doivent concorder dans chaque révision source. Les observations en attente d’indexation ne sont pas ignorées par la résolution. Formulaires et détail natifs, traitement dans le worker existant et restauration de toutes les preuves ; le lien vers les événements d’accès évalués reste à livrer.
- Comparaison à une intention approuvée ou à un droit applicable ; résultats conformes, écarts ou contexte insuffisant.
- [Évaluation de la durée observée](observed-intervals.md) : fin facultative, périodes semi-ouvertes, changements d’autorisation et de contexte examinés pendant la session, horaires contractuels contrôlés sur toute la période. Les anciennes observations restent instantanées et les anciennes évaluations sont conservées. Au-delà de 31 jours ou 32 périodes de contexte, aucune conformité globale n’est déclarée. La chronologie conserve les chevauchements et distingue durée de session et retard de réception.
- Détail des preuves et export JSON par événement.
- Campagnes de recertification et révocation des droits locaux.
- Départ d’une identité : désactivation locale des comptes, droits, intentions et autorisations temporaires liés.
- Baux PAM limités dans le temps et expiration exécutée par le processus de tâches du conteneur.
- Mandats PAM individuels pour comptes privilégiés ou techniques : lien explicite compte du portail/personne IAM par organisation, vérification administrative avec référence et MFA récente, attestations signées immuables et révocation tracée. Utilisation d’un compte d’identité technique distincte sans transfert de propriété ; l’emprunt du compte personnel d’un autre humain est refusé.
- Votes PAM signés sur un périmètre figé, comptés par personnes IAM indépendantes : les comptes multiples ne permettent ni auto-approbation ni double vote. MFA personnelle à la demande, à la décision et à l’ouverture ; contrôles continus sans challenge pendant SSH/RDP. Révocation du lien coupant les mandats, pas le compte technique partagé ni le compte global du portail. Anciennes demandes conservées mais non exécutables sans nouvelles preuves ; aucune liaison déduite du nom ou de l’e-mail.
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
- Test natif SSH sur serveur factice éphémère : mauvaise clé refusée avant authentification, bon couple clé/identifiants accepté, aller-retour clavier et fermeture effective du canal constatés. Huit scénarios d’image traversent formulaire, WebSocket et moteur avec PostgreSQL : expiration MFA sans interruption puis déconnexion, expiration de bail, cible désactivée, entrée interdite, quota, authentification par clé Ed25519, erreur de base simulée après établissement du canal et contrôle de démarrage volontairement ralenti. L’erreur de base coupe le transport, conserve une capture partielle lisible et reste distincte d’une révocation. Les transactions d’un relais sont ordonnées sans verrou global et avec attente incluse dans la limite de quatre secondes. Diagnostic limité à l’opération et au SQLSTATE validé, sans message d’exception ni secret. Fermeture constatée sur le serveur SSH et capture relue après MFA. Aucun compte système ni shell distant n’est installé par ces fixtures.
- Portes RDP séparées : pair FreeRDP/NLA factice, contrôle des identifiants délégués après vérification NTLM, refus natif des pins et mots de passe incorrects, clavier et pixels cibles vérifiés. Six scénarios WebSocket/PostgreSQL couvrent aussi la MFA périmée, la déconnexion, l’expiration, la désactivation et la redirection malveillante. Cette dernière exige un hook natif constaté et aucune connexion TCP vers la cible leurre. Les outils de test ne sont pas livrés dans l’image de production ; cela ne certifie pas toutes les versions Windows et politiques AD.

## Couverture des huit scénarios initiaux

Les scénarios proviennent de la [vision produit](product-vision.md). Les tests vérifient
les règles internes et des pairs éphémères ; une collecte réelle depuis un produit tiers
reste une étape distincte. Aucun des huit scénarios ne doit être présenté comme intégré
de bout en bout à tous les systèmes cités.

| Scénario | Capacité livrée et tests associés | Travail restant pour le terrain |
|---|---|---|
| Intervention TeamViewer | Événement, acteur, compte, intention approuvée et explication ; collecte brute avec [configuration et reprises](../tests/test_teamviewer_collection.py), [correspondances attestées](../tests/test_teamviewer_mapping.py), [attribution](../tests/test_access_attribution.py) et [périmètre](../tests/test_platform.py) | Normalisation des rapports en événements corrélés, vérification du ticket source et qualification du jeton réel |
| Chronologie physique et numérique | Ordre source/réception, arrivées tardives, incertitudes d’horloge et domaines séparés ; [chronologie](../tests/test_intelligence.py) | Collecteurs badge/PAM/vCenter et qualité des horloges sur l’installation réelle |
| Fournisseur hors intervention | Contrat versionné, méthodes, horaires, pays inconnus et couverture de collecte ; [gouvernance](../tests/test_governance.py) et [couverture](../tests/test_intelligence.py) | Sources physiques et métier connectées, règles de risque adaptées à l’organisation |
| Déplacement réseau d’une machine | Comparaison switch/port/VLAN et changement approuvé précisément borné ; [réseau](../tests/test_intelligence.py) | Collecteur NAC/switch et résolution fiable de l’identité machine |
| Certificat sur un autre hôte | Références publiques, hôtes attendus et signal d’écart sans conclure à une copie de clé ; [certificats](../tests/test_intelligence.py) | Collecteur PKI/services et preuve de possession de clé lorsqu’elle est disponible |
| Intention et activité réelle | Écart de ressource, méthode, temps, acteur et compte ; évaluations conservées ; [évaluation](../tests/test_platform.py) et [attribution](../tests/test_access_attribution.py) | Vérification du contexte métier externe et collecte opérationnelle du périmètre |
| Contrat fournisseur | Participants, révisions, contraintes et retraits ciblés ; [gouvernance](../tests/test_governance.py), [confirmation SCIM](../tests/test_provisioning.py) | Adaptateurs des systèmes concernés, création initiale de comptes et réconciliation d’inventaire |
| Chemins d’accès | Graphe daté, intersection physique/privilégié, fournisseur/production et investigations ; [graphe](../tests/test_intelligence.py) | Connecteurs réels, rôles métier transverses et qualification des recherches à grande échelle |

## Portes de livraison restantes

- [x] Publier le code du socle et sa documentation dans `pamolive/PamOlive-Platform`.
- [x] Déployer une instance NAS avec un seul conteneur applicatif et PostgreSQL séparé.
- [x] Qualifier le noyau sur PostgreSQL et les transports SSH/RDP sur des pairs de test.
- [x] Tester une restauration isolée sans remplacer la base en service.
- [ ] Valider les ADR encore proposés, notamment la place de Redis et la frontière commerciale.
- [ ] Choisir et qualifier les connecteurs réels du premier périmètre client.
- [ ] Vérifier les références métier auprès de leur système source.
- [ ] Qualifier deux VM réelles, le répartiteur, les partitions réseau et la reprise PostgreSQL.
- [ ] Qualifier la charge, la rétention des captures et la rotation des clés.
- [ ] Livrer le contrat et la distribution des modules commerciaux séparés.
- [ ] Qualifier la sécurité et l’exploitation avant une annonce de version stable.

Une porte cochée correspond au périmètre indiqué, pas à une qualification globale du produit.
La version OIDC `0.2.0a6` est qualifiée par la [CI PostgreSQL et image](https://github.com/pamolive/PamOlive-Platform/actions/runs/42479225455)
sur le code `1281979`. La qualification de restauration peuplée inclut des preuves OIDC synthétiques ;
la sauvegarde du NAS ne contient pas de fournisseur réel. Les procédures sont dans
[OIDC](oidc.md), [actif-actif](active-active.md) et [sauvegarde](backup-restore.md).

## Travail requis pour la cible complète

Les expirations du budget de base du relais sont distinguées des révocations : `database_unavailable`, phase interne bornée dans le journal, fermeture du transport avant finalisation et capture partielle. Un cas RDP natif vérifie cette dégradation avec la limite réelle de quatre secondes après clavier et pixels confirmés. Cela ne résout pas la saturation du stockage : les constructions et qualifications lourdes doivent rester séparées des sessions réelles, et la capacité sous charge reste à qualifier.

- Étendre les contrôles MFA aux contrats des futurs services exécutant des actions externes ; ajouter WebAuthn et revue spécialisée des parcours d’authentification.
- Adaptateurs spécifiques AD/Entra, ticketing, accès physiques, PAM et collecte réseau/certificats ; création initiale de comptes et synchronisation d’inventaire. Le client SCIM livré couvre des comptes existants et des groupes, pas tous les fournisseurs SCIM.
- Vérification des tickets/contrats dans leurs systèmes sources, catalogue de pays de confiance, gestion des délégations et escalades d’approbation. Les horaires sont vérifiés sur la fenêtre d’autorisation entière, pas appliqués nativement à chaque application SCIM.
- Étendre les matrices de compatibilité SSH et Windows/RDP, les politiques AD/Kerberos, les scénarios de panne et la charge. Les fermes RDS à redirection et RD Gateway ne sont pas prises en charge. Le bail seul reste une autorisation ; les sondes testent le serveur, pas les identifiants. Ajouter rétention contrôlée des captures, quotas configurables, restauration et rotation de clé sans perte de preuves.
- Résolution automatique des identifiants externes, groupes/roles métier transverses, preuves cryptographiques de possession de clé, ticketing vérifié et analyse de risque spécialisée. La chronologie rapproche des faits, pas des causes démontrées.
- Délégations avancées et élévation fine : les mandats livrés ouvrent les droits natifs du compte choisi (`native_full_account`), sans filtrage de commandes, sudo/JEA ou profil OS « lecture seule ». L’emprunt de comptes personnels et le provisioning IAM pour une autre identité ne sont pas pris en charge.
- Parcours de grand graphe et pagination haute volumétrie. La projection actuelle limite le contexte à deux sauts, 120 nœuds et 400 relations ; chronologie à 500 événements, investigations à 1000 droits examinés, couverture à 100 périmètres et 500 rapports par périmètre. Les limites sont signalées ; une couverture tronquée n’est jamais déclarée complète.
- Extensions commerciales : choix de licence adapté à leur distribution, entitlements et canal privé. L’API d’extension livrée est communautaire ; les tâches tierces planifiées, la migration/reprise des contrats incompatibles et le backfill contrôlé des notifications restent à implémenter. Les modules Python restent du code de confiance, pas des sandboxes.
- Reprise après sinistre, charge et actif-actif sur deux VM réelles : la qualification hors ligne de restauration et la porte HTTP à deux instances sont livrées, mais ne prouvent ni une bascule PostgreSQL ni une reprise métier sûre. Une session SSH/RDP ne migre pas à chaud.

Une révocation interne n’est jamais présentée comme la preuve d’une révocation exécutée sur un système externe. Une confirmation SCIM cite une relecture datée ; elle ne garantit pas l’absence d’une modification ultérieure faite hors plateforme. Une absence d’intention dans les données collectées n’est pas présentée comme la preuve que l’accès est illégitime.
