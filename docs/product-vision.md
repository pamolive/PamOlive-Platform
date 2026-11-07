# PAM-olive — Gouvernance universelle des accès

> Référence fonctionnelle issue de la vision produit exprimée le 27 septembre 2026. Les capacités décrites sont des objectifs ; leur présence dans ce document ne signifie pas qu’elles sont déjà implémentées. La conception détaillée précède le développement des modules.

## Finalité

PAM-olive gouverne les interactions entre des identités et des ressources, depuis leur justification métier jusqu’à leur activité observée. Le produit rapproche les mondes numérique et physique : personnes, prestataires, machines, services, workloads, applications, comptes, certificats, badges, réseaux et systèmes.

Chaque accès doit pouvoir répondre à six questions : **Qui ? Quoi ? Où ? Quand ? Comment ? Pourquoi ?** La réponse peut inclure une information inconnue ou non collectée ; le système ne doit jamais inventer un lien pour compléter le récit.

Le positionnement est **Universal Access Governance**, ou **Identity-Centric Access Control Plane**. IAM, PAM et les autres domaines se raccordent à ce modèle commun.

## Les objets de premier rang

| Objet | Signification |
|---|---|
| Identité | Acteur gouverné : humain, intervenant externe, machine, service, workload, application ou API ; responsable et cycle de vie explicites |
| Compte | Moyen de connexion à un système ; standard, technique ou privilégié ; distinct de l’identité et du compte ouvrant l’interface PAM-olive |
| Certificat / credential | Objet d’authentification gouverné, distinct de son propriétaire : émetteur, empreinte, validité, usages, sujets et hôtes liés |
| Ressource | Application, serveur, base, porte, réseau, API ou ressource cloud |
| Lieu / contexte d’origine | Bâtiment, zone, switch, port, VLAN, IP, appareil ou localisation ; provenance et confiance conservées |
| Fournisseur et contrat | Société, sponsor, intervenants, durée, périmètre, méthodes, horaires et restrictions |
| Contexte métier | Ticket, incident, changement, maintenance, projet, urgence ou justification déclarée |
| Access Intent | Intervention prévue : acteurs, comptes, ressources, méthodes, privilèges, lieux, durée, contexte métier et décision d’approbation |
| Access Event | Fait observé : acteur ou acteur inconnu, cible, action, résultat, moyen, origine, dates et référence de preuve |
| Access Evaluation | Comparaison explicable entre politique, intention et observation, avec constats, incertitude et risque |
| Response Action | Alerte, investigation ou action autorisée sur un système connecté, avec résultat et preuve |

Un prestataire humain appartient à une société fournisseur ; les deux objets restent distincts. Une identité machine reste distincte de son certificat. Les credentials MFA sont des facteurs d’authentification, pas automatiquement des certificats.

## Six dimensions d’un événement d’accès

| Dimension | Informations à rechercher |
|---|---|
| WHO — Qui ? | Identité résolue, compte utilisé, credential, société fournisseur, organisation, rôle et responsable |
| WHAT — Quoi ? | Ressource, action tentée ou exécutée, résultat et niveau de privilège |
| WHERE — Où ? | Origine physique ou logique, appareil, IP, switch/port/VLAN et localisation disponible |
| WHEN — Quand ? | Début, fin, durée, heure source, réception, fuseau, horaires, validité du contrat et fenêtre d’intervention |
| HOW — Comment ? | Badge, TeamViewer, Wallix, SSH, RDP, VPN, certificat ou connexion interactive ; chemin et contrôles observés |
| WHY — Pourquoi ? | Contexte métier, justification, Access Intent, décision d’approbation et adéquation au périmètre |

Une justification saisie, un ticket existant et une intervention approuvée sont trois niveaux différents. Le moteur doit pouvoir les distinguer.

## Cinq couches fonctionnelles

1. **Gouvernance** : lifecycle, fournisseurs, contrats, rôles, droits, politiques, séparation des tâches, demandes, validations et revues.
2. **Access Intent** : périmètre métier déclaré, daté et approuvé lorsqu’une politique l’exige.
3. **Observation** : collecte depuis PAM, outils distants, badge, réseau/NAC, EDR, annuaires, certificats, cloud, VPN, applications et SIEM.
4. **Corrélation et analyse** : rapprochement d’identités et de preuves, comparaison attendu/observé, écarts de politique, risque et explication.
5. **Réponse et audit** : alerte, investigation, révocation/blocage lorsque techniquement possible, preuves et suivi d’exécution.

Le noyau technique conserve ses cinq responsabilités : authentification, permissions, audit, modules et organisations. Ces couches fonctionnelles sont réalisées par des domaines métier modulaires.

## Identity Graph et jumeau numérique/physique

Le graphe rapproche les comptes AD/Entra, badges, appareils, certificats, appartenances, accès PAM/distants, applications, lieux et justificatifs d’une identité.

Les relations sont typées : `account-of`, `owns`, `member-of`, `approved-for`, `permitted-through`, `badge-access`, `responsible-for`, `issued-by`, `used-by`, `observed-on` et `justified-by`. Elles portent organisation, provenance, période de validité et confiance.

Le graphe distingue :

- la **capacité d’accès**, déterminée par les droits et politiques ;
- l’**intention**, déclarée ou approuvée pour une intervention ;
- l’**activité**, réellement observée ;
- l’**évaluation**, produite à partir des trois précédentes.

PostgreSQL reste la source de vérité. Une projection relationnelle du graphe suffit au démarrage ; une base supplémentaire ne sera introduite qu’après démonstration d’un besoin de parcours ou de volumétrie.

## Scénarios et critères d’acceptation

Les noms et références ci-dessous sont des exemples de conception issus du besoin, sans connexion aux systèmes mentionnés.

### 1. Expliquer une intervention TeamViewer

À partir d’une connexion à un poste, la plateforme restitue identité, compte, équipe, appareil, propriétaire, début/fin, méthode, privilège, justification et ticket lorsqu’ils sont disponibles.

**Acceptation :** la question « Pourquoi Cyriel s’est-il connecté sur ce poste ? » donne une explication avec la provenance de chaque information. Les données absentes sont signalées ; un ticket rattaché après l’événement est identifiable comme tel.

### 2. Reconstruire une chronologie physique et numérique

Les événements badge salle serveur, Wallix, vCenter, maintenance ESXi, fermeture de session et sortie sont affichés sur une chronologie commune, reliés à l’identité et au changement approuvé.

**Acceptation :** chaque lien cite une relation ou une preuve. Le système distingue corrélation temporelle et relation causale établie ; il gère les écarts d’horloge et les arrivées tardives.

### 3. Identifier une intervention fournisseur non justifiée

Un accès physique à 03:12 est comparé au contrat, aux personnes autorisées, au périmètre physique, aux horaires, aux interventions et fenêtres actives.

**Acceptation :** les écarts sont listés et rattachés à une règle versionnée. « Aucune session PAM détectée » indique la couverture de collecte ; une source indisponible ne produit pas la même conclusion qu’une absence confirmée.

### 4. Expliquer un déplacement réseau de machine

Une machine attendue sur un switch, port ou VLAN est observée ailleurs. Le moteur rapproche son identité, certificat, propriétaire, emplacement attendu et éventuel changement autorisé.

**Acceptation :** la réponse montre attendu/observé, première occurrence connue, source et contexte métier. Un remplacement de switch ou déplacement approuvé peut expliquer l’écart ; l’usage habituel seul ne vaut pas autorisation.

### 5. Détecter un écart d’usage de certificat

Un certificat lié à un serveur est observé sur un hôte différent. La plateforme examine empreinte, émetteur, validité, usage, hôte et changement autorisé.

**Acceptation :** elle produit un signal à investiguer, avec preuve de possession de clé lorsqu’elle existe. Le nom CN seul ne suffit pas à conclure à une duplication ; migration, failover et qualité de la source sont pris en compte.

### 6. Comparer l’intervention prévue à l’activité réelle

L’intention INC-47294 autorise TeamViewer sur PC-483 et PC-484 entre 14:00 et 16:00 avec un privilège donné. Un accès à PC-991 est également observé.

**Acceptation :** l’accès à PC-991 est marqué hors périmètre de cette intention, avec ressource, méthode, durée et privilège comparés. Un autre accord valable doit être recherché avant de déclarer l’accès globalement non autorisé.

### 7. Encadrer un fournisseur par contrat

La société, le sponsor, les intervenants, les serveurs autorisés, méthodes, accès physiques, horaires/fuseau et restrictions géographiques sont définis séparément.

**Acceptation :** changer la période ou révoquer un intervenant modifie l’évaluation des nouveaux accès et déclenche les retraits prévus. La réponse distingue accès observés et accès contrôlables par les connecteurs.

### 8. Interroger les chemins d’accès

La plateforme permet de rechercher :

- les personnes possédant à la fois un accès physique à une zone et un compte administrateur sur les systèmes qui s’y trouvent ;
- les fournisseurs pouvant atteindre une ressource de production ;
- les comptes administrateurs utilisés sans justification active ;
- les accès observés sans ticket associé sur une période donnée.

**Acceptation :** résultats et chemins portent validité et source. Les requêtes restent dans l’organisation autorisée ; un droit expiré et un droit actif ne sont pas confondus.

## Contrat d’explication : « Explain this access »

Une explication restitue l’accès observé, l’identité résolue, l’autorisation applicable, l’intention rapprochée, les preuves concordantes, les écarts et les informations inconnues. Elle cite la version des règles, la période évaluée, la couverture des sources et la décision de traitement.

Les évaluations sont révisables sans réécrire le fait source. Un comportement familier ne rend pas légitime un accès interdit ; une activité atypique peut être conforme à une intervention autorisée.

## Direction de conception

Le prochain travail est de détailler les frontières et schémas des domaines Graphe, Intentions, Observation, Évaluations et Réponse, puis leurs contrats avec IAM, Approbations, Connecteurs, Recertification et PAM. Les connecteurs sont choisis selon les capacités réelles des API sources, sans présumer qu’un fournisseur expose toutes les données ou commandes nécessaires.

Le modèle doit conserver les choix déjà proposés : Python/Django modulaire, PostgreSQL 16+, Redis, isolation multi-organisation, comptes distincts des identités, compatibilité actif-actif et activation de modules par organisation. La page [d’architecture visuelle](architecture-platform.html) sert à présenter cette cible aux contributeurs et partenaires.
