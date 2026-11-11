# Revue contradictoire indépendante P1-C / P1-D / P1-E et préparation N0

11 novembre 2026. Revue indépendante du développement, sur code local et données synthétiques uniquement. Aucun NAS, annuaire, collecteur ou compte privilégié réel n'a été contacté. Ce rapport ne qualifie pas un déploiement ni la sécurité de l'hôte Docker.

## Périmètre et méthode

Lecture des services Identity 360 et de simulation AD/LDAP/Entra, du workspace Governance, du registre d'exceptions et de sa migration/restauration, d'Observe et du démonstrateur PC-483/PC-991, des vues/routes/templates et de la préparation Compose Synology. Les garanties sont confrontées aux ADR-013/014, aux preuves P0 et au contrat de lecture P1-B1. Les services appelés depuis les nouveaux parcours sont inclus, même lorsqu'ils préexistaient au lot.

Les tests PostgreSQL indépendants utilisent une base `test_pamolive_redcde_*` dédiée sur loopback, détruite par le runner à la fin. Les essais Compose exécutent seulement `docker compose config` et des mutations de plan en mémoire, sans moteur Docker ni connexion NAS.

## Constats et décisions

### RT-1 — Autorité administrative périmée dans des services existants

**Sévérité élevée pour les écritures de sécurité concernées ; correction requise avant livraison.** Une authentification/MFA préexistante et un objet utilisateur conservé en mémoire pouvaient survivre à la désactivation du compte en base. Le verrou d'organisation ne rechargeait pas toujours les attributs `is_active` et `is_superuser`, ou l'autorisation précédait l'attente de ce verrou.

Deux exploitations ont été reproduites indépendamment sur PostgreSQL : désactiver `self.admin` en base sans rafraîchir l'objet, puis appeler la publication d'un rôle métier via `MoverFixture.role()` ; même scénario avec `RecertificationFixture.schedule()` pour publier et activer une planification. Chaque reproduction a effectivement écrit l'objet interdit, dans sa propre base synthétique (respectivement 0,151 s et 0,152 s hors initialisation). Une revue IAM séparée a également reproduit la publication d'une politique Governance par un compte désactivé. Les chemins étaient `identity.mover._guard`, `recertification.schedules._operator` et `governance.services._publisher`.

Les protections de tenant, MFA, politique et signatures existaient ; elles ne rendaient pas fraîche une instance utilisateur périmée. Les corrections utilisent `lock_authorized_actor` après verrou, puis revérifient module et MFA. Le même principe couvre maintenant l'ouverture manuelle de campagne et l'activation/désactivation des modules du noyau. Le bootstrap explicite par organisation et la restriction fédérée restent conservés. Les tâches planifiées sans acteur suivent leur propre validation de publication ; aucun compte humain fictif ne leur est attribué.

Les régressions conservées sont dans `test_mover_authority`, `test_module_activation_authority`, `test_governance_workspace` et `test_governance_workspace_concurrency`. Elles incluent comptes/organisations périmés, retrait du statut superutilisateur, appartenance révoquée et mutations bloquées derrière un verrou. La correction n'affaiblit ni le quorum indépendant PAM ni les gardes de destination P0-2.

### RT-2 — Taille HTTP malformée produisant une erreur interne

**Sévérité faible, corrigée.** La simulation exécutait `int(CONTENT_LENGTH)` sans validation : une valeur non numérique produisait `ValueError`, sans contournement d'autorisation. La reproduction sans réseau a été confirmée, puis le même cas a retourné `400` avec `no-store` après correction.

La validation canonique et bornée est désormais placée avant le décorateur de session/MFA, afin que le mécanisme de reprise MFA ne reçoive pas non plus une longueur malformée. Une longueur valide excessive conserve `413`. Les tests couvrent GET et POST, absence de MFA récente et formats négatifs/non canoniques ; les requêtes valides gardent les contrôles CSRF, MFA, tenant et modules.

### RT-3 — Préflight N0 incomplet face à un plan modifié

**Durcissement nécessaire avant publication, corrigé dans le périmètre examiné.** Le Compose actuel n'employait aucun privilège hôte, mais son validateur acceptait des plans mutés en mémoire avec `pid=host`, capacité `SYS_ADMIN` ou périphérique hôte. Le CLI utilise un Compose fixé et ne propose pas de fichier arbitraire ; aucune compromission par une entrée utilisateur ordinaire n'a été démontrée.

Le validateur refuse maintenant les namespaces/périphériques et exige les ensembles de capacités et options de sécurité relus. Les trois mutations adverses ont été réexécutées et sont toutes refusées ; les cinq tests indépendants de préparation Compose passent. Ce contrôle reste un garde de configuration, sans certifier un digest d'image, l'absence d'une ressource homonyme sur l'hôte ou l'autorisation de la créer.

### RT-4 — Nom de base incohérent avec le garde du démonstrateur

**Défaut fonctionnel corrigé.** Le plan initial utilisait `pamolive_p1_test`, refusé par le garde volontairement strict de la commande de démonstration. Compose, SQL, exemple, validateur et tests utilisent désormais `test_pamolive_p1`. Le garde exigeant une base synthétique neuve n'a pas été élargi.

## Garanties vérifiées et désaccords résolus

Le registre d'exceptions constitue une justification suivie, sans consommation par les moteurs d'autorisation. Son acceptation ne produit ni vote, droit, mandat ou opération fournisseur ; une exception acceptée ne lève pas un refus SoD. La séparation de deux comptes ordinaires n'est donc pas présentée comme une preuve de personnes indépendantes, réservée au modèle PAM P0-3. Les demandes/décisions sont immuables et ancrées ; la restauration vérifie signature, MFA historique, tenant, durée, chronologie, unicités et correspondance avec les ancres d'audit, sans réactiver une autorité expirée.

Identity 360 distingue références déclarées, droits locaux et références de groupes configurés ; il ne transforme ni un e-mail, ni un nom, ni un mapping en attestation PAM ou inventaire fournisseur. Les adaptateurs de réconciliation n'ont aucun transport ni chemin d'application ; leurs absences/collisions restent des incertitudes à examiner.

Observe vérifie l'évaluation et la provenance avant sa conclusion ; une preuve invalide devient indéterminée et aucune ancienne conformité de secours n'est reprise. Une comparaison explicite avec INC-47294 ne prétend pas exclure une autre autorisation légitime sur PC-991. Le démonstrateur utilise le worker existant avec transport mémoire, des clés synthétiques et des mots de passe inutilisables ; ses confirmations ne sont pas des faits d'un fournisseur réel. Les lectures et exports restent non signés, avec liens vers les preuves existantes V7/V8.

## Résultats indépendants

- Première campagne C/D/E/N0 : **67/67 PostgreSQL réussis en 27,736 s**, aucun ignoré.
- Requalification intermédiaire après corrections HTTP/N0 : **69/69 PostgreSQL réussis en 27,736 s**, aucun ignoré.
- Préflight après durcissement : **5/5 réussis en 0,388 s**, sans moteur Docker ; mutations host PID, capacité et périphérique refusées.
- Campagne élargie C/D/E, restauration, autorités du noyau/mobilité et recertification : **121/121 PostgreSQL réussis en 115,865 s**, aucun ignoré.
- Dernière requalification après stabilisation des corrections : **69/69 PostgreSQL réussis en 39,721 s**, aucun ignoré. Elle couvre `DirectorySimulationTests`, les suites Governance workspace/concurrence/restauration, `test_mover_authority`, `test_module_activation_authority` et `test_synology_preparation`. Elle inclut les dernières courses de publication/activation de planification et d'ouverture manuelle de campagne.

Les tests d'exploitation initiaux décrits dans RT-1 démontraient volontairement l'acceptation avant correction ; ils ne sont pas comptés comme des tests de refus réussis.

Le scan source courant ajoute six couples chemin/type/empreinte aux 82 entrées antérieurement revues : trois références de facteur synthétique dans les fixtures, deux marqueurs négatifs de mot de passe inconnu et un marqueur négatif de payload fournisseur à ne pas exporter. Chacun a été relu dans son test ; aucun ancien hash n'a disparu. Seules ces six entrées sont approuvées pour la baseline de **88 détections**. Aucun répertoire applicatif, test ou détecteur supplémentaire n'est exclu. Une baseline revue n'atteste pas l'absence de tout secret inconnu dans un dépôt.

**Conclusion locale : aucun blocage applicatif supplémentaire confirmé dans le périmètre revu après correction des constats ci-dessus.** Cette conclusion reste limitée aux chemins et essais décrits, avec les portes d'exploitation suivantes ouvertes.

## Limites et portes d'exploitation

Le nombre de lectures est borné, mais les vérifications d'Observe par événement et le verrou d'organisation peuvent provoquer contention et latence. Les exceptions disposent de bornes de contenu/durée, sans quota d'écriture dédié ; les contrôles de débit et la rétention restent à qualifier avant charge réelle. Aucune résistance à un propriétaire de la base ou des clés HMAC applicatives n'est affirmée.

N0 n'est pas une qualification de conteneur : Docker Engine local est indisponible. Le fichier secret PostgreSQL applicatif doit être lisible uniquement selon l'ownership/ACL explicitement prévu pour UID 999, tout en gardant le répertoire parent privé ; des secrets Compose fondés sur fichiers ne garantissent pas une conversion automatique des permissions. Cette initialisation doit être éprouvée réellement avant N2. Le superviseur minimal et l'initialisation PostgreSQL démarrent en root dans leur conteneur ; ce point reste une revue explicite par rapport au protocole du PDF, sans revendication « zéro processus root ».

La CI Linux, les transports natifs, les budgets ressources/IO/disque, l'état courant N1, la restauration sur clone et l'accord N2/N3 restent des preuves séparées. Aucune création, mise à niveau ou perturbation d'un service existant du NAS n'est autorisée par cette revue.

## Complément indépendant — fixture HA compatible avec P0-3

La CI du candidat antérieur a correctement refusé une ancienne fixture HA sans commissionnement PAM. La correction examinée concerne les outils `deploy.active_active_trust`, `check_active_active`, `active_active_ssh/rdp` et la préparation de fixture ; elle ne modifie aucun vérificateur ou contrôle PAM du produit.

Une première ébauche transférait les clés privées des commissaire/dépositaires au processus de fixture. Cette frontière a été contestée et corrigée avant publication : le commissaire, les trois dépositaires, le témoin et les authentificateurs logiciels restent désormais en mémoire sur l'hôte du pilote. Les helpers demandent signatures et assertions via un pipe privé ; ils ne reçoivent que clés publiques, enveloppes cosignées, réponses WebAuthn et identifiants de comptes. Aucune route HTTP de signature ni montage privé n'est ajouté.

Les checkpoints publics sont signés, renouvelés avec le TTL P0-3 inchangé de 60 secondes et liés à l'installation, l'organisation, la génération et la révision. Le témoin refuse un recul ou une autre empreinte au même numéro. Le seul montage ajouté est le répertoire public nouvellement généré, à une destination fixe, en lecture seule sur chacun des deux nœuds ; l'exception ne permet pas un montage arbitraire. Les gardes de base synthétique et la vérification du routage réel sont conservées.

Le RP est aligné sur `ha.pamolive.test`. Les demandes, votes et ouvertures passent par les vrais mécanismes P0-3, avec preuves personnelles, défi, session et action exacts. Le test négatif d'une autre session de navigateur refuse le lancement et ne crée aucun relais. Les assertions sont émises par un authentificateur logiciel contrôlé par le pilote : ce dispositif ne prouve ni possession matérielle, ni indépendance de personnes physiques, ni WebAuthn dans un navigateur réel ou TLS. Voir [la qualification synthétique HA](ha-p0-trust-qualification.md).

Vérifications indépendantes sur la version stabilisée : **19/19 tests PostgreSQL réussis en 2,675 s**, aucun ignoré, base `test_pamolive_ha_redfinal` détruite. Cela inclut les quinze tests historiques de garde/orchestration et les quatre nouveaux tests d'autorité/commissionnement. Des vérifications cryptographiques adverses supplémentaires ont réellement vérifié les cosignatures Ed25519 et signatures de checkpoint, l'enrôlement/assertion WebAuthn avec la bibliothèque du projet, puis les refus d'un autre challenge, RP, origine, génération, installation ou recul de révision. Aucune privée sérialisée n'a été trouvée dans les sorties publiques de configuration/commissionnement examinées. Ruff ciblé et diff-check sont verts ; la syntaxe du pilote/hôte reste acceptée par la grammaire Python 3.8.

Le mode historique HTTP/partition conserve son fonctionnement sans Django ni bibliothèque cryptographique locale. Les options natives ajoutent explicitement `cryptography` et `cbor2` sur le pilote ; la documentation recommande l'environnement verrouillé Python 3.12 de CI et le précontrôle échoue avant démarrage si ces outils manquent. Cette nouvelle dépendance de qualification ne doit pas être présentée comme une absence de prérequis pour le mode natif Python 3.8.

**Aucun bypass de production confirmé dans la correction relue. La requalification Docker HA complète reste ouverte** : le moteur Docker local étant indisponible, ces dix-neuf tests ne démontrent pas l'exécution des deux runtimes, des pairs SSH/RDP ni des fautes réseau après correction. Les assertions originales de bascule, rejeu de ticket, capture et portée de partition sont conservées ; leur nouvelle preuve d'exécution doit venir de la CI.
