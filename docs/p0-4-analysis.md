# P0-4 · Reproduction et préparation de la provenance des événements

**Photographie de la vulnérabilité avant correction, établie le 11 novembre 2026.** Le responsable du projet a ensuite accepté l'option C de l'[ADR-014](adr-014-event-provenance.md) pour une implémentation locale. Ce document conserve la chaîne d'attaque et les résultats initiaux ; les tests de reproduction sont convertis en régressions et le bilan du correctif est tenu dans [la validation P0-4](p0-4-validation.md). Aucun NAS, annuaire, collecteur ou compte privilégié réel n'a été contacté.

## Chaîne d'exécution et conditions d'exploitation

1. Un opérateur ou administrateur d'organisation, connecté avec MFA récent, soumet `/records/event/new/`. Le formulaire accepte `source` et `external_id` comme chaînes libres. [Formulaire et entrée HTTP](../platform_modules/access/ui.py#L99)
2. `ingest_event` vérifie l'acteur et son organisation, mais ne rattache pas le texte `source` à l'autorité manuelle. Pour un collecteur, la même fonction remplace ce texte par le UUID de l'`EventSource` authentifié. Elle réserve seulement l'espace `managed:`. [Ingestion](../platform_modules/access/services.py#L87)
3. Sous verrou de l'organisation, le service cherche la première ligne ayant les mêmes `source` et `external_id` et la renvoie sans comparer les faits. L'unicité SQL `(organisation, source, external_id)` empêche une seconde ligne. [Service](../platform_modules/access/services.py#L102) · [Modèle](../platform_modules/access/models.py#L224)
4. L'API Bearer déduit le collecteur du jeton et rejette un champ `source` dans la requête, mais son propre appel à `ingest_event` trouve la ligne manuelle. Elle renvoie `200`, `created: false` et l'identifiant de cette ligne. [Authentification du collecteur](../platform_modules/connectors/services.py#L32) · [API](../platform_modules/access/ui.py#L814)

L'attaque ciblée nécessite un rôle autorisé à saisir des événements, un MFA récent, le UUID d'un collecteur de la même organisation et un identifiant externe futur connu, prévisible ou réutilisé. Un export d'événement déjà visible aux rôles autorisés révèle le UUID de ce collecteur. La campagne ne démontre pas comment prédire tous les identifiants d'un collecteur neuf. Aucun jeton de collecteur n'est nécessaire à l'attaquant pour la collision manuelle. La portée vérifiée reste celle d'une seule organisation.

## Preuves reproductibles

Les fixtures créent des organisations, comptes, MFA TOTP, ressources, collecteurs, jetons et événements synthétiques. Elles passent par les vues Django réelles et l'API Bearer, sans connexion réseau à une cible. [Reproduction HTTP et concurrence](../tests/test_event_provenance_reproduction.py) · [Effets sur les preuves et décisions](../tests/test_event_provenance_effects.py)

| Scénario | Avant correction, reproduit | Garantie du correctif local |
| --- | --- | --- |
| Saisie manuelle avant le collecteur, faits divergents | Le collecteur reçoit `200` et l'ID de la ligne manuelle ; l'observation authentique n'est pas créée. | `201` et une ligne `collector` distincte malgré le même texte et identifiant. |
| Livraison authentique retardée de 45 jours | Trois livraisons retrouvent toujours la ligne manuelle. | La livraison est liée au principal collecteur, quel que soit son délai. |
| Saisie manuelle après un événement authentique | Le formulaire retrouve l'événement du collecteur malgré ses propres faits divergents. | La saisie manuelle possède son propre espace et son propre principal. |
| Rejeu authentifié identique | `200`, même ID, sans nouvel audit : protection à conserver. | Même comportement, contrôlé par comparaison canonique. |
| Rejeu authentifié divergent | `200`, même ID, aucune trace de conflit. | `409` et conflit audité, sans écraser l'original. |
| Deux collecteurs, même identifiant externe | Deux événements indépendants : protection à conserver. | Même séparation par principal stable. |
| Deux organisations, même texte et identifiant | Deux événements indépendants : protection à conserver. | Même isolation, y compris au niveau SQL. |
| Jeton faux, source fournie par le client, référence étrangère ou collecteur désactivé | Refus observés. | Refus conservés et revalidation de l'état sous verrou. |
| Espace `managed:` et possession de certificat | Saisie manuelle `managed:` refusée ; une collision manuelle ne satisfait pas le défi de possession. | Protection conservée ; la preuve de certificat doit viser une provenance typée. |
| Concurrence PostgreSQL : transaction manuelle gagnante | Le collecteur attend le verrou puis reçoit `200` et la ligne manuelle. | Les deux canaux peuvent coexister ; aucun faux accusé de réception. |
| Concurrence PostgreSQL : deux contenus divergents du collecteur | Une réponse `201`, une réponse `200`, même ID ; divergence non signalée. | Une réponse `201`, une réponse `409` ; un seul événement original. |

Les oracles `assert_independent_authorities` et `assert_divergent_replay_conflict` du test de reproduction avaient échoué avant correction. Ils sont conservés comme assertions positives dans la suite de régression P0-4, avec des tests supplémentaires pour les nouveaux champs, reçus et index.

**Exécution initiale avant correction :** SQLite, `14 tests`, `12 réussis`, `2 tests de concurrence ignorés car PostgreSQL requis`. PostgreSQL 17.11 temporaire, lié uniquement à `127.0.0.1` sur un port éphémère, base de tests préfixée `test_pamolive_`, `14 tests réussis` dont les deux scénarios concurrents ; le serveur temporaire a été arrêté après le passage. Les deux environnements ont utilisé des clés et identités de test. Ces résultats caractérisent le comportement vulnérable initial, pas une installation client.

## Portée des conséquences et protections

Un événement manuel forgé peut recevoir un verdict `expected` avec une évaluation V7 valide, une chaîne d'audit valide et un export indiquant le UUID du collecteur. Le collecteur authentifié peut ensuite signaler des faits `failure` divergents qui sont perdus sans conflit. Un événement manuel dont le texte `source` ressemble au UUID du collecteur hérite aussi, dans les tests, du rapport d'horloge et de la couverture de ce collecteur. [Évaluation et signature](../platform_modules/access/evidence.py#L11) · [Horloge](../platform_modules/intelligence/coverage.py#L97) · [Interprétation temporelle](../platform_modules/access/temporal.py#L122)

Le test compare avant/après les identifiants de `Grant`, `AccessIntent`, `ApprovalDecision`, `SessionLease`, `RelayConnection`, `PAMTrustRevision` et `ExternalChange` : aucun droit, mandat, ticket ou relais n'est créé directement. La revue du chemin PAM confirme le contrôle distinct des intentions approuvées, du registre et de la destination. La conséquence démontrée porte sur l'intégrité des observations, des exports, des alertes et des décisions humaines fondées sur ces preuves ; elle ne démontre pas une ouverture PAM directe. [Contrôles PAM](../platform_modules/pam/services.py#L17) · [Ouverture du relais](../platform_modules/pam/sessions.py#L388)

Protections effectives à préserver : séparation des organisations ; authentification Bearer et refus du champ `source` côté API ; vérification des références liées à l'organisation ; espace `managed:` réservé ; possession de certificat basée sur une ingestion auditée sans acteur manuel ; signature et vérification des faits enregistrés ; contrôles P0-1 à P0-3. Ces signatures prouvent l'intégrité de l'état accepté par PamOlive, pas la provenance physique de la télémétrie. [Possession](../platform_modules/access/certificate_possession.py#L151) · [Audit](../platform_core/audit.py#L9)

Deux risques supplémentaires restent à valider : un flot de nombreux identifiants uniques pourrait saturer stockage et verrou d'organisation malgré la limite de corps HTTP de 64 Kio ; la révocation d'un collecteur pourrait courir avec la vérification préliminaire du jeton. Aucun essai de charge ni interleaving déterministe de révocation n'a été exécuté. Le service permet aussi à un appel interne de fournir simultanément `actor` et `source` : les endpoints HTTP actuels ne le font pas, mais la future frontière de service devra le refuser.

## Plan de fichiers établi avant autorisation

| Domaine | Cibles précises | Travail prévu |
| --- | --- | --- |
| Autorité et jetons | `platform_modules/connectors/models.py`, `services.py`, migration `connectors/0012` | Principal stable `EventSource`, génération ou référence du justificatif, revalidation sous verrou. Ne pas faire de la rotation un nouvel espace de déduplication. |
| Événement, reçu, contraintes | `platform_modules/access/models.py`, `services.py`, migrations `access/0015` et éventuellement `0016` | Canal/principal typés, empreinte canonique, reçu et conflit, contraintes partielles, suppression de l'unicité globale, vérification tenant et immutabilité. |
| HTTP et producteurs | `platform_modules/access/ui.py`, `platform_modules/connectors/teamviewer_access.py` | Assigner la provenance côté serveur, rejeter JSON ambigu, exposer `409`, adapter le rédacteur TeamViewer à l'autorité interne. |
| Preuve et consommateurs | `platform_modules/access/observations.py`, `evidence.py`, `certificate_possession.py`, `temporal.py`, `platform_modules/intelligence/coverage.py`, `projection.py` | Préserver V7, ajouter reçu V8, attribuer horloge/confiance par principal typé, présenter explicitement le niveau de provenance. |
| Opérations et contrôle | `deploy/controlled_upgrade.py`, vérificateurs de restauration, docs d'API et de migration | Arrêter les anciens rédacteurs pour la bascule, vérifier l'historique, index et reçus, documenter retour arrière et réconciliation. |

Les tests demandés après ce plan étaient : collision manuelle/collecteur et histoire cohabitante ; rejouages exacts/divergents, y compris concurrence PostgreSQL ; deux organisations et deux collecteurs avec mêmes identifiants ; rotation, révocation et course sous verrou ; migration aller/retour compatible avec les preuves V7 ; immutabilité du reçu ; possession de certificat et normalisation TeamViewer ; exports, alertes, couverture et horloge ; quotas et débit avec un seuil explicite ; non-régression P0-1, P0-2, P0-3 et absence de création de droit/PAM par la seule observation. Le résultat de leur exécution et les fichiers effectivement modifiés figurent dans [la validation locale](p0-4-validation.md).

## Revue contradictoire, Blue Team et Red Team

**Blue Team AppSec :** exploitation confirmée par les endpoints réels. Le UUID n'est pas un secret : l'export autorisé le montre après un premier événement. Le futur identifiant externe reste une condition d'attaque. Elle demande l'inventaire de tous les rédacteurs avant les contraintes SQL, l'arrêt des anciens binaires et une validation active du collecteur sous verrou.

**Blue Team cryptographie :** V7 signe les faits stockés. Le reçu V8 proposé doit attester l'acceptation par le serveur, conserver les vérificateurs V7 et maintenir une clé de vérification historique. Il ne peut pas prouver la vérité d'une source distante. Toutes les anciennes lignes restent `legacy_unknown` et les événements perdus ne sont pas reconstructibles depuis la base seule.

**Blue Team IAM/IGA/PAM :** impact confirmé sur les preuves et l'interprétation, sans voie directe démontrée vers le bail ou le relais privilégié. Le texte `source` ne doit plus conférer l'horloge d'un collecteur ; les gardes P0-2/P0-3 demeurent indépendantes.

**Red Team :** reproduction indépendante de la collision et du faux accusé de réception, avec les mêmes conditions d'attaque. Le test de certificat de possession résiste. La suppression de l'unicité globale est indispensable ; sinon la correction de surface laisse les lignes historiques empoisonnées bloquer la nouvelle ingestion. La saturation, la course à la révocation et l'appel interne à double autorité sont des points de test complémentaires, pas des contournements HTTP démontrés.

Le consensus est l'option C de l'ADR, avec ces limites explicites. Aucun spécialiste n'a établi qu'un faux événement ouvrait directement une session PAM. La revue n'a pas été étendue à des installations ni à des cibles réelles.

## Feuille de route consolidée après les quatre P0

1. **Avant tout pilote privilégié :** autoriser, implémenter et valider P0-4, puis qualifier opérationnellement P0-3 : témoin indépendant effectivement déployé, cérémonie de commissionnement, vérification des personnes et clés, restauration et révocations. Les transports natifs Linux et la séparation entre applications et clés restent à qualifier. [Limites P0-3](p0-3-validation.md)
2. **Isoler l'exécution et les secrets :** séparer portail, courtier PAM et coffre ; limiter chaque processus à ses clés et capacités strictes. Lier la libération des secrets aux autorisations P0-2/P0-3 et à l'identité exacte de la cible. Segmenter les sorties des travailleurs et du relais ; borner temps, fréquence et destination.
3. **Réduire le pouvoir PostgreSQL :** propriétaire et migrateur distincts du rôle d'exécution ; rôle applicatif sans DDL, `TRUNCATE`, changement de rôle ou accès global ; contraintes multi-organisations et transactions vérifiées. Tester restauration, révocation concurrente et partitions sur PostgreSQL réel isolé.
4. **Rendre l'audit vérifiable hors base :** reçus versionnés, clés isolées, points de contrôle signés et ancrage externe append-only/WORM. La chaîne SHA-256 actuelle ne résiste pas seule à un acteur pouvant réécrire la base et recalculer la chaîne. Préserver l'accès aux anciennes clés de vérification.
5. **Qualifier réseau et transports PAM :** TLS avec validation complète, politiques de sortie, épinglage SSH/RDP et refus des changements d'identité cryptographique, tunnels et redirections contrôlés, tests de panne et charge en HA. Vérifier la capture, la coupure, le routage des révocations et la restauration sur cibles de laboratoire uniquement.
6. **Sauvegarde et reprise :** sauvegardes chiffrées, restauration testée, comparaison anti-retour arrière avec témoin indépendant, réconciliation des jetons, sessions, reçus et révocations ; mesurer RPO/RTO sans réactiver une autorisation ou destination ancienne.
7. **Préparer la cryptographie post-quantique :** inventorier les usages et dépendances, garder l'agilité des algorithmes et des formats de preuve, archiver les clés publiques et algorithmes historiques, tester des pilotes hybrides standardisés hors production. Une double signature par la même personne ne compte jamais comme deux approbateurs. Ne présumer ni le support effectif d'OpenSSH dans libssh2 ni celui de TLS hybride dans le relais RDP. Références : [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final), [SP 800-227](https://csrc.nist.gov/pubs/sp/800/227/final).
8. **Étendre les fonctions métier après consolidation :** IAM/IGA avec sources d'identité attestées, revue et retrait d'habilitations ; PAM avec disponibilité et reprise contrôlées ; gestionnaire de mots de passe seulement avec modèle de chiffrement de bout en bout et racine de confiance distincte. Chaque extension doit conserver la preuve de destination, de personne et de provenance et être testée entre organisations.

Cette feuille de route est une séquence de risques et dépendances, pas une déclaration de qualification des installations existantes.
