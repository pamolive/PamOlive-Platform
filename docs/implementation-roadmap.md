# Roadmap d’implémentation et qualification

Réconciliation mise à jour le 14 novembre 2026 avec *Architecture & Roadmap 2026–2029* (pages24–28) et la mission de développement autonome continu. Le programme avance par livraisons qualifiées sans confirmation humaine pour les opérations ordinaires autorisées. Cette autonomie ne permet ni contournement des protections GitHub ni utilisation de comptes ou de systèmes de production.

## Référence réellement publiée

P0 et P1-A/B1/C/D/E sont intégrés dans [main dcaa116](https://github.com/pamolive/PamOlive-Platform/commit/dcaa116be6f026f67ad3825feb38d90ac632ce80), [PR1 fusionnée](https://github.com/pamolive/PamOlive-Platform/pull/1). [CI main réussie](https://github.com/pamolive/PamOlive-Platform/actions/runs/43074618211) :931tests découverts, sortie929tests/42exclusions en702,397s ; les exclusions ne sont pas des réussites. Transports natifs, corpus dédiés, HA sur un hôte et restauration/upgrade disposent de gates séparés.

[Image publiée et attestée](https://github.com/pamolive/PamOlive-Platform/actions/runs/43078536377) : `ghcr.io/pamolive/pamolive-platform@sha256:a3e4cdb647d57cb627b0322569e58cf6760d7107793af3d9b4870ee2f6538981`, linux/amd64. Registre anonyme et attestation vérifiés indépendamment. Ce périmètre reste alpha/laboratoire, pas une qualification de production.

Cette référence publiée précède les remédiations de dépendances Python et
FreeRDP documentées depuis l'audit d'image. Elle ne doit pas être utilisée
avec des comptes privilégiés réels. Une attestation de publication ne supprime
pas ces vulnérabilités ; aucune nouvelle image corrigée n'est encore promue.

Le packaging Synology TLS a été réellement exécuté sur Docker Linux avec Compose2.20.1 : migrations, démonstrateur, HTTPS/MFA, isolation, redémarrage et restauration sur copie. L’ancienne instance NAS a son historique de qualification ; **cette nouvelle image n’est pas installée sur le NAS** au point de départ. Son indisponibilité ou un prérequis manquant ne bloque pas les lots suivants.

## Échelle de statut

Chaque livraison indique séparément : implémenté, testé localement, testé en laboratoire, qualifié sur l’infrastructure cible, puis éventuellement prêt pour la production. Une simulation JSON n’est pas un transport LDAP ; une lecture distante n’est pas une autorisation ; un retrait demandé n’est pas un effet confirmé ; une image publiée n’est pas un déploiement.

## P1-F — Connect / Audit, en cours

Réutiliser SCIM, TeamViewer, outbox, correspondances, reprises et reçus existants. Écart immédiat : les prévisualisations AD/LDAP/Entra sont éphémères et sans transport.

| Livraison | Travail | Réception exigée | Statut |
| --- | --- | --- | --- |
| F1 inventaire | Sources immuables liées à destination/identité TLS, observations persistantes, runs signés et mappings explicites ; vues/API/exports paginés | Deux sources/deux tenants avec mêmes UUID, historique et absence incertaine conservés, aucun droit créé | Implémenté, tests ciblés locaux réussis ; promotion bloquée par le runtime |
| F2 lecteurs | LDAP/AD read-only, pagination et identifiants stables ; préparation Graph tenant-scoped ; serveurs factices TLS | Mauvais pin refusé avant secret, referrals/downgrade refusés, pagination bornée, erreurs partielles sans suppression | StartTLS synthétique local et130tests Directory dans deux CI95fe14f réussis ; LDAPS refusé et Graph partiel ; runtime final non promu |
| F3 rapprochement | Rapprocher inventaire, comptes IAM et confirmations SCIM/TeamViewer sans confondre autorités | Collisions visibles, reprises idempotentes,200identique/409divergent, contexte source historique des retraits conservé | Réuni avec G/P2 dans PR3 `09b6fa43` ; 134/134 PG locaux et portes fonctionnelles CI réussies ; promotion bloquée par les 35 groupes High |
| F4 livraison | Migrations/restauration, export auditable, quotas, supervision et revues adverses | PostgreSQL réel, concurrence, rôles restreints, régressions P0, CI et promotion qualifiée | Campagnes locales partielles réalisées ; gate de scan strict ajouté, promotion bloquée |

Le [candidat PR2](https://github.com/pamolive/PamOlive-Platform/pull/2) reste en brouillon. La première analyse exhaustive de son image a détecté des dépendances Python/FreeRDP vulnérables : aucune fusion ou publication de ce runtime n’est autorisée par ses seuls tests applicatifs. [ADR-019](adr-019-native-runtime-dependencies.md) retient une base corrigée et FreeRDP maintenu compilé depuis une source signée, puis une nouvelle qualification complète et un inventaire des bibliothèques réellement chargées. Le [rapport de scan initial](p1-f-image-security.md) conserve tous les findings ; les travaux de remédiation ne constituent pas encore un résultat vert. Les répertoires F3 et revues P2 du checkout restent distincts du candidat F1/F2.

Mise à jour du12novembre : les deux CI95fe14f passent leurs portes fonctionnelles/PG/natives/HA/restauration mais échouent avant verdict complet du scanner, puis au nettoyage LDAP. Les corrections locales sont testées ; le scanner B2 termine sous son nouveau quota et conserve ses High. B3r3 reconstruit le backport Kerberos après les diagnostics ASN.1 avant/après12cas réussis ; aucun paquet ou runtime B3 n'est encore qualifié. Les35groupes High restent non arbitrés, malgré des propositions individuelles documentées. Les nouveaux formats de décision de build ne constituent aucune exception activée.

Au 14 novembre, le socle courant est `2f28224`. Ses deux CI passent les portes
fonctionnelles, 1345 tests généraux comptés / 42 exclusions, les transports
SSH/RDP et la qualification à deux nœuds avec partition de route PostgreSQL
sur un même hôte, puis restauration et retour arrière. Elles échouent au seul
gate final de scan : 35 groupes High non arbitrés, zéro Critical. Les jobs de
sécurité du code réussissent. Les échecs précédents restent historiques dans
le [rapport daté](p1-f-qualification-20261114.md) et les preuves de PR2.
Le sujet local R8-r2 valide la correction ensurepip par deux vrais venvs hors
réseau avec pip 26.3 ; aucune suppression des couches historiques n'est prétendue.
La chaîne des matériaux APT/SDK/compilateur et attestations ADR-021 demeure
incomplète ; aucune exception ni promotion ne découle de ces résultats.

La [fusion locale F3/G/P2](p1-fg-p2-integration-20261114.md) `4c9cd2b` réunit
les fonctionnalités des branches préservées : 134/134 tests PostgreSQL sans
exclusion, 25 tests enveloppe et 17 tests contrats, revue indépendante et scan
de secrets sur 698 fichiers réussis. La branche PR3 `09b6fa43` ajoute la CI
des bibliothèques installées, réussie dans ses deux runs, avec les contrôles
de sécurité du code. Les 1433 tests généraux comptés / 42 exclusions, transports,
HA même hôte avec partition et restauration passent ; seul le scan final
refuse les 35 groupes High. Aucun
service Vault, registre, ledger ou nouveau chemin PAM P2 n'est livré.

ADR de travail : [ADR-018](adr-018-directory-inventory.md). Les écrivains/provisioning réels restent désactivés tant que leur destination, leurs permissions et leur périmètre ne sont pas qualifiés. Les faits d’annuaire ne deviennent jamais une attestation indépendante PAM.

## P1-G — portail complet, après F

Parcours Identity360 → intention/ticket → politique → approbation indépendante → exécution ou session → observation → évaluation/preuve → audit → retrait confirmé. Conserver le portail serveur natif olive/noir, sans Django admin comme interface métier.

Scénarios : arrivée/mobilité/départ, fournisseur, privilège temporaire, expiration, tentative hors périmètre et provenance insuffisante. Réception : deux tenants aux modules différents, UI/API/MFA/sessions/exports/erreurs, accès clavier/accessibilité, captures de démonstration, cibles et données synthétiques. Les personnes et autorités simulées ne prouvent pas l’indépendance d’humains réels.

Premier incrément réuni dans PR3 : Identity360 propose le formulaire existant prérempli avec identité/compte, sous rôle et module autorisés. GET ne crée aucune autorité et n'alimente jamais un POST incomplet. Les tests des routes et du parcours HTTPS participent aux 134 cas PostgreSQL intégrés ; le service conserve la revalidation de l'autorité sous verrou corrigée dans le socle. Les CI de `09b6fa43` sont terminées avec les limites ci-dessus ; la CI du correctif suivant, la promotion qualifiée et le navigateur headless restent requis. P1-G n'est pas déclaré terminé.

Le [complément HTTP PAM](p1-g-pam-http-validation.md) passe ensuite 5/5 cas
jusqu'au ticket pending, à l'arrêt et à l'audit, avec correction de rendu
et conservation des autorités existantes. La régression de 29 modules compte
324 réussites et une exclusion SQLite attendue sur 325, contrepartie PG
réussie. La qualification navigateur/JavaScript reste distincte et non exécutée.

## P2 — architecture hybride et domaines sensibles

### État courant du 15 novembre

La [PR #6](https://github.com/pamolive/PamOlive-Platform/pull/6), head `67ee7c9`,
reste en brouillon. Les deux CI Platform exactes passent les portes exécutées,
dont acquisition/build et exclusion post-build des credentials, 52 purs Vault,
PostgreSQL, natives, SSH/RDP, HA même hôte, restauration et Compose. Elles refusent
uniquement les 35 groupes High ; la provenance de build reste incomplète.
La suite générale annonce 1 457 tests / 42 entrées Skip (40 méthodes et deux
classes), plus deux marqueurs séparés de 1 skip ; aucun calcul par soustraction
n'est présenté comme réussite. Le vérificateur public installé reçoit séparément
30 tests sans skip. Le timeout TLS du push parent `6c17536` reste un échec
historique distinct, sans transfert rétrospectif du succès courant. Résultats et
corrigenda dans [l'état d'implémentation](implementation-status.md).
Aucun merge main ni image nouvelle.

Le vérificateur public V1 du head `bd8d228` a reçu ses 30 tests installés sans
exclusion dans deux CI dédiées ; les contrôles P0 et leurs appelants demeurent
distincts. Les deux CI Platform exactes passent leurs portes fonctionnelles,
1 439 tests généraux comptés dont 42 exclusions et restauration, puis refusent
les 35 groupes High non arbitrés, zéro Critical. Aucune promotion n'en découle.

Le [lot vertical de réservation Vault](p2-vault-reservation-runtime.md) intègre
les sources R2 sous [ADR-024](adr-024-vault-reservation-boundary.md) : 51 purs et
dix méthodes mTLS/PostgreSQL réellement reçues sur un laboratoire synthétique.
Le bind N0 est ensuite limité aux deux adresses exactes, avec un cas pur ajouté
(52 au total). Un laboratoire distinct reçoit deux nouveaux cas : vrai restart
du service avec PG conservé et writer client jetable sorti par `os._exit(73)`
après commit, puis retry mTLS avec même ligne/dates/nonce privé/audit. Le bind
privé exact est corroboré par code épinglé et TLS. Les dix anciens cas wildcard
restent historiques, sans rejeu ; aucune CI Vault réelle encore.
Slot administré hors Web, DER par connexion, runtime SQL non-owner et retry
durable aboutissent seulement à `pending_proofs`, sans secret ni autorité d'action.
Pas de migration Django, service de production, Vault installé ou image minimale.

La réception des deux cas confirme les faits H1, 190 clients CLI récoltés/drainés,
six stdin complets et nettoyage 4/3/1, lease libre et PG inchangé. Les 18 retours
non nuls sont des sondes readiness avant succès ; les quatre exits 137 sans OOM
sont les arrêts de nettoyage prévus. Restent les lots crash réel du serveur et
PG power-loss, perte réseau réelle, expiration attendue, backup/restore avec
nouvelle incarnation et frontière OS Web hostile. L'ancrage indépendant des
usages/compteurs reste nécessaire avant
toute remise ; une tête PAM fraîche ne détecte pas un rollback clandestin du
ledger sous la même incarnation. Ces sources ne soldent ni P2 ni les High.

Premier essai de restauration logique : dump/restauration sous rôle restreint
vers une seconde base synthétique et refus 403 de l'ancien contexte reçus, mais
probe finale après commissionnement en échec. Conserver ce refus et diagnostiquer
avant un nouveau lot ; ne pas prolonger la fenêtre 40 s / TTL 30 s pour réussir.
Nettoyage local complet et PG historique inchangé. Restauration complète, PITR
et reprise sur hôtes indépendants restent à qualifier.

### Historique des préparations et premiers refus

Premier complément du15novembre :
[R1b.1 matériaux publics PAM](p2-public-material-verifier.md), source locale
`77613e8`, ajoute la bibliothèque pure selon [ADR-023](adr-023-public-pam-material-verifier.md).
Les30tests de source et30tests purs d'adaptateur passent, avec13matériaux
audités. Les deux premières CI installées du `7083a96` rendent42 avec nettoyage
confirmé ; la remontée de leur diagnostic interne est corrigée sous revue,
avec57tests purs et cinq contre-cas AppSec. La réception installée reste ouverte.
Cette préparation ne fournit aucun service, contexte commissionné, permission
d'action, ledger ou remise. La correction du banc sur l'incertitude des clients
est conservée. Les décisions de détection Linux sont rapprochées individuellement
des fixtures publiques revues, sans modifier filtres ou seuils. Les prochains contrats devront lier
les actions au transcript V2 puis traiter les compteurs et la consommation
durable ; le registre public ne suffit pas à autoriser une session.

Le monolithe modulaire conserve Identity/Governance/Observe/Connect/Audit métier/Machine/Cloud/Defense/Posture et les contrats d’organisation. Séparer progressivement Web/API, worker, broker PAM, Vault, PostgreSQL, gateway, témoin et gestion des clés. Ne pas créer onze microservices.

1. ADR de frontières et contrats versionnés ; identités de service, authentification mutuelle, audiences, opérations autorisées, timeouts et comportements fail-closed. Aucun fallback silencieux vers un ancien chemin lorsque le nouveau composant est indisponible.
2. Vault indépendant : chiffrement à enveloppe, clés par tenant/domaine, gestion des clés séparée, versions/rotation/récupération. Domaine utilisateur et domaine technique distincts ; MFA révélation/export ; aucune revendication zero-knowledge si le serveur déchiffre.
3. Broker isolé : vérification indépendante des mandats/quorum P0-3, capacités tenant/session/destination/credentialversion/TTL/nonce, relais SSH/RDP, révocation et captures ; aucune clé maîtresse Vault dans le broker et aucun secret technique dans Web/navigateur.
4. Audit témoin séparé : clés et autorité distinctes, checkpoints anti-retour arrière, historique V7/V8, exports SIEM, rétention/quota/rotation.
5. Exploitation : rôle migration distinct du runtime sans DDL, backup/PITR/restauration, métriques/alertes/circuit breakers, tests de panne et charge sur infrastructure dédiée. Ancien chemin maintenu explicitement tant que sa migration n’est pas qualifiée.

Réception par composant : revue cryptographique indépendante, fuite simulée et compromission Web/worker/broker, isolation tenant, révocation pendant session, restauration multi-version et preuves historiques. Docker sur un seul hôte ne constitue pas une indépendance de production. KMS/HSM et plusieurs hôtes réels nécessitent leur qualification dédiée ; une absence d’infrastructure est documentée sans arrêter les autres travaux.

## P3 — capacités enterprise puis qualification

- Privilège : JIT/JEA, commandes/profils/contextes et élévation temporaire explicites, sans assimiler le compte OS complet à du moindre privilège.
- Machine/NHI : comptes techniques/workloads, propriétaires, certificats, fédération et rotation, orphelins et preuve de possession.
- Cloud/CIEM : adaptateurs d’inventaire initialement read-only, permissions effectives et chemins d’élévation explicables, recommandations sans remédiation destructive implicite.
- Defense/ITDR/ISPM : règles versionnées avec confiance/source/explication, dérives, comptes à risque, MFA et postures ; réponses contrôlées.
- Gouvernance avancée : délégations, revues de risque/SoD/fournisseurs, politiques contextuelles et rapports.
- Qualification dédiée : deux hôtes, pertes DB/broker/Vault, transports Windows/SSH, interruptions/révocation, concurrence/charge/mémoire/disque/rétention, reprise et protections cryptographiques. Ne pas annoncer enterprise/production à partir de tests unitaires.

## Porte commune à chaque livraison

Tests unitaires/intégration, PostgreSQL réel, permissions/tenants/concurrence, migrations et retour arrière sur copie, restauration, Docker, Ruff/Django, dépendances/SBOM/secrets et revue Red Team. Les échecs sont corrigés ; les exclusions et limites sont explicites. Pour Vault/PAM : revue crypto et tests de fuite/panne/révocation obligatoires.

Branche → modifications/tests/revue → commit/push/PR → CI vérifiée → fusion conforme aux protections → CI du main exact → promotion de son image sans rebuild → digest/attestation vérifiés → statut mis à jour → lot suivant. Aucun force-push destructeur, aucune désactivation de protection, aucune publication arbitraire stable/latest.

## Relation avec l’ancien ordre d’implémentation

L’ancien document décrivait contrats → noyau → IAM → gouvernance → PAM. Ce sont des dépendances historiques déjà partiellement ou largement implémentées, pas de nouveaux lots à réécrire. Les ADR encore proposés restent visibles dans leur index ; l’autonomie technique ne les rend pas rétroactivement qualifiés. Le worker/outbox PostgreSQL actuel est réutilisé ; Redis n’est pas ajouté sans besoin démontré et ADR.
