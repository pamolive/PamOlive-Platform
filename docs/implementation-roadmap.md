# Roadmap d’implémentation et qualification

Réconciliation mise à jour le 14 novembre 2026 avec *Architecture & Roadmap 2026–2029* (pages24–28) et la mission de développement autonome continu. Le programme avance par livraisons qualifiées sans confirmation humaine pour les opérations ordinaires autorisées. Cette autonomie ne permet ni contournement des protections GitHub ni utilisation de comptes ou de systèmes de production.

## Référence réellement publiée

P0 et P1-A/B1/C/D/E sont intégrés dans [main dcaa116](https://github.com/pamolive/PamOlive-Platform/commit/dcaa116be6f026f67ad3825feb38d90ac632ce80), [PR1 fusionnée](https://github.com/pamolive/PamOlive-Platform/pull/1). [CI main réussie](https://github.com/pamolive/PamOlive-Platform/actions/runs/43074618211) :931tests découverts, sortie929tests/42exclusions en702,397s ; les exclusions ne sont pas des réussites. Transports natifs, corpus dédiés, HA sur un hôte et restauration/upgrade disposent de gates séparés.

[Image publiée et attestée](https://github.com/pamolive/PamOlive-Platform/actions/runs/43078536377) : `ghcr.io/pamolive/pamolive-platform@sha256:a3e4cdb647d57cb627b0322569e58cf6760d7107793af3d9b4870ee2f6538981`, linux/amd64. Registre anonyme et attestation vérifiés indépendamment. Ce périmètre reste alpha/laboratoire, pas une qualification de production.

Le packaging Synology TLS a été réellement exécuté sur Docker Linux avec Compose2.20.1 : migrations, démonstrateur, HTTPS/MFA, isolation, redémarrage et restauration sur copie. L’ancienne instance NAS a son historique de qualification ; **cette nouvelle image n’est pas installée sur le NAS** au point de départ. Son indisponibilité ou un prérequis manquant ne bloque pas les lots suivants.

## Échelle de statut

Chaque livraison indique séparément : implémenté, testé localement, testé en laboratoire, qualifié sur l’infrastructure cible, puis éventuellement prêt pour la production. Une simulation JSON n’est pas un transport LDAP ; une lecture distante n’est pas une autorisation ; un retrait demandé n’est pas un effet confirmé ; une image publiée n’est pas un déploiement.

## P1-F — Connect / Audit, en cours

Réutiliser SCIM, TeamViewer, outbox, correspondances, reprises et reçus existants. Écart immédiat : les prévisualisations AD/LDAP/Entra sont éphémères et sans transport.

| Livraison | Travail | Réception exigée | Statut |
| --- | --- | --- | --- |
| F1 inventaire | Sources immuables liées à destination/identité TLS, observations persistantes, runs signés et mappings explicites ; vues/API/exports paginés | Deux sources/deux tenants avec mêmes UUID, historique et absence incertaine conservés, aucun droit créé | Implémenté, tests ciblés locaux réussis ; promotion bloquée par le runtime |
| F2 lecteurs | LDAP/AD read-only, pagination et identifiants stables ; préparation Graph tenant-scoped ; serveurs factices TLS | Mauvais pin refusé avant secret, referrals/downgrade refusés, pagination bornée, erreurs partielles sans suppression | StartTLS synthétique local et130tests Directory dans deux CI95fe14f réussis ; LDAPS refusé et Graph partiel ; runtime final non promu |
| F3 rapprochement | Rapprocher inventaire, comptes IAM et confirmations SCIM/TeamViewer sans confondre autorités | Collisions visibles, reprises idempotentes,200identique/409divergent, contexte source historique des retraits conservé | Branche locale séparée `ece41d6`, routes intégrées,105tests PG et contre-revue45/45 ; aucun push ni activation dans main |
| F4 livraison | Migrations/restauration, export auditable, quotas, supervision et revues adverses | PostgreSQL réel, concurrence, rôles restreints, régressions P0, CI et promotion qualifiée | Campagnes locales partielles réalisées ; gate de scan strict ajouté, promotion bloquée |

Le [candidat PR2](https://github.com/pamolive/PamOlive-Platform/pull/2) reste en brouillon. La première analyse exhaustive de son image a détecté des dépendances Python/FreeRDP vulnérables : aucune fusion ou publication de ce runtime n’est autorisée par ses seuls tests applicatifs. [ADR-019](adr-019-native-runtime-dependencies.md) retient une base corrigée et FreeRDP maintenu compilé depuis une source signée, puis une nouvelle qualification complète et un inventaire des bibliothèques réellement chargées. Le [rapport de scan initial](p1-f-image-security.md) conserve tous les findings ; les travaux de remédiation ne constituent pas encore un résultat vert. Les répertoires F3 et revues P2 du checkout restent distincts du candidat F1/F2.

Mise à jour du12novembre : les deux CI95fe14f passent leurs portes fonctionnelles/PG/natives/HA/restauration mais échouent avant verdict complet du scanner, puis au nettoyage LDAP. Les corrections locales sont testées ; le scanner B2 termine sous son nouveau quota et conserve ses High. B3r3 reconstruit le backport Kerberos après les diagnostics ASN.1 avant/après12cas réussis ; aucun paquet ou runtime B3 n'est encore qualifié. Les35groupes High restent non arbitrés, malgré des propositions individuelles documentées. Les nouveaux formats de décision de build ne constituent aucune exception activée.

Au14novembre, B3r4 est construit et passe les essais N0 de transport, TLS/SCRAM,
extensions et restauration réelle. B3r6 passe ensuite les régressions P0,
la sonde embarquée avec init et le scan frais :35groupes High restent non arbitrés.
Les deux CI `7bfbe18` échouent à la bascule entre deux nœuds malgré une sécurité
réussie. Le [rapport daté](p1-f-qualification-20261114.md) sépare ces sujets.
L'intégration des entrées Python hashées et hors réseau attend son build exact ;
la chaîne des matériaux/attestations ADR021 reste requise. Aucune High n'est neutralisée et aucun nouveau digest
n'est promu par ces seuls essais. La primitive d'enveloppe P2 est conservée dans
la branche locale distincte `agent/p2-vault-envelope`, commit `177df2b` :25tests,
huit sondes cryptographiques indépendantes et wheel installée testée ; aucun
service Vault, registre ou chemin PAM P2 n'est encore livré.

ADR de travail : [ADR-018](adr-018-directory-inventory.md). Les écrivains/provisioning réels restent désactivés tant que leur destination, leurs permissions et leur périmètre ne sont pas qualifiés. Les faits d’annuaire ne deviennent jamais une attestation indépendante PAM.

## P1-G — portail complet, après F

Parcours Identity360 → intention/ticket → politique → approbation indépendante → exécution ou session → observation → évaluation/preuve → audit → retrait confirmé. Conserver le portail serveur natif olive/noir, sans Django admin comme interface métier.

Scénarios : arrivée/mobilité/départ, fournisseur, privilège temporaire, expiration, tentative hors périmètre et provenance insuffisante. Réception : deux tenants aux modules différents, UI/API/MFA/sessions/exports/erreurs, accès clavier/accessibilité, captures de démonstration, cibles et données synthétiques. Les personnes et autorités simulées ne prouvent pas l’indépendance d’humains réels.

Premier incrément local séparé : Identity360 propose le formulaire de demande existant prérempli avec identité/compte, sous rôle et module autorisés. GET ne crée aucune autorité et n'alimente jamais un POST incomplet.17tests de routes réelles, les8parcours HTTPS et21tests Identity360 passent en12,795s ; la non-régression F3 passe63/63. Le coordinateur rejoue indépendamment les17nouveaux cas en4,266s. La revue contradictoire finale, la CI/image, le navigateur headless et le parcours PAM complet restent à effectuer ; P1-G n'est pas déclaré terminé.

## P2 — architecture hybride et domaines sensibles

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
