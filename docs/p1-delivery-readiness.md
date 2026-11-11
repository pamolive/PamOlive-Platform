# P1-A à P1-E : préparation de livraison

État au 11 novembre 2026. Candidat fonctionnel : `d247ed5639bc326b28331a791fdb0eca605fb955`, branche `agent/p1-a-b1-review`, [PR #1](https://github.com/pamolive/PamOlive-Platform/pull/1). Cette note complète les rapports historiques ; elle ne remplace pas une qualification du commit qui lui succéderait.

## Preuves GitHub

Les runs [push 43056154739](https://github.com/pamolive/PamOlive-Platform/actions/runs/43056154739) et [PR 43056166692](https://github.com/pamolive/PamOlive-Platform/actions/runs/43056166692) sont terminés avec succès, jobs sécurité et PostgreSQL/Docker. Leurs contrôles comprennent migrations, régressions P0, isolation des organisations/modules, OIDC, extensions signées, SSH/RDP/WebSockets/captures, séparation de privilèges, HA avec partition PostgreSQL, restauration avec rôle restreint, upgrade/rollback historique et installation neuve sans build.

Suite générale : 921 tests découverts ; sortie du runner `Ran 919 tests`, `OK (skipped=42)`, respectivement 546,976 s et 691,872 s. Deux exclusions sont des classes réservées à des profils dédiés ; ne pas soustraire directement ces compteurs pour annoncer un nombre de réussites. Gates séparés : 146 tests P1, 21 tests de cérémonies PAM et corpus de restauration hors ligne. Les transports natifs ont leurs propres étapes.

Scans au moment de la qualification : 26 dépendances runtime / zéro avis connu ; aucun moyen/haut applicatif, aucun haut deploy. Le rapport deploy complet conserve 79 faibles et 16 moyens. Revue indépendante complémentaire : 555 fichiers suivis, 85 signalements déjà connus dans la baseline de 88 empreintes, aucun nouveau. Aucun vérificateur de secret en réseau exécuté. Aucun chemin privé NAS/SSH, dump, clé PEM ou fichier de secrets identifié dans les objets introduits depuis main. Cela ne prouve pas l’absence absolue de secret dans tout l’historique.

Les quatre commits préexistants et les changements P0 sont conservés. Deux diagnostics restent exclusivement locaux et non suivis. Voir les rapports `p1-cde-validation.md`, `p1-cde-redteam.md` et `p1-cde-crypto-review.md` pour les essais et limites historiques.

## Portes avant fusion

La PR reste en brouillon pendant la qualification spécifique Synology. Au contrôle initial, `main` n’a ni protection de branche ni ruleset. La procédure humaine seule ne constitue pas une protection technique.

Configuration proposée avant fusion : PR obligatoire, revue indépendante, checks `security` et `postgres-and-container` requis sur le dernier candidat, conversations résolues, refus des force-push et suppressions, application aux administrateurs. Examiner les règles et capacités du dépôt avant de les activer ; ne pas permettre de contournement automatique. Les deux événements actuels produisent des checks de mêmes noms : confirmer leur association au workflow GitHub Actions attendu.

Présenter la configuration et le dernier diff pour accord final de fusion. Ne pas fusionner automatiquement, ne pas publier depuis une branche arbitraire. Tout correctif changeant le candidat exige sa propre qualification.

## Promotion Docker préparée

Version proposée pour validation : `0.3.0-rc.1` ; aucun tag ou GitHub Release créé par cette note. Le pipeline actuel publie un tag technique unique `sha-<révision>-<run>-<tentative>` et une référence immuable par digest ; il ne crée pas de tag sémantique automatiquement.

Après accord de fusion :

1. Relever le SHA exact de main, qui peut différer de d247ed5 selon la méthode de fusion.
2. Attendre sa CI complète réussie. L’artefact image est conservé sept jours uniquement sur main ; les runs de branche d247ed5 ne fournissent donc pas d’archive promouvable.
3. Exécuter manuellement `Publish qualified Docker image` sur ce même SHA/main, avec l’identifiant du run qualifiant. Le workflow recharge l’archive vérifiée et publie sans rebuild.
4. Relever le digest de manifeste registry, vérifier le pull, les labels et l’attestation GitHub ; vérifier la visibilité du paquet. Un identifiant de configuration Docker local ou une empreinte d’archive n’est pas un digest registry.
5. Préparer la release avec SHA, run, référence `ghcr.io/pamolive/pamolive-platform@sha256:…`, architecture `linux/amd64`, migrations et procédures de restauration. Aucun support ARM n’est qualifié.
6. Utiliser exclusivement cette référence immuable dans le plan NAS approuvé, avec PostgreSQL également épinglé par digest et architecture vérifiée.

Aucun digest registry d247ed5 n’est annoncé. L’ancienne publication de main ne représente pas ce candidat. Voir [distribution des images](image-distribution.md).

## Qualification Synology et données

La réussite Docker générique de CI ne qualifie pas le fichier `deploy/synology-test/compose.yml`. Suivre [la qualification runtime](synology-runtime-qualification.md), puis consigner les résultats réellement observés avant toute installation.

La seule migration P1 est `governance.0003_exception_register` : deux tables de preuves, contraintes et immutabilité ; le downgrade est refusé si des preuves sont présentes. Le scénario historique vérifie 22 migrations et 37 nouveaux modèles depuis sa fixture. Conserver les clés exactes de chiffrement/attestation et les trousseaux historiques V7/V8. Une restauration doit viser une nouvelle copie, jamais les données existantes.

Les observations privées du NAS, ses adresses d’administration, inventaires et métadonnées de sauvegarde sont conservés hors dépôt. Aucun détail de secret, dump, environnement résolu ou inspect complet ne doit rejoindre les artefacts publics.
