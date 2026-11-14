# Intégration locale F3 / G / bibliothèques P2 — 14 novembre 2026

## Sujet et statut

Le commit de fusion **local** `4c9cd2beb620272e730cf671ec36cc6e8ad155cb`
réunit le socle `2f282246f70d33a4f94254d4e54190fff5d20609` et la branche
`cc764c0d6496f741859b3b17bc8dbd3853f5dfe2`. Les branches historiques restent
conservées. Ce sujet n'est ni main, ni le contenu publié de PR2, ni une image qualifiée.

Les 698 fichiers de la fusion ont été comparés à l'arbre attendu : modes,
objets Git, absence de conflit et conservation des 86 fichiers protégés du
socle (déploiement, dépendances et CI). Les trois fichiers du correctif
d'autorité de `create_record` sont conservés sans duplication. F3/G/P2 n'ajoutent aucun modèle
ou migration à cette fusion. Les changements ultérieurs de CI, lock de test et
documentation constituent un nouveau candidat, sans validation anticipée.

## Fonctionnalités réunies

- F3 : projection en lecture seule de l'inventaire, des correspondances et de
  l'histoire SCIM/TeamViewer ; routes HTML, API et export réelles, bornes
  explicites, permissions et modules revalidés sous verrou d'organisation.
- G : formulaire existant prérempli depuis Identity 360. GET n'accorde aucun
  droit et n'alimente jamais un POST. Le service recharge l'acteur et
  l'organisation, relit les modules après attente du verrou, puis applique les
  validations métier existantes. Il ne résout pas toutes les courses possibles
  sur les objets liés.
- P2 enveloppe : AES-256-GCM avec provider explicite et bindings typés, sans
  service, autorisation, KMS par défaut ou chemin applicatif de remise. La
  primitive retourne du plaintext à son appelant qui doit être préalablement autorisé.
- P2 contrats : DTO immuables, encodages et engagements versionnés ; aucun
  vérificateur d'autorité, registre, ledger, SQL ou transport. `authorized=False`
  documente le statut des objets et ne constitue pas une frontière de confiance.

Les packages P2 restent exclus du runtime Web. Leur installation et leurs tests
de wheel disposent désormais d'une [porte dédiée en préparation CI](p2-installed-library-ci.md),
dont le contrôleur a réussi localement sur les packages installés. Voir [ADR-020](adr-020-isolated-vault-envelope.md)
et [ADR-022](adr-022-vault-operation-contract.md).

## Résultats exécutés sur le contenu fusionné

| Contrôle | Résultat | Portée |
| --- | --- | --- |
| PostgreSQL réel, rôle de test restreint | 134/134, 57,122 s, zéro ignoré | 9 modules : autorité de création, F3/concurrence/vues/Red Team, parcours HTTPS, portail G, vues Directory et Identity 360 |
| Primitive enveloppe | 25/25 | Tests purs, aucun service Vault qualifié |
| Formats d'opération | 17/17 | Tests purs, aucune preuve d'autorité vérifiée |
| Ruff | Réussi | Checkout complet ; format des 16 nouveaux fichiers Python vérifié |
| Scan réel de secrets | 698 fichiers, 5 lots exit 0, zéro nouvelle détection | 313 décisions : 306 du socle et 7 fixtures P2 déjà revues ; aucun filtre ajouté |
| Revue indépendante de fusion | Réussie sur le périmètre examiné | Arbre attendu, contrôles conservés, routes en lecture seule et absence d'import P2 par l'application |

La base de test dédiée a été détruite par le runner et aucune session ne
subsiste. L'identité et le propriétaire de la base synthétique préexistante
sont conservés ; aucun volume supprimé. Une première invocation des tests purs
avait échoué sur le chemin d'import du lanceur. Elle reste dans les preuves ;
l'invocation documentée a ensuite réussi sans modifier les packages ou le venv Core.

Ces résultats ne remplacent pas les régressions P0 complètes, les portes
image/native/HA/restauration ni les tests des wheels installées du **nouveau
candidat intégré**. Aucun résultat R8-r2 ou CI du socle n'est transféré à ce sujet.

## Référence du socle, distincte de l'intégration

Les CI [push 43628037184](https://github.com/pamolive/PamOlive-Platform/actions/runs/43628037184)
et [PR 43628039886](https://github.com/pamolive/PamOlive-Platform/actions/runs/43628039886)
de `2f28224` terminent leurs portes fonctionnelles : 1345 tests généraux comptés
avec 42 exclusions, suites dédiées, SSH 10/10, RDP 9/9, deux nœuds et partition
de route PostgreSQL sur un même hôte, restauration et retour arrière.
Le build PR porte le merge de test `2d213558692b0f09031874493d0ce638a8872cf9` ;
le build push porte le SHA de branche. Aucun ne contient l'intégration F3/G/P2.

Leur scan final échoue : 348 correspondances OS, 102 High / 35 groupes,
zéro Critical et zéro correspondance ignorée. Les 35 groupes restent non
arbitrés ; les matériaux APT/SDK/compilateur et l'attestation restent incomplets.
`build_verified` et `cryptographic_build_attestation_verified` sont faux.

Le sujet local R8-r2 de `2f28224` corrige ensurepip : deux vrais venvs hors réseau
installent pip 26.3 sans paquets globaux. L'ancienne wheel reste dans les couches
historiques de la base. Son inspection, ses tests P0 sélectionnés, ses transports
et sa restauration sont des preuves propres à ce sujet ; les 35 groupes High
continuent à bloquer sa promotion.

## Suites nécessaires

1. Exécuter la nouvelle porte CI sur le candidat exact. Son contrôleur a passé
   localement 25 + 17 tests sur les packages installés, avec matériaux hashés,
   réseau absent et aucun fallback global ; le workflow complet reste à vérifier.
2. Rejouer les régressions et portes de packaging sur le candidat intégré exact,
   avec migrations/restauration, tenants, concurrence et preuves historiques.
3. Compléter le parcours G headless et PAM par cérémonies synthétiques réelles,
   puis transports ; les fixtures ne prouvent pas l'indépendance d'humains réels.
4. Construire les autorités, le registre et le stockage P2 après décision et
   contre-revue distinctes, sans faire d'un DTO une autorisation.
5. Refuser fusion/promotion tant que les contrôles requis échouent. Aucun NAS
   ou système réel n'a été contacté pour cette intégration.
