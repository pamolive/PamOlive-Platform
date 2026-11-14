# P1-F — Qualification locale du 14 novembre 2026

Statut : qualification N0 en cours, **aucune autorisation de production ni de
publication d'image**. PR2 reste une revue en brouillon. Les résultats de cette
page ne rendent pas vertes les anciennes CI refusées.

## Sujet testé et limites

Le build local B3r4, terminé le 12 novembre, a été identifié par les empreintes
de ses archives, configurations et manifestes avant les essais. Le plan contient
634 fichiers à partir du commit historique `42fdcb0` et de ses overlays natifs
explicites. Il exclut F3, G, P2 et les deux diagnostics privés. Ce n'est pas une
image reconstruite depuis un commit final propre et publié.

Le durcissement du superviseur, du préflight et de la sonde réalisé ensuite
**n'est pas présent dans B3r4**. Les résultats ci-dessous ne qualifient donc pas
ce nouveau profil. Le NAS, les systèmes réels et les identités réelles n'ont pas
été contactés. Docker Desktop local est le seul environnement de transport.

## Résultats du sujet B3r4

| Contrôle | Résultat | Limite |
| --- | --- | --- |
| Démarrage et inventaires runtime/natif/Kerberos/driver, plugins, SSH/RDP/DNS | 8/8 contrôles réussis | Fixtures synthétiques, pas AD/Kerberos réel |
| Relais SSH sur PostgreSQL | 10/10, aucune exclusion, 56,405 s Django | Image production locale |
| Relais RDP/NLA sur PostgreSQL | 9/9, aucune exclusion, 38,643 s Django | Image native-test distincte, pair headless synthétique |
| Driver PostgreSQL TLS/SCRAM | Réussite | Deux serveurs dédiés, sans port publié ; TLS1.3, verify-full, rôle nonadmin ; mauvais certificat/nom/mot de passe et serveur en clair refusés ; verrou55P03 puis reprise |
| Extensions signées installées séparément | 19 réussites et 1 exclusion avec fixture de base ; 20/20 SQLite périodique ; 20/20 PostgreSQL périodique | Le cas nécessitant V3 est exécuté dans les deux campagnes périodiques ; il n'est pas compté comme réussite dans la campagne de base |
| Régressions PAM supplémentaires | 146/146, aucune exclusion, 151,414 s Django | Dix modules PAM ; ne constitue pas à elle seule toute la régression SCIM, clés et provenance P0 |
| Tests de restauration | 30/30, aucune exclusion | Bases de laboratoire nominatives dédiées |
| pg_dump/pg_restore réel sur copie | Réussite, 67,516 s | 106 modèles, 87 preuves signées, 17 valeurs chiffrées, 3 reçus de provenance, 1 capture scellée, aucune migration en attente |
| Scan SBOM combiné du sujet exact | Zéro match sur41composants | Base du14novembre et contrôle positif222matches ; couverture déclarée partielle, pas absence générale de vulnérabilité |

La copie restaurée reste `safe_to_serve=false`. Le dump vérifié ne contient
aucun registre de confiance PAM ni preuve d'exception Governance non vide ; leur
préservation n'est pas revendiquée par ce dump. Leurs tests spécialisés passent
séparément. Les données Directory comprennent quatre sources, six runs, six
faits et huit mappings. Aucun volume existant n'a été supprimé.

Les conteneurs d'essai sont arrêtés et conservés avec leurs journaux. Le serveur
PostgreSQL local dédié reste disponible. Les refus de restauration avec mauvaise
clé ou mauvais mot de passe ont des retours non nuls attendus ; ils ne sont pas
des échecs maquillés en réussites.

## Correctifs et contre-revue

Le profil examiné refuse désormais les substitutions de commande/utilisateur,
les montages ombrant code, bibliothèques ou polices, les variables de chargement
et d'interpréteur non approuvées. La sonde contrôle les vrais services et leurs
arguments, filiation, UID/GID, capacités, environnements et répertoires privés.
Une contre-revue a reproduit l'acceptation d'un suffixe Uvicorn arbitraire ; le
vecteur exact est maintenant exigé, avec workers décimaux canoniques1..256.
Les 48 tests du profil et des clés passent, sans exclusion.

Le vérificateur d'archive recroise maintenant `Config.rootfs.diff_ids` avec les
flux décompressés de chaque couche raw/gzip, dans le même ordre et sous budget.
La contre-revue a confirmé le refus d'une injection `.pth` conservant l'ancienne
configuration, pour les deux codecs. Les 79 tests recette/politique/Kerberos et
les 70 tests de contre-validation passent. Ces nombres se recoupent ; ils ne
doivent pas être additionnés comme des scénarios indépendants.

Le contexte Docker CI est produit depuis l'arbre Git du commit, avec refus des
liens, chemins ambigus, fichiers spéciaux, doublons et diagnostics privés. Le
manifeste de contexte peut être relié à la recette complète, Dockerfile compris :
une recette cohérente avec un checkout modifié ne décrit pas automatiquement le
contexte du commit. Onze tests dédiés couvrent ces frontières. La CI continue à
tester les canaris de secrets dans ce contexte avant construction.

La campagne agrégée des outils et du profil passe 241 tests en25,480 s, sans
exclusion ; le onzième cas de liaison recette/contexte a été ajouté et exécuté
ensuite. Ruff passe sur l'ensemble du checkout. Les sorties négatives JSON
émises par les tests des outils sont attendues, pas des verdicts sur B3r4.

## Conditions restant bloquantes

- Le scan frais B3r4 avec la base du14novembre termine avec395matches,
  zéro Critical,136High réparties en69groupes et34matches High avec correctif
  annoncé disponible ; aucun match ignoré, aucune terminaison OOM. Le retour2
  signifie seuil High dépassé, pas erreur du scanner. Ces correctifs et les
  nouvelles analyses sont requis : les35groupes de la politique historique ne
  représentent plus tout ce résultat et restent `untriaged`, sans exception.
  Les34nouveaux groupes proviennent de PostgreSQL/libpq17.11 et annoncent17.12
  corrigé. Leur attribution au paquet source ne prouve pas34failles exploitables
  du client libpq ; le choix retenu est néanmoins de mettre à jour client et SDK,
  sans exempter ces avis. Une nouvelle image et son propre scan sont requis.
- ADR021 : inventaire examiné des matériaux compilateur/SDK/APT et chaîne
  d'attestation authentifiée du build et de sa qualification. La vérification
  locale de cohérence conserve `build_verified=false`.
- La couverture de sources `/app` et des ELF n'est pas une fermeture de tous les
  fichiers Python, `.pth` et configurations loader hors `/app`. Une injection
  accompagnée d'une configuration recalculée demande une identité de build
  fiable et les inventaires correspondants ; le hash seul ne donne pas confiance
  au producteur.
- Reconstruction de la source finale propre, sonde effective du nouveau profil,
  CI complète au SHA exact, migrations/upgrade/restauration et toutes régressions
  P0 avant fusion. Les capacités exclues des makecheck Kerberos restent exclues.
- Promotion de la même archive sans rebuild, digest et attestations vérifiés.
  Aucun tag stable/latest, mise à niveau NAS ou usage privilégié réel implicite.
