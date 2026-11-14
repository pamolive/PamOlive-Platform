# P1-F — Qualification locale du 14 novembre 2026

Statut : qualification N0 en cours, **aucune autorisation de production ni de
publication d'image**. PR2 reste une revue en brouillon. Les résultats de cette
page ne rendent pas vertes les anciennes CI refusées.

## Complément B3r6 et candidat Python

B3r6 est construit depuis les seuls octets Git du commit `8ca92bf` ; son archive
de production a pour SHA256
`73fa1d8f8d5f00a4149b380e521f89376f4f51c655acf8e021816b46e380e9c0`.
La sonde embarquée avec Docker init passe, ainsi que8smokes,10tests SSH,9RDP,
TLS1.3/SCRAM sous rôle non administrateur, les extensions et30tests de restauration.
La campagne P0 exécute227tests en140,632s :226réussissent et un cas SQLite est
ignoré sur PostgreSQL ; son homologue PostgreSQL passe. Le complément PAM passe
28tests. La restauration réelle contient106modèles,17objets chiffrés,87preuves
signées et3reçus ; elle ne contient pas de registre PAM commissionné non vide
ni de preuves d'exception Governance non vides. `safe_to_serve` reste faux.

Le scan OS avec la base du14novembre conserve348matches,102High dans35groupes,
aucun Critical et aucune High avec correctif disponible. Les34groupes PostgreSQL
apparus sur B3r4 disparaissent avec libpq17.12. Le SBOM compilé déclaré contient
41composants sans match et son contrôle positif passe ; cette couverture n'est
pas exhaustive. Aucune exception ni promotion ne découle de ces résultats.

Les deux CI suivantes du commit `7bfbe18` passent le job de sécurité puis échouent
au test de bascule entre deux nœuds. Leur diagnostic est ouvert ; les autres
résultats locaux ne permettent pas de déclarer ces CI réussies.

Reproduction locale : le montage RO des checkpoints publics de la fixture HA
sous `/tmp` déclenche `runtime_tmpfs_shadow`. Les journaux internes du helper
ne sont pas présents dans les artefacts CI : cette incompatibilité est prouvée,
mais ne permet pas d'exclure un second défaut au même stade. La fixture utilise
désormais `/run/pamolive-ha-public-checkpoints`, avec la même source publique RO,
les mêmes signatures et les mêmes validateurs. La sonde stricte est inchangée.
Les22tests HA PostgreSQL passent en3,692s sans exclusion, et25tests purs passent.
Le démarrage de deux nœuds et la CI du nouveau sujet restent à rejouer.

Le nouveau profil [Python](python-materials.md) conserve les versions, fige32
fichiers publics et sépare acquisition et compilation/installation hors réseau.
Ses18tests et97sondes indépendantes passent ; son build exact reste à exécuter.
Il ne remplace pas les matériaux APT/SDK/compilateur, une attestation de build,
ni les arbitrages High. Les résultats B3r6 ne sont pas reportés sur ce candidat.

## Sujet B3r4 historique testé et limites

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
