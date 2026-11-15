# P2-R1b.1 — matériaux publics PAM, sans remise de secret

15 novembre 2026. La bibliothèque et son adaptateur sont préparés dans le
commit local `77613e8`, sur `agent/p2-r1b1-public-verifier-a573`, depuis `a57350f`.
L'installation Linux et sa CI restent à exécuter. Aucun service Vault, broker,
ledger, migration ou nouveau chemin d'accès aux secrets n'est livré ici.

[ADR-023](adr-023-public-pam-material-verifier.md) fixe la frontière :
`verify_archived_registry_chain` contrôle la chaîne publique complète fournie ;
`verify_current_registry_materials` contrôle aussi le checkpoint et l'heure
explicite. Installation, organisation, génération, révision, tête et clés
externes attendues viennent d'un contexte de l'appelant. La bibliothèque
ne commissionne pas cette autorité et ne charge aucune configuration Web.

Les résultats immuables restent constructibles : ils ne sont ni capacités,
permissions d'action, preuves MFA ou de possession, ni attestations d'humains
indépendants. Aucun appelant P0 n'est remplacé. Aucun déchiffrement n'est ajouté.
La future liaison entre installation opaque P0 et UUID Vault reste indépendante.

## Fonctionnement et compatibilité

Six modules autonomes, sans Django, SQL, réseau, découverte de clé ou fichier
fourni à l'API. Chaîne contiguë depuis le bootstrap, anciennes autorités éligibles
et cinq cartes de propriétaires conservées lors des recommissionnements.
Les engagements V1 préservent les champs signés inconnus, Unicode et cartes
de signatures. L'égalité historique des révisions de checkpoint signées
flottantes/booléennes reste documentée ; les révisions de registre et contexte
restent des entiers stricts.

Le profil borné impose notamment 256 enveloppes, 2 MiB par enveloppe et 32 MiB
au total. Un TTL courant plus court est une restriction explicite. Ces bornes
ne réécrivent pas les archives P0 et ne les déclarent pas corrompues ; le chemin
historique existant conserve sa portée. Les preuves V7/V8 et données chiffrées
ne sont pas modifiées. Voir le
[contrat détaillé du composant](../components/pam-trust-verifier/README.md).

## Résultats réellement obtenus pour le commit local

| Contrôle | Résultat et portée |
| --- | --- |
| Bibliothèque depuis ses sources | 30 tests, zéro erreur/échec/exclusion, 1,172 s ; processus, réseau et SQL interdits pendant le rejeu |
| Adaptateur après mise au format du dépôt | 30 tests purs, zéro erreur/échec/exclusion, 2,765 s ; aucune installation ou exécution de son main |
| Dépendances de qualification | 13 wheels, 8 939 939 octets, hashes/ZIP/RECORD contrôlés ; audit strict des 13 versions : zéro vulnérabilité connue au contrôle |
| Ruff | Contrôle global réussi ; format ciblé des 12 fichiers Python réussi, sans cache dans le périmètre source fermé |
| Bandit du nouveau code de bibliothèque | Zéro finding et zéro erreur sous seuil Medium/High |
| Secrets | Vrai CLI sur 1 071 fichiers du commit, huit lots exit0 ; 881 nouvelles décisions publiques revues et 313 anciennes conservées, total 1 194 |
| Revue indépendante | Règles publiques, formats, contextes, UUID avant parsing, imports, fichiers fermés et preuves cryptographiques revus ; contrôles anciens CI conservés |
| Wheel installé dans Linux isolé | Non exécuté ; gate obligatoire avant réception |
| P0, PostgreSQL, migrations, transports | Aucun nouveau modèle, appelant ou migration ; les CI de la branche publiée devront revalider le périmètre applicatif existant |

Les fixtures sont statiques : 17 fichiers originaux, 320 adverses et un témoin
figé de fonctions P0. Elles ne sont pas régénérées et ne contiennent pas les
clés privées éphémères de leur construction. Les paramètres COSE complets ont
été contrôlés comme publics. Les signatures et engagements de leurs preuves
sont recalculés indépendamment. L'index diagnostique des JSONpaths est borné
et n'est pas revendiqué exhaustif ; les préimages et décisions individuelles
ont été vérifiées. Aucun filtre ou plugin de détection n'a été désactivé.

Deux fichiers CRLF restent octet pour octet identiques aux preuves historiques :
le témoin P0 et le plan de matériaux. Leurs règles Git ciblées conservent les
octets et les contrôles habituels d'espaces, avec CR reconnu comme fin de ligne.
Le helper d'IO conserve son code AST sauf ordre des imports standard ; les
autres changements de style préservent les AST, hormis deux pins de fichiers
recalculés et revus. Les anciens gels restent conservés.

## Gate installé et suite

L'acquisition publique des 13 entrées est explicite et distincte du test.
Le banc doit ensuite imposer Linux/amd64, Python 3.12.16, nonroot, rootfs et
entrées RO, réseau none, capacités nulles, NNP et quotas ; construire un wheel,
l'installer dans un venv sans sources, contrôler origines/distributions et
`pip check`, puis exiger les 30 tests et les compteurs d'IO attendus.
Les rapports du tmpfs doivent sortir avant l'arrêt, sans logs bruts.
Le workflow dédié est `.github/workflows/p2-public-verifier.yml` ; son contrôleur
se trouve dans `qualification/p2_installed_ci`. Il impose trois entrées publiques
fermées, l'image S0 par manifeste et un stockage Docker classique explicitement
vérifié. Un autre backend refuse ; aucune tolérance vers le profil Docker local
n'est introduite. Seul le rapport public borné est conservé en artefact.

La contre-revue du banc a reproduit une annonce de ressources libérées malgré
un client non récolté ou un drainage incomplet. Sa correction R2 conserve
l'incertitude au fil des phases et des cleanups : 48 tests purs et 42 sondes
indépendantes passent. La copie intégrée rejoue ces 48 tests sans exclusion ;
la revue indépendante du remapping confirme les 354 fichiers du composant,
les huit adaptations du qualifier, les manifestes et le workflow. Ruff global
passe. Le contrôle Bandit supplémentaire du banc conserve huit signaux B108
Medium/Medium, sans erreur : la revue les rattache aux littéraux et assertions
du tmpfs privé, sans fichier temporaire hôte vulnérable confirmé dans ce profil.
Aucun `nosec`, filtre ou suppression de signal n'a été ajouté. Ce résultat est
distinct du zéro finding de la bibliothèque. Le scan de secrets des nouveaux
fichiers du banc constitue un contrôle séparé du résultat historique à 1 071
fichiers présenté dans le tableau. La qualification installée nécessite son
propre rapport CI ; aucun résultat installé n'est inféré de ces tests purs.
Aucun test installé réel n'a été lancé avec le banc refusé. Le banc demeure
une qualification distincte de la bibliothèque, du build de sa base et d'un
service P2.

Après réception installée : contexte commissionné indépendant, preuves d'action
liées au transcript V2, puis compteurs et ledger transactionnel avant toute
remise réseau. Les 35 groupes High de l'image applicative et la provenance de
build incomplète restent bloquants pour sa promotion. Aucun nouveau déploiement
NAS, compte privilégié réel ou image stable ne découle de ce lot.
