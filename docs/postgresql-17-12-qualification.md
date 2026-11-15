# PostgreSQL 17.12 : régressions CI reçues, promotion bloquée

La [mise à jour de sécurité PostgreSQL du 12 novembre 2026](https://www.postgresql.org/about/news/postgresql-187-1712-1616-1520-1425-and-19-rc-2-released-3442/)
inclut 17.12. Ses corrections demandent une nouvelle qualification ; les succès
historiques sur une autre version ne sont pas transférés.

Le service PostgreSQL jetable de la CI remplace le tag flottant `postgres:17`
par l'image officielle linux/amd64 :

```text
docker.io/library/postgres@sha256:6f7593c161689b6b02c78668b314af7da8811b592c5519108c57a49d0b6ad788
```

L'index officiel découvert par le tag 17.12 porte le digest
`sha256:0d938e975177bef9f1f61f3f9dbcf2e0aa0a139568f66d3415ed8892eb97f6ac`.
La réception initiale des octets index/manifeste vérifie leur liaison comme
données via HTTPS, sans télécharger les couches ou le payload de configuration.
Cette découverte seule ne prouve ni la version exécutée ni l'attestation de build.

Après installation des dépendances, la CI exige `server_version_num=170012`
par `SHOW` dans une connexion en lecture seule, avant toute régression.
Connexion et statement ont un délai de cinq secondes ; le processus de sonde
est limité à quinze secondes, puis deux secondes de nettoyage. Les erreurs
affichées sont constantes et ne contiennent aucun DSN ou diagnostic du serveur.
Les suites PostgreSQL, P0, migrations, concurrence, transports, restauration et
Compose gardent leurs portes existantes.

## Réception exacte du 15 novembre

Au head `edec99ab510165cf8231aeb9bf7513272c87cc87`, les
[CI PR](https://github.com/pamolive/PamOlive-Platform/actions/runs/43736103902) et
[push](https://github.com/pamolive/PamOlive-Platform/actions/runs/43736048530)
sont terminées. Le résultat JSON réellement émis par la sonde est `170012` dans
les deux journaux ; il est distingué de l'echo du code de la commande. La
contre-revue AppSec confirme la liaison HEAD/base/merge, les octets et les
résultats reçus : gel `a50643da6512d554d69e6bb984dacc3af9fd6e359f288ae309e74b036d69b801`.

Chaque run passe les portes PostgreSQL, P0, natives SSH10/RDP9, HA à deux nœuds
sur le même hôte avec partition, restauration, upgrade/rollback et Compose.
La suite générale annonce 1 457 tests avec 42 entrées Skip : 40 méthodes et
deux classes. Les deux autres marqueurs 1+1 restent séparés ; aucune exclusion
n'est comptée comme réussite. L'upgrade synthétique conserve les anciennes
colonnes de 374 lignes/65 modèles, avec 23 migrations/41 nouveaux modèles.
Les 52 purs Vault et 17 cas de wheel comme données restent distincts des
bibliothèques installées contrats17/enveloppe25 et du vérificateur public30.
Ces résultats ne reçoivent pas l'installation du runtime Vault.

Les deux CI échouent uniquement au scan applicatif final : 35 groupes High,
102 matches High sur 349 OS, zéro Critical/ignoré, compiled0. La provenance de
construction reste incomplète. Résumé exact :
`a010014fc616c3df3641e1bd89a888fa40d8ea12c1a3b4b9981f4b1a4bc40f7d`.
La [PR7](https://github.com/pamolive/PamOlive-Platform/pull/7) conserve son
brouillon et le compte rendu de réception ; aucun résultat de parent n'est transféré.

Cette modification concerne seulement le service CI neuf. Le PostgreSQL 17.11
historique du PC, ses volumes et les installations existantes restent intacts.
Le packaging Synology exige toujours un digest explicitement configuré ; aucun
NAS n'est contacté ou mis à niveau. La qualification de l'image auxiliaire et
de sa restauration reste distincte de celle de l'image applicative. Les
35 groupes High applicatifs et la provenance de build incomplète bloquent
toujours la promotion main/image.
