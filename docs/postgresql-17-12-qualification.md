# PostgreSQL 17.12 : maintenance et qualification en attente

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
Les octets index/manifeste et leur liaison ont été vérifiés comme données via
HTTPS. Les couches et le payload de configuration ne sont pas téléchargés par
cette réception ; ni la version exécutée ni l'attestation de build n'en découlent.

Après installation des dépendances, la CI exige `server_version_num=170012`
par `SHOW` dans une connexion en lecture seule, avant toute régression.
Connexion et statement ont un délai de cinq secondes ; le processus de sonde
est limité à quinze secondes, puis deux secondes de nettoyage. Les erreurs
affichées sont constantes et ne contiennent aucun DSN ou diagnostic du serveur.
Les suites PostgreSQL, P0, migrations, concurrence, transports, restauration et
Compose gardent leurs portes existantes. Leur résultat sur ce nouveau sujet
reste en attente.

Cette modification concerne seulement le service CI neuf. Le PostgreSQL 17.11
historique du PC, ses volumes et les installations existantes restent intacts.
Le packaging Synology exige toujours un digest explicitement configuré ; aucun
NAS n'est contacté ou mis à niveau. La qualification de l'image auxiliaire et
de sa restauration reste distincte de celle de l'image applicative. Les
35 groupes High applicatifs et la provenance de build incomplète bloquent
toujours la promotion main/image.
