# Fournisseur OpenBao Transit pour le Vault

Adaptateur explicite du protocole `KeyProvider` de PamOlive. Installer le paquet
et ses dépendances dans le processus Vault isolé. Aucun réglage Django ni
chargement depuis les variables d'environnement ne sélectionne le fournisseur.

Construire `TransitTransport` depuis la destination commissionnée et ses fichiers
CA, certificat et clé client. Construire ensuite `TransitProvider` avec la
référence KEK active, le nom Transit, les versions lisibles et un token de
service dédié. Le consommateur doit obtenir la version attendue depuis son
registre autorisé avant d'appeler le chiffrement d'enveloppe.

L'opérateur crée une clé Transit `aes256-gcm96` non exportable, non dérivée et
sans chiffrement convergent. La politique minimale associe les deux chemins
`transit/encrypt/<nom>` et `transit/decrypt/<nom>` à la seule capacité `update`.
Le token ne doit pas recevoir les capacités `create`, `delete`, `sudo`, la
lecture d'autres clés ou les opérations de rotation. Tester l'ACL effective
avec des tokens et clés synthétiques avant le raccord. Le listener doit exiger
le mTLS et la CA client prévue.

Les conditions de rotation, les limites de confiance du token bearer et la
qualification attendue sont décrites dans [ADR-030](../../docs/adr-030-openbao-transit-key-provider.md).

Les tests locaux utilisent un double Transit et un serveur mTLS synthétique
temporaire sur loopback. Le laboratoire CI utilise les deux wheels installées,
un binaire OpenBao publié et signé, des données neuves et un stockage PebbleDB
jetable. [Stockage PebbleDB](https://openbao.org/docs/configuration/storage/pebbledb/)
Il vérifie les ACL et les versions après redémarrage, puis révoque un token.
Le processus d'administration et le client utilisent des identités TLS
distinctes sur le même runner. L'indépendance de l'hôte et la restauration
d'une sauvegarde OpenBao demandent leur propre qualification.
