# ADR-030 — Fournisseur de clés OpenBao Transit pour le Vault technique

**18 novembre 2026 · Décision pour le laboratoire P2.** Prolonge
[ADR-020](adr-020-isolated-vault-envelope.md) et le contrat de réservation
[ADR-024](adr-024-vault-reservation-boundary.md).

## Décision

| Option | Effet sur la frontière de confiance |
| --- | --- |
| Clés de test en mémoire du Vault | Utile pour vérifier les octets et les régressions. Vault détient alors les KEK. |
| OpenBao Transit sur un processus et un stockage dédiés | Le service maintient les KEK et leurs versions. Le laboratoire peut vérifier le mTLS et les ACL avec des données synthétiques. |
| KMS ou HSM géré avec autorités séparées | Convient à la qualification de production. Le modèle de version et la restauration doivent être validés pour chaque service. |

Le premier adaptateur concret utilise l'API v1 d'OpenBao Transit. Le laboratoire
cible la version corrigée OpenBao 2.7.2 épinglée lors de son acquisition. La bibliothèque
`pamolive-vault-envelope` conserve son API, ses AAD et ses formats. Le fournisseur
transmet les octets complets de son contexte en `associated_data` et exige une
clé Transit AES-256-GCM. Il demande une version d'enveloppement explicite et
compare la version du reçu avec celle portée par le ciphertext. Seul le Vault
manipule la DEK en clair côté PamOlive. Le KEK reste dans OpenBao. Le broker et
le portail reçoivent zéro matière de clé. [API Transit](https://openbao.org/docs/2.5.x/api/secret/transit/) · [OpenBao 2.7.2](https://github.com/openbao/openbao/releases/tag/v2.7.2)

## Commissionnement et autorité

Chaque configuration lie l'installation, l'organisation, le domaine, la famille
de KEK, son nom Transit exact, l'IP du service, son identité DNS de certificat et
sa CA dédiée. L'opérateur fournit aussi les versions historiques autorisées.
L'enveloppe ne choisit ni une adresse réseau, ni un token, ni une clé Transit.
La première activation est limitée à `technical-credentials`.

Le service OpenBao exige un certificat client vérifié sur un listener dédié.
L'identité Vault dispose d'un jeton de service court et d'une politique réservée
à `update` sur les deux chemins exacts d'une clé. Le jeton reste un bearer et
peut porter les mêmes droits avec un autre certificat accepté par le listener.
La CA client est réservée au processus Vault pour ce premier profil. La
configuration de laboratoire doit démontrer séparément le refus d'un client
sans certificat et le refus d'un client mTLS sans l'ACL de la clé. L'accès au
listener, aux tokens et à la CA relève du déploiement, avec egress limité au
processus Vault. [Configuration du listener](https://openbao.org/docs/2.5.x/configuration/listener/tcp/)

Avant activation, une identité d'administration distincte vérifie `aes256-gcm96`,
`derived=false`, `convergent_encryption=false`, `exportable=false`,
`allow_plaintext_backup=false` et `deletion_allowed=false`. Elle vérifie les ACL
du compte délégué et interdit l'upsert. L'identité de service ne tourne pas les
clés et ne modifie pas les politiques. Elle ne porte aucune autorité métier de
remise. Le raccord transactionnel au registre des versions et aux preuves PAM
constitue une porte distincte.

## Rotation, reprise et échecs

La nouvelle version de chiffrement doit être créée côté OpenBao avant de changer
la configuration Vault. Avancer `min_encryption_version` dans OpenBao retire
aux anciens clients le droit d'envelopper sous la version précédente. Conserver
`min_decryption_version` compatible avec les archives autorisées. Publier la
nouvelle référence explicite et réenvelopper par le chemin existant. Le payload
AES-GCM garde ses octets. Une restauration de données sélectionne ses anciennes
KEK depuis l'état de récupération autorisé et la sauvegarde OpenBao validée.
Les enveloppes historiques, Fernet, preuves V7/V8 et réservations sont préservées.

La connexion utilise l'adresse commissionnée, le nom de certificat attendu, un
délai total et des limites de réponse. Toute erreur de transport ou de format
induit un refus constant et aucun retry implicite. Les logs de l'adaptateur ne
reçoivent aucune DEK, aucun token et aucun corps de réponse. L'audit OpenBao doit
garder ses protections sur les champs sensibles.

## Réception

Le paquet est séparé du Web et du runtime de réservation. Les tests de source
couvrent version explicite, AAD intégrale, rewrap, isolation de configuration et
refus avant réseau. Le banc OpenBao dédié doit encore vérifier les certificats
et ACL réels, la révocation, la rotation persistée et la restauration OpenBao.
Le témoin indépendant, l'autorité PAM et la publication suivent leurs propres
portes d'acceptation.
