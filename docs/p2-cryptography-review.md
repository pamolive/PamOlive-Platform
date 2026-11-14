# P2 — revue cryptographique indépendante des frontières de confiance

État : revue de conception du code courant, le 11 novembre 2026. Ce document n’annonce ni un Vault implémenté, ni une validation de production. Seul ce fichier a été créé par le reviewer ; aucun code produit, système réel, secret réel ou NAS n’a été modifié ou interrogé.

La proposition d’infrastructure est examinée dans [la revue des frontières P2](p2-trust-boundary-review.md). Les accords ci-dessous expriment des recommandations après confrontation, pas une preuve de sécurité par consensus.

## Constats vérifiés dans le code

| Constat et source | Garantie actuelle | Conséquence pour P2 |
| --- | --- | --- |
| `platform_core.security.cipher` dérive une clé Fernet de SHA-256 de `PAMOLIVE_ENCRYPTION_KEY` | P0-1 refuse la configuration vide/invalide ; le format historique reste déchiffrable. Une variable absente conserve le comportement de compatibilité configuré dans settings. | Cette validation syntaxique ne mesure pas l’entropie. Les nouvelles clés doivent être aléatoires, indépendantes et gérées hors Web, sans dérivation depuis un mot de passe humain ou les identifiants d’un tenant. |
| `platform_core.attestations.signature`, `pam.mandates`, `pam.target_binding` et `pam.sessions` utilisent le matériel applicatif pour leurs MAC | Namespaces et périmètres lient preuves, cible et ciphertext ; SQL et services protègent l’historique. | Le détenteur du secret HMAC peut aussi produire des MAC. Ce mécanisme ne donne pas une vérification publique indépendante et le noyau d’attestations n’a pas aujourd’hui de dispatch universel par version de clé. |
| `access.evidence` conserve le format V7 et `access.provenance` ajoute V8 avec trousseau de vérification historique | Les reçus V8 couvrent les faits normalisés, le principal réel et l’ancre ; ils n’attestent pas la vérité de la télémétrie. | Préserver les octets, formats, domaines de signature et clés historiques. Ne pas transformer ces reçus en signature indépendante du collecteur ou du futur témoin. |
| `pam.trust_registry` vérifie Ed25519, registre cosigné et checkpoint externe ; `pam.trust_auth` vérifie réellement les assertions WebAuthn | P0-3 ne repose pas simplement sur un booléen `approved` ou des rôles créés en base. Les personnes, clés, politiques et cibles ont une autorité distincte de l’administration tenant. | Réutiliser les preuves brutes et règles exactes dans les consommateurs indépendants. Ne pas remplacer ces vérifications par un résumé HMAC produit par Web. |
| `pam.sessions.endpoint_credentials` revalide sous verrou mandat, cible, sceaux, lancement et confiance, puis appelle `cipher().decrypt` | P0-2 lie précisément le credential et le mandat à la destination ; le navigateur PAM ne reçoit pas les identifiants injectés. | Le processus applicatif possède encore le pouvoir de déchiffrer. Un changement de conteneur ou d’UID seul n’établit pas une frontière Vault. |
| Captures dans `pam.sessions` et `pam.recordings` : Fernet, chaîne MAC, sceau de fin et contrôle du lecteur | Captures historiques bornées et vérifiées avant leur lecture ; pas de bloc natif injecté transmis au navigateur par ce chemin. | Conserver ce vérificateur. Les nouvelles captures nécessitent un domaine de clés distinct des secrets d’authentification et des preuves d’autorisation. |

La limite de concentration des clés est une frontière architecturale connue du monolithe, pas la démonstration d’un contournement des menaces tenant administrateur corrigées par P0. Sa criticité devient élevée dès qu’on revendique une résistance à la compromission du Web ou du worker.

## Choix minimal recommandé

Conserver le monolithe métier ; ajouter un Vault, un gestionnaire de clés et un broker effectivement séparés. Web transmet des références et des preuves, jamais une clé maîtresse ni un credential technique. Vault possède le stockage des enveloppes et son ledger d’autorisations ; KMS possède les KEK et ses propres règles. Le broker reçoit seulement le credential nécessaire à une session précise. Aucune route de déchiffrement arbitraire n’est accordée à Web ou au worker.

| Modèle | Apport | Limite et décision proposée |
| --- | --- | --- |
| Même clé globale, autres conteneurs | Sépare des processus et certains accidents d’exploitation. | Une compromission ayant toujours la clé et les ciphertexts conserve le même pouvoir. Insuffisant pour l’objectif final P2. |
| Vault indépendant avec KMS logiciel de laboratoire | Permet des tests réels de certificats, droits par opération, enveloppes, coupures, reprise et nonces. | Le root de l’hôte peut lire fichiers et mémoires. Profil local explicite ; aucune revendication HSM ou indépendance multi-hôte. |
| Vault et gestion des clés sur autorités/hôtes distincts, KMS/HSM maintenu | Peut imposer séparation des administrateurs, clés non exportables et politiques par domaine. | Dépend du déploiement, de l’enrôlement, des permissions et de la reprise effectivement qualifiés. Cible de production, pas propriété obtenue par une interface Python seule. |

Une première tranche utile peut porter sur une **nouvelle cible V2 synthétique**. Son credential effectif est nouveau ou réellement renouvelé sur la cible ; l’ancien credential ne fonctionne plus. L’ancien chemin ne peut exécuter cette cible ni par dispatch ni par réseau, et aucune panne du nouveau Vault ne le réactive. Cette tranche démontre le confinement de cette cible, pas celui de tous les anciens secrets.

## Enveloppes et séparation des domaines

Choix proposé : AES-256-GCM via la bibliothèque maintenue `cryptography`, DEK aléatoire de256bits neuve pour chaque version de secret, nonce de96bits et tag complet. Ne jamais réutiliser un couple clé/nonce ; conserver le résultat chiffré pour les retries, sans répéter une encryption avec le même couple. L’API AEAD authentifie aussi les AAD ; toute erreur de clé, nonce, tag ou AAD doit refuser le résultat. [API AEAD officielle](https://cryptography.io/en/latest/hazmat/primitives/aead/), [NIST SP800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final).

Le contrat d’enveloppe est versionné et strict. L’AAD **du payload** comprend format, installation, tenant, domaine, identifiant/version du secret, identifiant de DEK, but et identité de destination pour un credential technique. Elle est reconstruite depuis le contexte autorisé et les références immuables ; déplacer ensemble une ligne et ses métadonnées vers un autre tenant ne doit pas la rendre valide.

La DEK est enveloppée par une KEK de tenant/domaine tenue hors Vault. L’AAD **du wrapping** et la politique KMS lient la référence/version de KEK, la DEK et le hash de l’AAD du payload. Ne pas placer la version mutable de KEK dans l’AAD du payload si l’on veut réenvelopper sans rechiffrer ce payload. Une API KMS maintenue fournit génération et wrapping ; son contexte authentifié n’est pas confidentiel et ne doit contenir ni secret, ni nom de personne, ni chemin privé. [Contexte KMS officiel](https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html).

Les domaines minimum sont `user-vault`, `technical-credentials`, `recordings` et `evidence-signing`. Les KEK de tenant/domaine sont indépendantes ; leur ID est une référence autorisée, pas une permission ni une URL fournie par le client. Une KEK commune à tous les tenants ou un principal KMS autorisé à tout déchiffrer conserve un rayon de compromission global, même si les lignes affichent des IDs différents.

Les clés de signature des capacités et du témoin restent distinctes des clés AEAD et de celles du TLS. Le Vault ne remet aucune KEK ou DEK au broker. Il peut connaître le plaintext d’un credential et le transmettre sur le canal mTLS du seul consommateur autorisé ; on ne présente donc pas le système comme zero knowledge. La brièveté de vie des buffers Python réduit l’exposition, sans garantir leur effacement physique.

## Autorisation par opération et mTLS

mTLS identifie le service et protège le transport ; il ne lui accorde pas tous les droits de son tenant. Le certificat vérifié doit être mappé côté serveur à une identité stable, à ses rôles, tenants, audiences et opérations autorisées. Un CN, un en-tête proxy ou un champ JSON envoyé par l’appelant n’est pas cette identité. La rotation d’un certificat conserve l’identité de service mais révoque l’usage du certificat remplacé ; une capacité liée à son empreinte ne migre pas silencieusement. Le modèle de jetons liés au certificat est défini dans [RFC8705](https://www.rfc-editor.org/rfc/rfc8705.html).

Le transcript signé d’une action V2 couvre au minimum : version/type, installation/génération, issuer/subject/audience, tenant, opération, compte/personne canoniques, intention et hash de périmètre, session/broker destinataire, destination exacte/epoch, référence/version de credential, révisions de politique et registre, checkpoint, nonce émis par Vault, dates d’émission et expiration. Il ne contient pas le secret.

**Une ancienne assertion P0-3 ne signe pas automatiquement un nonce Vault ou une audience ajoutés ensuite.** Prévoir une nouvelle action versionnée qui couvre effectivement tout ce transcript, ou une autorité indépendante qui vérifie les preuves puis émet la capacité correspondante. Ajouter des métadonnées non signées à une assertion existante est insuffisant. L’évolution conserve intégralement les anciens vérificateurs ; elle ne modifie pas leur sens historique.

Si JWS/JWT est retenu, utiliser la bibliothèque maintenue déjà disponible, avec algorithmes et clés autorisés hors du message, types/audiences/émetteurs distincts et schéma strict. Aucun `alg=none`, `jku`, `x5u`, clé fournie par le client ou conversion automatique entre familles de jetons. [RFC8725](https://www.rfc-editor.org/rfc/rfc8725.html).

Broker **et** Vault vérifient le faisceau de preuves P0-3, les identités canoniques et la destination P0-2. Le ledger Vault consomme atomiquement un nonce court lié au corps, à la session et au certificat destinataire ; les deux nœuds concurrents ne peuvent obtenir deux libérations. Une reprise identique retourne un statut/reçu, sans redistribuer automatiquement du plaintext ; un corps divergent est un conflit audité. Aucun exactement-une-fois global n’est promis entre transport distant et plusieurs bases.

Les délais proposés de capacité peuvent être plus courts que les limites existantes120s/24h/60s ; ils ne les prolongent jamais. Révocation connue, checkpoint périmé, rotation, changement de cible ou composant indisponible refusent une nouvelle libération. Les transports existants sont réellement fermés au délai mesuré de contrôle ; ne pas allonger ce délai pour cacher une panne.

## Coffre utilisateur et coffre technique

Le coffre technique expose aux consommateurs une opération d’injection bornée, jamais une API de révélation offerte au navigateur PAM. Un nouveau formulaire du profil isolé référence un secret importé directement dans Vault par un canal qualifié ; il ne fait pas transiter son plaintext dans l’ancien Web.

Le coffre utilisateur a des objets, collections, partages et droits propres. Révélation/export et mutations sensibles imposent une preuve personnelle fraîche sur l’opération exacte. Un booléen « MFA récente » signé seulement par le Web ne résiste pas à sa compromission. Les clés et la récupération de cette autorité personnelle ne doivent pas être réenrôlées unilatéralement par l’administrateur dont on cherche à se protéger. Ne pas confondre un utilisateur ordinaire du coffre avec un dépositaire ou approbateur PAM.

Un serveur capable de déchiffrer n’est pas zero knowledge. Une interface compromise peut aussi capter un secret saisi ou affiché lors d’une action légitime. Pour revendiquer une protection contre le Web métier compromis, les pages et cérémonies sensibles du coffre doivent provenir d’une origine de confiance distincte ou d’un client indépendant ; même une bonne assertion WebAuthn ne prouve pas ce que l’interface a montré à l’humain. Cette garantie doit être testée et nommée, pas supposée à partir de TLS.

Un broker compromis peut divulguer le credential effectivement reçu pour sa session. La frontière promise est l’absence de clés globales et d’accès arbitraire aux autres credentials. Un mot de passe n’est pas cryptographiquement inutilisable sur toute autre cible qui l’accepterait ; comptes dédiés, renouvellement effectif, restrictions réseau et identifiants éphémères sur cible réduisent cette limite.

## Rotation, histoire et récupération

Réenvelopper une DEK sous une nouvelle KEK est distinct de changer un secret distant ou de rechiffrer les données. Changer le secret ou la destination crée une version et une DEK neuves, puis une autorisation compatible. Conserver les anciennes enveloppes, clés nécessaires et liens de preuve selon la rétention ; ne pas détruire une KEK encore requise par une sauvegarde.

Le risque majeur de migration est de laisser Web/worker conserver `PAMOLIVE_ENCRYPTION_KEY` pour MFA, SCIM, TeamViewer ou Directory tout en leur laissant lire les anciens ciphertexts PAM. Les nouveaux credentials Vault n’annulent pas les anciens secrets encore valides sur d’autres cibles. **La fin de P2 demande aussi de retirer ce pouvoir legacy**, par migration des domaines/consommateurs et médiation des opérations, ainsi que des rôles SQL non propriétaires avec droits de lecture réellement restreints. Un owner PostgreSQL peut contourner des restrictions qu’il administre ; les rôles de migration, runtime et récupération doivent être distincts.

Ne pas tourner en bloc la clé globale actuelle : cela casserait Fernet, sceaux et MAC encore utilisés. Conserver les clés historiques dans un vérificateur legacy dédié avec méthodes par format et but, sans export de clé, déchiffrement générique ou oracle de signature. Pour un HMAC, « clé de vérification » demeure un secret capable de MAC ; la qualifier de publique serait faux. Le trousseau V7/V8 existant reste utilisable dans ce périmètre de récupération. Les nouvelles preuves indépendantes peuvent employer des signatures publiques, sans re-signature rétroactive des anciennes.

Les sauvegardes couvrent données, envelopes, versions de clés, politiques, registres, schémas et références du témoin, avec clés/accès de récupération tenus séparément. Tester une récupération sans HSM disponible n’équivaut pas à qualifier son backup. Utiliser les mécanismes de reprise du KMS/HSM maintenu ; ne pas inventer un partage de secret ou une procédure d’unseal cryptographique maison.

Après restauration/PITR, comparer génération, révisions et révocations à un état indépendant. Invalider les sessions, tickets, capacités et nonces issus de l’archive ; réconcilier les effets incertains avant remise en service. Une ancienne sauvegarde de ledger ne doit pas réautoriser un nonce consommé après sa prise. À défaut de continuité, recommissionner une génération indépendante, sans baisser les quorums. Le break-glass cible suit ADR-013, avec autorité et traces distinctes ; il n’est pas un fallback automatique lorsque KMS ou témoin est indisponible.

## Réception falsifiable

Les essais suivants sont des critères proposés, **non exécutés par cette revue** :

- Vrais services TLS dans des conteneurs/processus distincts : certificats valides, mauvaise CA/SAN/EKU, certificat révoqué/rotaté, en-têtes usurpés, audience/opération/tenant incorrects. Refus avant toute opération KMS.
- Source/cible synthétique V2 : absence de clé globale dans Web/worker, absence de plaintext en HTTP/logs/captures injectées, impossibilité d’ouvrir la cible via le chemin legacy, aucun fallback pendant panne Vault/KMS.
- AEAD : substitution de tenant, domaine, version, destination, clé, nonce ou tag refusée ; enveloppe échangée entre tenants refusée ; corps/algorithmes inconnus et tailles excessives refusés. Retry et rotation ne réutilisent pas un couple clé/nonce pour une nouvelle encryption.
- PostgreSQL réel : deux consommateurs d’un nonce, deux brokers, crash avant/après consommation et réponse perdue ; au plus une remise, état incertain conservé, aucun plaintext retourné par simple retry. Rôle runtime non-owner sans DDL ni accès aux domaines interdits.
- Compromission simulée : requêtes arbitraires Web, worker, broker et Vault limitées à leurs périmètres ; un certificat de broker ne suffit pas à fabriquer des approbations, un principal KMS de tenant A n’ouvre pas les enveloppes B. Documenter les secrets de session qu’un broker légitimement destinataire pourrait voler.
- Révocation/checkpoint/politique/cible/credential modifiés avant et après autorisation : refus ou fermeture réelle du transport dans les délais. Régression complète P0, SSH et RDP/NLA natifs.
- Restauration peuplée : Fernet historique, MAC et preuves V7/V8/captures conservés ; nouveau Vault multi-version, rotation KEK puis DEK, mauvaise clé, clé retirée trop tôt, vieille génération et nonce rejoué refusés. Tester le retour arrière sans réactivation d’anciens credentials.
- Coffre utilisateur : propriétaire/partages/MFA/export, récupération sous la bonne autorité, autre tenant et compte réattribué refusés ; distinguer secret affiché volontairement et credential PAM jamais révélé.

Docker sur un hôte peut prouver les échanges et refus de ce laboratoire, pas une indépendance face au root de cet hôte. La qualification finale requiert autorités de clés séparées, infrastructure prévue, sauvegardes et tests de panne réels. Un KMS logiciel recevant une DEK voit nécessairement cette DEK ; son accès réseau au stockage Vault et ses identités ne doivent pas lui donner automatiquement toutes les enveloppes.

## Agilité post-quantique

Versionner formats, algorithmes, IDs de clés et références de confiance dès P2 ; inventorier TLS, SSH, WebAuthn, Ed25519 et les formats archivés. Ne pas qualifier les signatures classiques du registre ou un TLS classique de post-quantiques. Les standards NIST FIPS203/204/205 couvrent respectivement ML-KEM et des signatures post-quantiques ; leur disponibilité ne qualifie pas automatiquement une pile PamOlive. [Annonce primaire NIST](https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved).

Une future transition utilise des bibliothèques/protocoles standardisés et maintenus, profils explicites et essais d’interopérabilité, sans concaténation de signatures ou construction hybride inventée. Préserver les anciens vérificateurs et l’historique de confiance ; une signature nouvelle ajoutée à une archive atteste son ancrage à cette date, pas une sécurité post-quantique rétroactive de son émission originale.

## Résultat de confrontation

L’agent infrastructure a accepté trois précisions : première tranche V2 et fin de P2 sont deux périmètres différents ; l’AAD de payload ne contient pas la KEK mutable ; une action V2 doit signer réellement nonce/audience/contexte au lieu d’étendre sans signature une ancienne preuve. Le retrait de la clé globale de Web/worker et la restriction SQL non-owner figurent désormais dans sa migration cible.

Aucun désaccord technique n’a été laissé caché. Restent à choisir et qualifier l’opérateur KMS/HSM, les autorités d’enrôlement/récupération, les politiques multi-tenants effectives et les origines des interfaces sensibles. Cette revue recommande l’architecture et ses tests ; elle ne valide aucune implémentation P2 encore absente.

## Primitive locale depuis cette revue d'architecture

ADR-020 et `components/vault` matérialisent désormais uniquement la primitive
d'enveloppe technique, sans service, API, registre d'autorisation ou KMS réel.
Sa revue cryptographique indépendante a exécuté 25 tests existants et huit
sondes adverses supplémentaires, sans blocage identifié dans ce périmètre.
Le 14 novembre 2026, les 25 tests ont également réussi sur une wheel installée
en environnement temporaire ; les dépendances locales existantes y étaient
rendues visibles explicitement. Aucun provider de test n'est inclus dans la
wheel. Cela ne satisfait pas les critères de services TLS, révocation,
concurrence de ledger ou récupération décrits plus haut. Les essais refusant
les exceptions `TimeoutError` ne prouvent aucun délai effectif d'un provider
bloqué : ce contrôle appartient au futur adaptateur isolé.
