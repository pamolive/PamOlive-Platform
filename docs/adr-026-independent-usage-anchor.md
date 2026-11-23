# ADR-026 — Témoin synchrone des usages Vault V2

Statut : accepté pour implémentation le 15 novembre 2026, après confrontation
architecture/cryptographie et AppSec indépendante. Aucune remise de secret autorisée.

Source W1 implémentée localement. La régression HTTP a été exécutée sur
62 tests purs avant correction, avec un échec attendu, puis sur 62 tests après
correction sans failure, error, skip ni tentative d'I/O externe. Les 59 méthodes
existantes sont conservées ; les signatures synthétiques sont réellement
vérifiées. Ces résultats ne réceptionnent ni SQL/mTLS réel, ni service W installé,
ni durabilité, ni origine humaine ou indépendance d'hôte.

## Problème et frontière de confiance

ADR-024 réserve un nonce, une opération et une expiration dans V, mais une tête
PAM fraîche ne démontre pas qu'une opération V2 n'a jamais été consommée. Une
restauration du ledger V sous la même incarnation, même avant 30 secondes, peut
restaurer un état local cohérent. L'anti-rejeu doit survivre à cette restauration.

Ajouter W, une autorité synchrone des usages et compteurs V2 dans le domaine du
témoin indépendant, avec stockage, identités, administration et restauration
distincts. Deux bases ou conteneurs sur le même hôte ne démontrent que la
séparation fonctionnelle N0 ; root, le superutilisateur du cluster ou un
restaurateur commun peuvent contourner cette frontière. La qualification sur
deux hôtes demeure exigée avant toute revendication correspondante.

## Alternatives examinées

| Modèle | Garantie et dépendance | Décision |
| --- | --- | --- |
| Contraintes, compteurs et audit dans V | Sérialise les appels honnêtes ; état restaurable avec V | Insuffisant contre le rollback de V |
| Export signé périodique | Détection ultérieure ; fenêtre de rejeu entre exports | Complément d'audit |
| Deux bases sur un hôte | Limite certaines erreurs et compromissions de processus | Banc N0, pas indépendance d'administration |
| W synchrone, SQL propre et compteurs uniques | Retient les usages malgré rollback V ; indisponibilité bloquante | Retenu |
| Quorum de témoins / compteur matériel | Étend la menace à W fautif ; exploitation et reprise complexes | Autre ADR si cette menace est requise |
| KMS/HSM seul | Protège des clés, ne connaît pas automatiquement l'usage métier | Futur point d'application, ne remplace pas W |

## Décision et tranche verticale

W reçoit sur un canal mTLS propre une réservation V déjà committée. Il vérifie
les matériaux publics P0 bruts depuis son artefact RO administré et son contexte
indépendant, sélectionne ses activations V2 et conserve baseline, FullTranscript,
hash et échéance immuables. Les contrats V2 et le vérificateur V1 existants sont
réutilisés ; aucun modèle Django ni résultat d'autorité déclaré par V ne devient
une autorité W. Le registre vivant et son policy/target réels font foi.

La tranche doit traverser V réservé → W mTLS/SQL → baseline/transcript W →
nouvelles confirmations V2 valides → consommation W → miroir V. Elle doit couvrir
les terminaux positif `consumed_no_release` et négatif `refused_no_release`,
avec de vraies signatures synthétiques, sans KMS, SDK d'enveloppe ni plaintext.
Ces terminaux ne deviendront jamais des permissions en activant une option.

### Fermeture concurrente du Vault

Le client Vault vérifie avant l'envoi que la réservation appartient au
commissionnement ouvert, avec la même incarnation et la même empreinte de
slot. Après la réponse mTLS, la transaction Vault verrouille cette ligne de
commissionnement, revalide la réservation puis verrouille ou crée son miroir.
Les droits d'écriture sur les réservations restent limités à l'insertion.
Le même contrôle borne l'enregistrement d'un résultat incertain. Un rejeu
terminal authentifié sous commissionnement ouvert compare les octets et
conserve la ligne existante.

Un verrou Vault conservé pendant l'aller-retour mTLS retarderait la fermeture
administrative et ne fournirait pas de commit atomique entre les deux bases.
Le contrôle avant envoi et avant commit a été retenu. Une fermeture peut
intervenir pendant un appel déjà envoyé. Le témoin peut alors conserver une
liaison ou un terminal durable. Vault refuse de publier la réponse et de
confirmer le miroir lorsque son contrôle local échoue.

Une reprise d'autorité après fermeture exige une nouvelle incarnation. Les
appels du client vivant restent fermés dans l'ancien
contexte, y compris les rejeux terminaux. Le contrôle ne garantit pas
une fermeture suivie d'une réouverture
sous la même incarnation. L'incertitude locale conserve l'état du miroir
sans établir l'empreinte de la première tentative de consommation. Une
révocation qui doit arrêter les mutations de W doit aussi fermer son bail
sous l'autorité du témoin.

### Consultation des reçus après fermeture

`POST /v1/operations/observe-terminal` présente le bundle d'origine au
témoin. L'identité mTLS courante doit conserver le service, l'instance et le
certificat DER de l'opération. Le témoin relit le reçu dans une transaction
PostgreSQL en lecture seule, sous son contexte courant. Il vérifie
l'incarnation du témoin, le tenant, l'installation et le commissionnement
du principal. Il compare le digest et les octets d'origine. Un terminal
éligible renvoie le reçu exact conservé, avec `authorized=false`. Une
opération en attente ou absente reçoit un refus. Un bundle différent pour
un terminal éligible reçoit un conflit.

Le client de consultation Vault vérifie son ancien miroir dans une
transaction locale en lecture seule. Il laisse le miroir intact lorsque le
témoin confirme un terminal que Vault avait perdu avant de fermer. La route
peut répondre quand le bail W est fermé, tant que le service W fonctionne
et que l'identité mTLS est toujours autorisée. La remise et les écritures
d'usage restent sous les contrôles du chemin de consommation. La reprise
au-delà d'une rotation d'identité demandera un mécanisme d'archive distinct.

### Redémarrage d'un témoin fermé

Le mode de consultation au démarrage est explicite et utilise le rôle
PostgreSQL dédié `usage_anchor_observer`. Il exige le contexte fermé et
un bail clôturé à un epoch supérieur à celui du slot. Il vérifie le tenant,
l'installation, l'incarnation, l'empreinte du slot et l'identité du
principal Vault. Le rôle doit être dépourvu de droits d'écriture effectifs.
Les consultations revérifient la fermeture dans leur instantané SQL en
lecture seule. Le processus ne monte que le slot épinglé, ses éléments
mTLS et les identifiants SQL d'observation.

L'option de démarrage conserve le refus de l'application ordinaire sur un
contexte fermé. Déduire automatiquement le mode depuis un état SQL
risquerait de changer l'autorité du processus à son insu. Employer le
même rôle SQL avec un filtre HTTP préserverait ses droits d'écriture
sous le filtre. La récupération retient donc une application dédiée, une
route et un rôle SQL distincts. Le reçu d'origine reste consultable sous
la même identité autorisée. Le mode de récupération ne peut réarmer un
bail ni administrer le contexte.

Chaque mutation suit contexte → quota principal → lease → opération → activations
en ordre ASCII → audit. N0 sérialise les écritures par contexte tenant. Le CAS
compare toutes les versions et tous les compteurs du snapshot, y compris les
personnes absentes d'un refus partiel, avant les signatures et le commit. Les
compteurs inclus, usages, terminal, bundle exact et audit sont atomiques. Un refus
valide d'un reviewer/sponsor habilité suffit sans quorum positif ; tout membre
inclus invalide fait refuser le bundle entier sans effet partiel.

Le retry terminal exact renvoie la réponse initiale sans reconsommer les preuves.
Un autre body/bundle donne409 ; baseline stale donne409 sans quarantaine. Un
commit inconnu reste503/uncertain ; aucune compensation ne réarme un usage. Aucun
fallback legacy ou offline n'autorise une consommation si W n'est pas disponible.

Les nouveaux credentials sont dédiés au RP `confirm.pamolive.invalid`, inscrits
dans une chaîne P0 contiguë cosignée après enrôlement/possession, puis activés
avec un nouveau défi W. Une ancienne ligne de compteur SQL Web n'est pas une
baseline indépendante. Le profil0→0 est explicite et conserve un state_version
et une consommation durables, sans prétendre détecter un clone. Aucun credential
V2 n'est utilisé parallèlement dans les cérémonies vivantes P0. La réception de
la frontière de confirmation navigateur/OS est distincte de signatures simulées.

## Arbitrages contradictoires obligatoires

Il n'existe **aucune quarantaine automatique W1** : la bibliothèque WebAuthn peut
refuser un compteur avant de vérifier la signature. Une telle exception n'est
pas une preuve de clone et ne peut suspendre d'autres opérations.

La canonicalité byte-exacte s'applique aux nouveaux objets B/E/F et au wrapper
JSON d'assertion. **Elle ne s'applique pas au `clientDataJSON` signé décodé.**
Celui-ci est analysé strictement, sans doublons, avec bornes et champs fermés ;
challenge, origin et crossOrigin sont validés, puis ses octets originaux sont
transmis à la bibliothèque WebAuthn maintenue. Des ordres de propriétés ou espaces
signés valides ne sont pas refusés implicitement ; aucune réécriture avant
vérification. Deux sérialisations équivalentes exigent chacune leur signature.

`policy_binding_id` est un UUID de liaison administré W, pas une révision UUID
imaginaire dans la policy P0. La policy effective est reconstruite des seuils
signés, de la cible et de minima indépendants qui ne peuvent que renforcer.
W1 active un contexte synthétique sans contrat ; contrat non vide ou champ
policy/target inconnu ferme le bind. Ce périmètre ne remplace pas le moteur
Governance et ne migre aucune cible existante en écartant ses contrôles.

Le nonce peut circuler dans W0/confirmation authentifiés où il est nécessaire.
Il reste absent des logs publics, erreurs et réponses terminales. `authorized:false`
décrit le résultat ; l'absence structurelle de route/provider de remise est le
contrôle effectif.

## Corrections R2 après confrontation indépendante

Le slot W impose `intent_requester_person_id`, UUID canonique provenant de
l'intention indépendante commissionnée. Le même intent ID/hash et des
signatures valides ne suffisent pas à autoriser un autre demandeur. W compare
ce pin au demandeur du draft avant toute transaction ; un ancien slot sans
ce champ refuse sans enrichissement automatique. Ce champ reste propre à W :
aucune extension implicite du contexte partagé ADR-024 ou du registre P0.

Dans `Service`, toute mutation métier passant par
`PostgresLedger.transaction`, ainsi que le retry d'un bind encore pending,
enregistre un callback local d'autorité/contexte RO et d'heure SQL. Le ledger
l'exécute après les écritures et l'audit, juste avant la sortie transactionnelle ;
pour ces chemins, une mutation enregistrée sans callback provoque un rollback.
Ce contrôle ne prend aucun nouveau verrou métier et n'effectue aucun appel
réseau. Il ne garantit pas que l'instant physique de durabilité du COMMIT est
antérieur à l'échéance ; un ACK inconnu reste 503/uncertain et ne réarme aucun usage.

L'administration hors ligne de fermeture/révocation suit son circuit distinct
`Administration._locked` et conserve l'ordre global des verrous et de l'audit.
Le callback d'admission runtime ne lui est pas imposé : ce chemin reste utilisable
pour fermer ou révoquer un contexte expiré, sous ses propres contrôles d'accès et
de transaction SQL. Il n'ouvre, ne renouvelle et ne réarme aucun usage.

Le retry terminal exact reste une observation sans mutation, y compris
après expiration de l'opération. Le DER et le purpose courants, la liaison au
contexte/tenant, le propriétaire et l'instance de l'opération, le bundle reçu
byte-exact et ses hashes restent contrôlés ; le slot et le principal courants
doivent encore être valides. Seules la revérification des preuves/compteurs,
la fraîcheur d'admission de l'opération/lease/checkpoint et le callback mutateur
sont sautés. Aucune nouvelle consommation ni prolongation n'en découle.

Les branches terminales SQL exigent explicitement bundle, digest et réponse
non NULL. Les probes de permissions sont rollback-only même si l'instruction
interdite réussit par erreur. La probe monotone teste un compteur positif1→0
avec version avancée et attend P0001 ; une simple erreur de plage23514 ne
prouve pas le trigger. Ces choix ferment des défauts de source reproduits ;
les tests purs et les deux revues indépendantes ne remplacent pas le vrai
laboratoire PostgreSQL/mTLS/concurrence.

## Restauration, compatibilité et limites

W garde les tombstones ; expiration ne supprime pas une clé consommée. Restaurer
V ne restaure pas W. Une reprise déclarée fence la lease et change le slot V sans
réinitialiser les compteurs W. W restauré ne s'ouvre jamais automatiquement :
continuité durable vérifiée hors sauvegarde, nouvelle incarnation et invalidation
des anciennes leases ; si les compteurs ne sont plus fiables, réactivation
indépendante requise. Le rollback clandestin de W et la collusion V+W restent
hors de cette garantie, explicitement.

Pour une reprise en consultation, conserver hors de PostgreSQL la référence
du contexte fermé, l'epoch minimal et le point de reprise attendu. Restaurer
sur un stockage isolé et vérifier le bail, les reçus et l'intégrité des preuves
avant d'exposer l'interface. Restreindre la connexion au rôle observateur.
Si la restauration précède la fermeture attendue ou si des preuves manquent,
maintenir le service fermé et documenter l'écart. Conserver les archives WAL
et le manifeste sous les droits de l'opérateur de récupération.

La campagne PITR du témoin démontre ce parcours en laboratoire avec un point
nommé après fermeture et un commit ultérieur archivé. Elle redémarre le
service de consultation après vérification de l'état restauré. Le contrôle
hors sauvegarde et la conservation inter-hôte restent des prérequis
d'exploitation. [Qualification PITR](p2-usage-anchor-validation.md#restauration-physique-à-un-point-nommé)

Pour vérifier la continuité de l'audit après reprise, conserver un point
d'ancrage complet hors de la sauvegarde et sous une autorité indépendante de
la base restaurée. Ce point associe le contexte fermé, l'empreinte du fichier
de slot, l'organisation, l'installation, la dernière séquence et l'empreinte
de tête. Conserver ce tuple dans un registre authentifié avec intégrité et
contrôle d'accès. La preuve couvre la chaîne conservée jusqu'au point d'ancrage.
Son origine et l'intégrité de la source avant capture relèvent de l'autorité
qui conserve le point.

L'opérateur utilise `assembly.audit_archive_page` avec le slot épinglé, la
connexion observateur et le point d'ancrage indépendant. Son premier appel
part de `after_seq=0`. Il transmet les pages bornées à `ArchiveVerifier` et
utilise le curseur vérifié pour poursuivre. La validation complète exige
`finish()`. Les pages `pamolive.vault.usage-audit-archive-page/1` préservent les
octets historiques et leur chaînage. Elles contiennent des identifiants
d'audit et suivent les règles de protection des preuves. L'export hors ligne
s'ajoute au parcours fermé sans migration ni nouvel accès HTTP. La vérification
d'une chaîne avant et après rotation de slot repose sur des points séparés
pour chaque contexte.

Un V compromis disposant d'un unwrap KMS générique peut ignorer W. Avant remise,
une garde indépendante devra imposer chaque usage W avec claim d'émission unique,
tenant/destination/broker/version/certificat exacts et aucun chemin générique
accessible à V. W1 ne crée pas ce service et ne revendique pas sa garantie.

P0-1 à P0-4, vérificateurs V1, preuves V7/V8, Fernet et ancien chemin PAM restent
préservés. Aucune migration automatique de secrets, de credentials ou de
compteurs existants. Les 35 groupes High et la provenance de build incomplète
continuent à bloquer main/image ; cet ADR ne les arbitre pas.

## Contrats et validation

Les octets, tailles, états, sources, verrous et HTTP sont normatifs dans
[le contrat W1](p2-usage-anchor-contract.md). Les cas complémentaires sont dans
[le plan de validation](p2-usage-anchor-validation.md). Exiger tests purs, vraies
signatures, rôles PostgreSQL restreints, mTLS/DER par connexion, concurrence,
révocation/fencing, commit perdu, crash, idempotence et rollback V dans30s.
Les succès unitaires ne réceptionnent ni durabilité, ni origine humaine, ni
indépendance d'hôte. La qualification installée ADR-025 reste une porte distincte.

Filiation locale conservée : proposition architecture `fb1bcf5b…`, addendum
`94257dc0…`, revue AppSec `9c932c70…`. La revue clôt A–E au niveau conception,
avec la précision clientDataJSON ci-dessus. Lors de cette décision initiale de
conception, aucun test SQL/TLS/signature du nouveau service n'était encore reçu.
Cette mention est historique ; le statut local courant et les 62 tests purs reçus
sont décrits en tête, sans réception SQL/mTLS ou de service installé.
