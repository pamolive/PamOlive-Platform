# ADR-018 — Inventaire d’annuaire, rapprochement et autorités distinctes

Statut : retenu pour implémentation P1-F, qualification en cours. 11 novembre2026.

## Problème

SCIM et TeamViewer possèdent déjà des correspondances, opérations, reprises et preuves. Les adaptateurs AD/LDAP/Entra P1-C ne traitent que des fixtures éphémères. Il manque un inventaire persistant permettant de comparer les observations aux comptes IAM sans transformer des noms, groupes déclarés ou absences en autorités d’accès.

Un identifiant distant peut se répéter entre deux sources ou organisations. Une modification de destination, de pin TLS, de base de recherche ou de principal de lecture ne doit pas réutiliser silencieusement un ancien secret ou une correspondance. Les continuations LDAP/Graph peuvent aussi détourner des credentials ou masquer une collecte partielle.

## Choix

Conserver la prévisualisation `identity.directory_simulation` et ses règles historiques ; le normaliseur de lecteur versionné v2 reprend son identité UUID stricte, les modèles IAM actuels et les mécanismes d’audit/attestation/activation existants. Ajouter dans Connect quatre familles de modèles tenant-scoped : source, run accepté, faits de run et décisions de correspondance append-only.

La source porte un UUID serveur et une destination immuable : protocole/hôte/port/identité cryptographique et périmètre, base DN et principal LDAP, ou cloud/tenant Graph. Un changement incompatible crée une nouvelle source ; les anciennes observations et décisions gardent leur destination d’origine. Une rotation du secret de la même identité conserve le principal/source mais incrémente sa révision. Aucun ancien secret ne teste une nouvelle destination.

Les preuves de run et de mapping sont liées à l’acteur, à l’organisation et à l’ancre d’audit, avec le mécanisme signé existant. Les imports humains portent `synthetic_fixture`, jamais une provenance de collecteur. Seul l’adaptateur serveur peut produire une observation de transport authentifié de laboratoire. Une signature d’acceptation ne prouve pas la vérité de l’annuaire ni l’indépendance d’une personne PAM.

Une décision de correspondance relie explicitement `(organisation, source, objet distant UUID)` à un compte IAM du même tenant. La révocation et la réassignation sont des décisions historiques, pas une réécriture. La projection n’accorde aucun droit et ne crée aucun mandat PAM ou commande SCIM. Les opérations SCIM/TeamViewer existantes restent leurs propres autorités et conservent leurs règles P0-2.

## Lecteurs et frontières réseau

LDAP/AD : client OpenLDAP maintenu `python-ldap`, dépendance Linux verrouillée dans le lock applicatif et compilée dans un étage Docker distinct. Le runtime installe le wheel et les bibliothèques OpenLDAP, sans compilateur. Le lock de construction reprend exactement les versions applicatives ; les scans et le SBOM couvrent aussi ce lecteur natif. L’absence du client natif sur Windows échoue explicitement ; elle ne déclenche pas de faux transport réussi. LDAP avec StartTLS obligatoire uniquement pour cette première version ; `ldaps://` est refusé explicitement avant lecture de credentials ou connexion. L’API publique `python-ldap` utilisée avec un descripteur déjà connecté ne permet pas de déclencher et qualifier TLS implicite LDAPS ; aucune API privée, double connexion ou suppression de vérification ne contourne cette limite. TLS vérifié, pin du pair et nom contrôlés sur la connexion effectivement utilisée avant tout bind secret ; referrals/reconnexions/downgrade interdits. AD objectGUID est traité avec son encodage binaire défini, LDAP entryUUID avec sa forme UUID stable ; aucun DN mutable ou login n’est une identité d’objet.

Graph : HTTPS et adresse épinglée, GET seulement, origine/tenant/périmètre figés. Une déclaration de tenant ne suffit pas : le tenant effectif doit être confirmé par une réponse authentifiée ou un justificatif cryptographiquement vérifié. Ne jamais décoder simplement un JWT pour lui attribuer une autorité. Les continuations sont validées/reconstruites dans leur périmètre, jamais suivies comme des URLs arbitraires.

Pages (20), objets (1000), groupes (32 par objet), octets conservés (4Mio) et temps (45s) sont bornés. La résolution DNS conserve au maximum quatre slots, y compris lorsque le resolver système continue après le timeout de son appelant ; une cinquième résolution est refusée. Le plafond LDAP est contrôlé après le décodage OpenLDAP : il ne constitue pas une garantie de mémoire avant allocation, qui exige isolation et limites de processus/conteneur. Erreur, boucle de cookie, troncature AD/range ou budget épuisé donnent un résultat incomplet explicite ; cookies et URLs de continuation restent côté serveur. L’absence d’un objet ne prouve jamais sa suppression, même dans un run complet. Aucun retrait automatique n’est dérivé de cet inventaire.

Pour LDAP générique, le schéma standard ne garantit aucun attribut d’activation : une valeur absente reste `null`, exposée avec une assurance `unknown`, et ne désactive aucun compte IAM. AD utilise les bits UAC ; Graph utilise son attribut explicite. La préparation Graph lit les utilisateurs, sans qualifier l’exhaustivité des groupes : le run reste incomplet et porte cette limite. Les collisions de login restent des avertissements et ne décident jamais une identité.

Les lectures réseau restent limitées au laboratoire qualifié et aux destinations autorisées côté déploiement. Les écritures LDAP/Graph ne font pas partie de ce lecteur. Les opérations réelles de provisioning ne sont pas activées par cette livraison.

## Transactions, permissions et preuves

Trois phases : garde fraîche/verrou et capture de révision ; I/O borné sans verrou PostgreSQL conservé ; nouvelle garde et verrou au moment de l’acceptation. Revalider acteur, MFA, modules, source active, révision et identité. Le callback de revalidation est aussi exécuté après TLS avant émission des credentials, avant chaque requête Graph et avant chaque page LDAP. Une désactivation concurrente refuse la publication. Cela ne prétend pas annuler rétroactivement des octets déjà transmis au pair autorisé ; les opérations en cours sont bornées.

Les entrées UI/API sont limitées à 64Kio de corps effectivement lu, y compris sans `Content-Length`, avant parsing MFA. JSON à clés dupliquées, récursion excessive et fixtures non listes explicites sont refusés ; une liste vide reste un inventaire synthétique valide. Les secrets des formulaires invalides ne sont jamais réaffichés.

Configuration et correspondances : administrateur avec MFA récente. Collecte/import : acteur autorisé avec MFA récente. Lectures et exports : rôles explicites, modules actifs et pagination liée au tenant/source/run. Une source désactivée ne peut plus collecter ; son historique reste lisible aux lecteurs autorisés.

Idempotence liée au principal et au périmètre : même clé et contenu canonique identique retourne le même run ; divergence donne un conflit409 audité sans modifier l’original. Des quotas bornent faits/runs/conflits ; aucun effacement automatique de preuves pour libérer de la place. Export strictement whitelisté sans credential, bind secret, capsule, cookie, header ou diagnostic brut.

## Alternatives écartées

- Continuer uniquement les previews JSON : ne fournit ni historique durable ni rapprochement exploitable.
- Réutiliser directement AccountBinding SCIM comme inventaire : confond observations et autorité d’exécution.
- Déduire des liens par email/login/DN ou retirer sur absence : mélange d’identités et de garanties incompatibles.
- Écraser un snapshot ou sa destination : détruit contexte et preuves historiques.
- Onze microservices ou nouveau bus : aucun besoin démontré ; la séparation opérationnelle des composants sensibles reste le lot P2.

## Migration et réception

Migration additive, contraintes PostgreSQL de tenant et d’immutabilité, aucun reclassement des observations historiques. Le downgrade destructeur est refusé lorsque des preuves existent. Conserver les clés historiques et vérifier nouveaux runs/mappings lors des restaurations.

Réception obligatoire : mêmes UUID sur deux sources/deux tenants ; replay/conflit ; fuite de secret ; changement de pin/destination ; révocation/rotation/modules pendant lecture ; pagination/ranges/erreurs partielles ; permissions UI/API/services/exports ; SQL direct ; migrations aller/retour sur copies et rôle restreint ; vrais pairs LDAP/HTTPS synthétiques ; régressions P0 et revue Red Team. Les tests unitaires ou fixtures ne certifient pas AD/Entra commerciaux.

## Références des dépendances

Le client natif suit les [prérequis officiels python-ldap](https://python-ldap.org/en/latest/installing.html) : compilation avec en-têtes OpenLDAP/SASL, aucune roue Windows non officielle introduite. Les essais Linux utilisent un serveur OpenLDAP éphémère, sans extension de schéma fictive pour le statut des comptes. La réussite de ces essais n’est annoncée que dans le rapport de validation correspondant.
