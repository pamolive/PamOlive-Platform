# Contrat W1 — témoin indépendant des usages

Statut normatif : accepté pour implémentation par ADR-026.

Source W1 implémentée localement. La régression HTTP a été exécutée sur
62 tests purs avant correction, avec un échec attendu, puis sur 62 tests après
correction sans failure, error, skip ni tentative d'I/O externe. Les 59 méthodes
existantes sont conservées ; les signatures synthétiques sont réellement
vérifiées. Ces résultats ne réceptionnent ni SQL/mTLS réel, ni service W installé,
ni durabilité, ni origine humaine ou indépendance d'hôte.

La filiation documentaire figée reste conservée dans output ; les mentions de
proposition ci-dessous décrivent cette filiation historique. ADR-026 et les
clarifications suivantes ont priorité.

**C01 — ClientData signé :** la canonicalité byte-exacte porte sur B/E/F et le
wrapper JSON d'assertion, jamais sur les bytes décodés clientDataJSON signés.
Parsing strict sans doublons, bornes, champs et valeurs fermés ; transmettre les
bytes originaux au vérificateur maintenu. Ordre de propriétés et espaces valides
restent admis avec leur signature propre, sans réécriture.

**C02 — Demandeur de l'intention :** le slot W-only impose le champ canonique
`intent_requester_person_id`, commissionné indépendamment. Bind compare
exactement ce champ au demandeur du draft avant SQL. Une autre personne
habilitée P0 ne devient pas le demandeur de cette intention, même avec le même
ID/hash et de vraies signatures. Slot ancien incomplet : refus fermé ; aucune
inférence depuis le draft, les alias ou les rôles. Le pin de tout le slot
engage déjà ce champ ; les contrats partagés ADR-024 restent inchangés.

**C03 — Bord de commit :** Dans `Service`, toute mutation métier passant par
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

Les références aux golden désignent les oracles statiques de codec dans
`components/usage-anchor/tests/golden/codec.json`, à copier byte pour byte depuis
le corpus indépendant. Leurs signatures sont des placeholders non autoritaires.
Le [plan de validation](p2-usage-anchor-validation.md) distingue les tests purs
locaux reçus des essais SQL/mTLS/concurrence qui restent à exécuter.

# Addendum normatif W1 — fermeture des contrats avant code

Texte historique du 15 novembre 2026, avant implémentation : proposition pour arbitrage Root puis contre-revue ciblée AppSec ; numéro ADR non attribué à ce stade. **À ce stade historique, aucune implémentation, remise ni réception opérationnelle.** Le statut courant est décrit en tête. Cet addendum supplante uniquement les clauses contradictoires du gel initial `fb1bcf5b402792ef1218644adc3c20d08163e336e5d3f8b9ba7697f02f7e8ab1`, dont les huit fichiers restent inchangés. Il répond à `report.json` AppSec SHA-256 `e6a2c5ce480816952680adbf0e65fbddf3d2395e5fb2972867919ce5877bb9cc`, gel AppSec `ec736b33fe70ecb40c11c07f1a21980fe4102ed8e958f68b7f89f0f4fe2b6886` et aux décisions Root A–E.

Les octets et types des trois engagements sont désormais dans [les octets normatifs](#octets-normatifs), avec golden indépendants de codec dans `GOLDEN-CODEC.json`. Ces golden ne portent aucune signature valide ni autorité PAM ; aucune primitive d'authentification n'est exécutée pour ce dossier. Le plan de réception supplémentaire est dans [le plan de validation](p2-usage-anchor-validation.md).

## A. Aucun mécanisme de quarantaine W1

La possibilité de quarantaine facultative décrite par le gel initial est supprimée entièrement de W1 : aucun état, champ, endpoint ni transition W1 ne suspend automatiquement une clé à partir d'un résultat WebAuthn. Utiliser `webauthn==3.0.1` avec le compteur courant réel W, après contrôle CAS. La comparaison de compteurs précède la signature dans cette bibliothèque ; **son exception ne prouve pas une signature valide**. Ne pas dériver de ce détail un nouveau wrapper crypto, une vérification avec baseline0, une accusation de clone ou une suspension globale.

Un échec de vérification retourne l'erreur générique de l'opération. Il ne modifie aucun compteur, activation, challenge, autre opération ou état terminal de celle-ci. Un audit d'échec borné peut être ajouté selon l'ordre global des verrous ; il n'est pas une preuve de signature valide. Les révocations administratives indépendantes conservent leur circuit normal ADR-013. Une éventuelle analyse de clone est un travail ultérieur, hors chemin W1.

## B. Ordre global unique des verrous

Toute transaction W1 qui peut écrire — bind, consume positif/négatif, première insertion, activation/révocation, lease/fencing, quota ou audit d'échec — suit exactement cet ordre, en sautant seulement les classes inutiles et sans revenir à une classe antérieure :

| Rang | Verrous | Clé de tri |
| --- | --- | --- |
| 1 | Contexte d'autorité administré | `(installation_vault_uuid, tenant_uuid)` ; UUID canoniques comparés octet ASCII |
| 2 | Scopes quota des principals concernés | `(installation, tenant, principal_type, principal_id)` ; chaînes ASCII canoniques |
| 3 | Leases concernées | `(installation, tenant, vault_service_id)` en ASCII |
| 4 | Opérations concernées | `(installation, tenant, broker_principal, operation, idempotency_key)` puis ID W si nécessaire ; ASCII |
| 5 | Activations d'authentificateurs | `(installation, tenant, credential_id_canonical)` en ordre C/ASCII ; si plusieurs versions historiques, activation_version croissante |
| 6 | Tête d'audit du contexte | `(installation, tenant)` |

Le credential est le base64url canonique non paddé, pas un collationnement linguistique de la base. SQL impose une collation C explicite aux tris de texte concernés ou transmet un ordre de paramètres déjà trié en ASCII et démontré en test ; aucun tri case-insensitive. Les UUID ne deviennent pas des séquences d'autorité : ce tri sert seulement à éviter les cycles de verrous.

**N0/W1 sérialise toutes ses écritures par un contexte par tenant.** Aucune transaction métier multitenant. Une localisation initiale par ID d'opération peut être une lecture non verrouillante ; après acquisition du contexte, relire et vérifier tenant/clé/contexte avant le premier verrou de rang4. Ne pas commencer par `SELECT ... FOR UPDATE` de l'opération puis demander le contexte. Une opération absente n'a pas de row lock : contexte et quota verrouillés sérialisent sa première insertion et l'unicité. Même règle pour l'activation initiale.

L'administration de révocation/fencing prend d'abord le contexte, localise sans lock inverse, puis verrouille leases, opérations et activations dans ces ordres avant de terminer à la tête d'audit. Une invalidation peut être appliquée via epoch/version du contexte sans modifier toutes les opérations ; si elle écrit ces lignes, elle respecte les mêmes rangs. Les écritures d'audit restent en dernier ; après ce rang aucun nouveau verrou métier n'est acquis. Ne pas introduire de trigger, clé étrangère, verrou consultatif ou fonction SQL qui inverse cet ordre implicitement ; le schéma futur doit les inventorier. La sérialisation du contexte limite les débits N0 mais évite une optimisation prématurée.

Les vérifications crypto peuvent être précalculées hors transaction, sans autorité de commit. Le CAS, les expirations et les états sont revérifiés sous locks. Employer une heure SQL réellement actuelle (`clock_timestamp()`), pas une date figée au début de transaction, et la relire avant commit. Aucun réseau sous verrou, timeouts bornés, `synchronous_commit=on` et durabilité à qualifier. Un résultat de commit inconnu ne devient jamais un succès supposé.

## C. Machine d'état positive et négative fermée

La préparation W conserve l'état `pending_proofs`. Les terminaux de W1 sont exactement :

- `consumed_no_release` : bundle complet d'autorisation positive valide, sans remise.
- `refused_no_release` : au moins un refus reviewer/sponsor autorisé valide, sans remise.
- `expired_no_release` ou `invalidated_no_release` : terminal administratif/temporel sans prétendre consommer des assertions absentes. Cette transition ne remet jamais le nonce à disposition ; elle peut être matérialisée ou calculée depuis l'état d'autorité avec le même résultat de refus.

Un état terminal ne redevient ni pending, ni un autre terminal d'approbation, ni une capacité de release. Aucun DELETE/recréation, nouveau nonce, compteur remis à zéro, compensation ou remplacement de bundle ne contourne cette règle. Le draft et `FullTranscript` restent immuables. Les terminaux W1 ne seront jamais promus en permissions lorsque le code de remise sera ajouté.

Le retry200 du consume concerne les deux terminaux de preuves qui ont réellement accepté et conservé un bundle (`consumed_no_release`, `refused_no_release`). Une opération seulement expirée/invalidate ne possède pas de bundle accepté : un consume reçoit410/403 selon la cause, et seule une consultation de statut autorisée peut l'observer avec200. Ne pas inventer un digest pour satisfaire la branche idempotente.

### Ordre d'évaluation d'un consume

1. Vérifier l'identité mTLS actuelle, son audience, tenant et droit d'observer cette clé métier ; bornes et forme du body/bundle ; comparer le body_hash exact. Une rotation DER ne transfère pas une opération.
2. Sous ordre global, retrouver la clé métier et un éventuel terminal. **Retry terminal exact** `(clé, body_hash, final_assertions_digest, octets bundle)` : renvoyer seulement le statut original, sans réévaluer les compteurs, sans aucune remise et sans nouvelle mutation. Un bundle/body divergent :409. L'observation d'un terminal ancien n'exige pas de raviver sa lease expirée ; le canal et le mapping courant d'observation doivent rester autorisés.
3. Pour une opération pending, vérifier contexte/lease/fence/révocations/fraîcheur et échéance réelle. Puis comparer **tous** les compteurs et state_version du snapshot aux lignes actuelles, y compris ceux des personnes absentes d'un bundle négatif partiel : baseline stale =>409, aucune quarantaine ni consommation. A=5 reçu après B=6 sur baseline4/v1 est ce cas, pas une preuve de clone.
4. Vérifier chaque assertion incluse avec son credential/activation, le challenge V2 exact, RP/origine, UV/UP, userHandle et décisions/rôles autorisés. Tout membre invalide invalide le bundle entier : aucun sous-ensemble n'est committé. Ne pas ignorer une assertion invalide parce qu'un autre membre porte un refus valide. Le motif public d'échec reste générique, y compris pour une erreur de compteur préalable à la signature.
5. Déterminer le résultat ci-dessous et préparer les mises à jour **uniquement pour les assertions incluses toutes vérifiées**. Contrôler à nouveau contexte/heure au bord de commit. Commit atomique compteur/state_version, challenges/usages, octets et digest du bundle retenu, terminal, audit et réponse terminale figée. Aucune émission de secret.

### Règle de décision

Les personnes et rôles du draft sont confrontés aux personnes canoniques et habilitations actives de la tête P0 cosignée et au scope cible exact. Des IDs distincts ne prouvent pas des humains distincts ; l'autorité de commissionnement P0 reste la racine. Le demandeur et ses alias sont exclus des reviewers/sponsor.

| Membre | Décisions syntaxiques | Condition |
| --- | --- | --- |
| Requester | `launch` seulement | Personne requester exacte du draft, habilitée requester sur la cible |
| Reviewer | `approve` ou `refuse` | Personne présente dans approver_person_ids du draft, habilitée reviewer sur la cible, distincte du requester |
| Sponsor | `sponsor` ou `refuse` | Sponsor exact du draft et du target signé, habilité sponsor sur la cible, distinct du requester |

**Si toutes les assertions incluses sont valides et qu'au moins un reviewer/sponsor ainsi habilité signe `refuse`, le terminal est `refused_no_release`.** Aucun quorum d'approbation ni launch du requester n'est requis pour fermer cette opération par refus. Le bundle peut ne contenir que cet unique refus. Le requester ne peut jamais signer une décision refuse avec le rôle launch ni s'attribuer le rôle reviewer/sponsor. Cette décision rejoint la sémantique métier existante de `approvals.services.decide`, où un refus met la demande en `denied` ; elle n'importe pas ses mutations Django dans W.

En l'absence de refus, seul un bundle comprenant requester.launch, le nombre requis de **personnes canoniques distinctes** reviewer.approve et sponsor.sponsor si requis peut finir `consumed_no_release`. Un bundle positif incomplet reste non committé et reçoit403 générique ; il ne conserve pas une approbation partielle. Une personne sponsor également reviewer peut compter une seule fois dans le quorum, si habilitée reviewer et si sa confirmation reviewer existe ; le défi sponsor ne lui donne pas une seconde voix.

### Compteurs zéro, multi-rôles et négatif

Pour chaque credential inclus, vérifier les assertions dans l'ordre déterministe décrit au contrat d'octets. Si les sign_count non nuls sont utilisés plusieurs fois pour des rôles distincts, ils doivent être strictement croissants sans doublon au-delà de la baseline, et chaque appel au vérificateur maintenu reçoit le compteur courant de la séquence validée. Si une étape échoue, tout le bundle échoue. Le dernier compteur validé est la seule valeur écrite ; state_version augmente **une fois par credential et opération**.

Le profil0→0, explicitement commissionné, accepte plusieurs défis distincts pour un même credential sans attribuer de détection de clone : chacun doit être valide, chacun reçoit un usage consommé et state_version augmente une seule fois. Un passage0→nonzero est admis, puis zéro ne peut plus suivre une valeur non nulle dans ce bundle ou les usages ultérieurs. Les compteurs ne sont jamais interprétés modulo2^32. Le choix de tri non nul est numérique croissant ; à égalité zéro, ordre des membres canoniques. Il n'autorise ni doublon de personne/rôle ni plusieurs credentials pour le même rôle de personne.

Un négatif contenant plusieurs rôles valides consomme **tous les membres inclus**, y compris leurs décisions positives, en même temps que le refus terminal. Les personnes absentes ne voient ni compteur ni challenge consommé, même si leurs lignes ont été verrouillées pour CAS du snapshot. Pour sponsor.sponsor et reviewer.refuse d'une même personne habilitée avec le même credential, deux défis distincts sont nécessaires ; les deux compteurs sont validés, une seule mise à jour finale, terminal refusé. Une mauvaise signature incluse ne met en quarantaine personne et ne termine aucune autre opération.

### HTTP et réponse exacte

| Situation | HTTP et effet |
| --- | --- |
| Première liaison W0 créée | 201, transcript complet seulement sur canal autorisé ; `authorized:false` |
| Retry exact W0 encore pending | 200, mêmes transcript/dates/snapshot ; `authorized:false` |
| Première consommation positive ou refus valide | **200**, observation de `consumed_no_release` ou `refused_no_release`, `authorized:false` ; ce n'est pas une permission |
| Retry terminal exact | **200**, réponse terminale canonique originale byte-identique, même après expiration du transcript, si droit courant d'observation ; aucune réévaluation des compteurs |
| Même clé, autre body/bundle/certificat/contexte de liaison |409, aucun nouvel usage |
| Snapshot stale |409 `baseline_stale`, aucun compteur/terminal modifié |
| JSON/tailles/canonicalité invalides |400 générique, aucun effet métier |
| Assertion/décision/rôle/quorum invalide ou positif incomplet |403 `proof_refused` générique, aucun effet métier ; pas de diagnostic signature/compteur |
| Pending expiré, y compris now==expires |410, aucune preuve ressuscitée ; terminal temporel observable séparément |
| Autorité/lease révoquée, mauvaise audience/tenant |403 générique ; observation terminale seulement si mapping courant l'autorise |
| W/SQL/transport indisponible ou commit inconnu |503 `unavailable` / uncertain côté V, pas de compensation ni re-émission |

Réponse terminale canonique fermée : `{schema, operation_id, reservation_id, state, body_hash, final_assertions_digest, issued_at, expires_at, terminal_at, authorized}`. Schema=`pamolive.vault.usage-terminal/1`, state positif/négatif ci-dessus, authorized est le booléen JSON false (profil de réponse distinct du V2 signé qui interdit les booléens). UUID canoniques, hashes hex SHA-256, dates entières UTC. Cette réponse n'inclut pas le nonce, les assertions, les compteurs ou le transcript. Son `terminal_at` est enregistré une fois, jamais recalculé au retry ; aucun now dynamique. Pour un terminal temporel/administratif sans bundle, utiliser une réponse de statut distincte et ne pas fabriquer un digest d'assertions.

## D. Matériaux RO, politique effective et autorités indépendantes

Choisir le bundle public **RO commissionné W** plutôt qu'une chaîne fournie par chaque bind HTTP. Le comparatif et les octets normatifs sont dans BYTE-CONTRACTS. Le slot W pinne un artefact local unique et fixe sa version/chemin au démarrage ; la requête ne choisit ni chemin, URL, clé ou nouvelle autorité. W lit ses octets, reconstruit le frame et les hashes, puis appelle réellement `verify_current_registry_materials(tuple(raw_chain), raw_checkpoint, CurrentContext_indépendant)` avec heure serveur. Un résultat/DTO ou hash venant de V n'est pas l'entrée autoritaire.

Le résultat API existant contient notamment `canonical_head_envelope`, `canonical_checkpoint`, `checkpoint_sha256`, `registry_hash`, `input_sha256`, `envelope_commitments`, `context_fingerprint`. Lire le `body` de la tête canonique vérifiée ; ne pas chercher une propriété policy/target inexistante sur le DTO. `checkpoint_sha256` porte sur les **octets bruts** du checkpoint. `context_fingerprint` inclut l'heure now et ne remplace pas un pin stable de matériaux. La bibliothèque accepte1..256 documents, <=2MiB/document, somme chaîne<=32MiB, checkpoint<=65536 octets ; ce n'est pas le plafond3MiB de l'endpoint de réservation V actuel. W1 ne change pas cet ancien endpoint implicitement.

### Politique effective réellement dérivée

- `draft.policy_hash = SHA256(p0_canonical(head.body["policy"]))`, sans domaine nouveau, conforme au hash de payload P0. Vérifier la valeur contre celle calculée et la liaison indépendante du slot ; ne pas croire le champ V.
- `standard_min` et `critical_min` viennent du vrai objet policy cosigné. `target = head.body["targets"][draft.target_id]`, son scope complet et son epoch sont vérifiés. `required_reviewers=max(policy[critical_min si target.critical sinon standard_min], target.get("min_reviewers",1), minimum_slot_indépendant)` ; le minimum du slot ne peut qu'augmenter.
- Si required_reviewers dépasse16 ou le nombre de reviewers distincts du draft, W1 refuse le bind ; il ne tronque jamais un seuil pour entrer dans son budget. Les entiers des nouveaux profils doivent tenir leurs bornes strictes même si une archive V1 plus permissive est cryptographiquement valide.
- Le sponsor requis est `target.get("sponsor_person", "")`, pas un choix Web ; son habilitation et endpoint sont vérifiés dans les persons signées. Les flags sponsor_required/contract_required vrais exigent leurs références, comme le profil P0 ; des références non vides imposent leur obligation même si un flag est absent/faux, comme `protected_target`.
- Le contrat est `target.contract_id` avec `contract_authority.revision/hash` signés. **W1 n'active que le profil synthétique sans contrat (`contract_id=""`)**. Une référence non vide bloque le bind tant qu'un document de contrat indépendant, sa sémantique et son validateur ne sont pas reçus ; un résumé V ne suffit pas. Cette restriction n'affaiblit pas le contrat requis P0 et ne déclare pas les archives invalides.
- Le UUID `draft.policy_revision` n'est pas un champ `policy.revision` P0 : les policy réelles lues ne l'exigent pas. Il provient d'une liaison de contexte commissionnée W qui fixe UUID, génération/révision/head, hash réel de policy, target/scope, intention et live credential. Un UUID client n'est jamais l'autorité. La source UUID est nommée `policy_binding_id` dans la nouvelle configuration pour ne pas prétendre qu'il s'agit d'une révision P0 signée.
- `trust._policy_snapshot` représente un autre objet P0, issu du moteur governance : `id,min_reviewers,critical_reviewers,supplier_sponsor_required,require_external_contract`. Il ne faut pas le confondre avec `registry.body.policy` ni importer une copie Web pour choisir une politique. W1 applique la politique indépendante du registre/target et des contraintes du slot ; il ne prétend pas reproduire tout le moteur governance ou sa politique publiée. Une contrainte supplémentaire applicable doit être commissionnée indépendamment, sinon la cible reste hors profil W1 ; aucun champ obligatoire existant n'est silencieusement écarté lors d'une migration produit.
- Credential_secret_id/version/wrapping_revision/profile live et intent_id/intent_scope_hash viennent de cette même liaison administrée indépendamment et du slot V concordant. W les compare au draft ; aucune sélection depuis JSON V. W1 n'invente pas un registre de credentials produit : c'est une table de contexte synthétique explicite, limitée à une cible et une version, sans secret ni pouvoir KMS.

Le profil vivant W1 comprend policy exactement `{standard_min,critical_min}` et target avec champs connus `scope,critical,min_reviewers,contract_id,contract_authority,sponsor_person,contract_required,sponsor_required` ; les optionnels gardent leur sémantique P0. Un champ de politique/target inconnu bloque ce profil vivant jusqu'à revue, mais n'altère ni la validité cryptographique historique V1 ni ses vérificateurs. Le bootstrap actuel sans target/authentificateurs/rôles ne satisfait pas ce profil. Il faut une nouvelle fixture indépendante avec update contigu cosigné, personnes/rôles, scope réel et nouveaux credentials du RP dédié, comme décrit au gel initial ; aucune valeur opaque du fixture pending n'est promue en autorité.

## E. Nonce dans les canaux autorisés

Le nonce d'opération32 octets est dans `FullTranscript` et doit être reçu par la confirmation de confiance pour recalculer son body_hash/challenge. Il peut donc être transmis dans la réponse W0 authentifiée V et dans le canal de confirmation **explicitement autorisé et indépendant de Web**, avec contrôle d'accès au contexte complet. Le nonce seul n'est pas une capacité.

L'interdiction porte sur les réponses publiques non autorisées, erreurs, métriques, reçus publics, logs et terminal-status ; elle ne porte pas sur toutes les réponses W0. Les assertions brutes, transcript et baseline sont également des données d'accès borné, pas des diagnostics publics. Le Web tenant ne doit pas devenir le canal de confirmation de confiance. Le contrôle d'origine/RP et l'affichage exact gardent leurs préconditions de qualification ; W1 synthétique ne prétend pas qu'une vraie frontière navigateur/OS est déjà reçue.

## Conséquences conservées

W reste l'autorité unique V2 ; V commit sa réservation avant W0, W commit sa consommation avant miroir V, puis aucun terminal ne remet un secret au retry. Délais cp synthétique40s/op30s, lease/fencing/DER exacts, restauration V sans rollback W, restauration W fermée, garde KMS future indépendante par opération, V7/V8/P0 inchangés : tous conservés. Pas de quarantaine, pas de source policy/credential Web et pas de nouveau service de contexte. La prochaine livraison après arbitrage est une tranche verticale réelle sans secret — **pas un lot DTO seul** — puis réception SQL/mTLS/concurrence/crash/rollback distincte. Les35High et la provenance de build ne sont pas arbitrés par cet addendum.


<a id="octets-normatifs"></a>

# Octets normatifs W1 : matériaux, baseline, bundle

Proposition fermée avant code. Aucune modification des formats ADR022 ni des octets/signatures V1. Ces contrats d'assemblage appartiennent au runtime W1 ; ils ne transforment pas un DTO en permission. `GOLDEN-CODEC.json` contient des préimages/hex/longueurs/hashes et mutations calculés indépendamment du code produit, sans signature ou autorité réelle.

## Conventions communes

La règle C01 d’ADR-026 exclut explicitement les bytes signés clientDataJSON
décodés de la canonicalité des wrappers. Cette exception est obligatoire.


`U32(n)` : entier non signé32 bits en big-endian, exactement4 octets. `L(x)=U32(len(x)) || x` pour une suite d'octets non vide. Longueurs en **octets**, jamais caractères. Rejeter longueur nulle/hors budget, troncature, suffixe après fin attendue et overflow avant allocation. Les domaines ci-dessous sont ASCII avec **un unique octet NUL terminal** ; la notation `\0` dans le texte ne représente pas les deux caractères antislash-zéro.

Pour les nouveaux JSON canoniques : UTF-8 sans BOM, `ensure_ascii=True`, clés triées par codepoint ASCII, séparateurs `,`/`:`, aucune espace finale ni newline ; chaînes ASCII uniquement, pas de NUL, nombres entiers stricts non signés sans conversion implicite, ni booléen/null/flottant. UUID : texte canonique minuscule avec tirets. Hashes SHA-256 :64 hex minuscules. Base64url : alphabet `[A-Za-z0-9_-]`, sans padding, décodage puis réencodage identiques. Les JSON reçus doivent être **byte-identiques à leur réencodage canonique** : variantes whitespace/échappements/ordre refusées. Rejeter les doublons de clés avant de construire un dict. Les listes signifiantes doivent déjà être dans leur ordre prescrit ; ne pas les trier pour rendre une entrée invalide acceptable.

Le JSON WebAuthn interne décrit plus bas a une exception nullable explicite pour userHandle ; le JSON V1 garde son profil historique Unicode/float/bool et n'est jamais recanonisé pour calculer le hash de matériaux bruts. Les réponses terminales HTTP ont également leur profil distinct avec authorized=false. Ces exceptions ne changent pas les types du transcript V2 existant.

## 1. Matériaux publics — `authority_materials_sha256`

### Choix du transport et de la garde

| Option | Gain | Coût / décision |
| --- | --- | --- |
| Chaque bind transporte une chaîne brute arbitraire | Pas de provisionnement local de corpus | Até32MiB répétés avant vérification, attaque bande passante/parsing, choix de corpus par V ; rejetée pour W1 |
| Digest déclaré V ou DTO de résultat V1 | Petit message | Aucun octet public à vérifier indépendamment ; rejetée |
| Artefact RO local W, pin exact administré hors Web, référence fermée dans slot | Réemploi des corpus/public verifier existants, trafic bind borné, identité de bytes stable | **Retenue** ; renouvellement de tête/cp requiert nouvelle révision cohérente de slot/artefact, sans service de contexte |

Un seul artefact de matériaux est actif par contexte W1. Le chemin absolu est fixé au startup par configuration administrée, jamais par une requête ; file/parents réguliers RO, non-symlink, propriétaire administré, pin et identité relus selon les garanties du slot existant à adapter. Aucun chemin interne au frame, URL ou découverte de clés. Les clés attendues restent dans le slot extérieur indépendant. L'identifiant d'artefact, si transmis, est un UUID opaque qui doit être exactement celui du slot ; il n'entraîne aucun lookup dynamique.

Le bind W1 HTTP est borné à32768 octets (draft<=16384 plus nonce/dates/références fermées). Il n'accepte pas registry_chain/checkpoint en corps. La route ADR024 pending actuelle et son plafond3MiB gardent leur sémantique ; toute route d'intégration W1 est explicite. L'artefact est borné en disque/mémoire avant parse et les workers reçoivent une limite mémoire couvrant son plafond ; W1 n'active qu'un contexte/tenant par instance de qualification.

La réponse authentifiée W0 est bornée à196608 octets et contient exactement `{schema,operation_id,reservation_id,body_hash,authority_materials_sha256,baseline_b64,transcript_b64,authorized}` ; schema=`pamolive.vault.usage-bound/1`, authorized=false. baseline_b64 et transcript_b64 sont les base64url canoniques des bytes B et FullTranscript existant, donc comportent indirectement le nonce nécessaire à la confirmation. IDs/hashes ont leurs types stricts usuels. Le récepteur décode, rehashe et vérifie l'égalité avec sa réservation/contexte ; aucun de ces octets n'est un credential. Le booléen de réponse appartient au profil HTTP, pas aux objets signés V2.

### Frame exact

```text
MATERIALS_DOMAIN = ASCII("pamolive.vault.public-materials.v1") || 0x00
M = MATERIALS_DOMAIN || U32(N)
    || L(raw_registry_envelope_1) || ... || L(raw_registry_envelope_N)
    || L(raw_checkpoint)
authority_materials_sha256 = SHA256(M)
```

Le fichier RO contient exactement `M`. Les documents sont les **octets JSON V1 bruts** préexistants, signatures et champs inconnus inclus, jamais un résumé ou une nouvelle signature. L'ordre est bootstrap puis chaîne contiguë dans l'ordre de révisions fourni et vérifié par l'API, sans suffixe, tri ou reconstruction SQL. N1..256 ; chaque document1..2097152 octets ; somme des documents<=33554432 ; checkpoint1..65536 octets. Plafond du fichier = `len(MATERIALS_DOMAIN)+4+4*256+33554432+4+65536` ; le lecteur refuse le dépassement, ne conserve pas un blob annoncé non borné. Rejeter des bytes après le checkpoint. Le parseur compte toutes les longueurs avant toute désérialisation JSON V1.

W décompose les slices, reconstruit ce même M à partir d'elles, compare les bytes/pin du fichier et le hash attendu du slot, puis vérifie chaque brut via `verify_current_registry_materials`. La reconstruction évite de considérer un header/compteur opaque comme preuve de contenu. `draft.authority_materials_sha256` doit égaler ce SHA256 reconstruit ; `draft.checkpoint_hash` doit égaler SHA256(raw_checkpoint), identique au champ `CurrentRegistry.checkpoint_sha256`. `draft.registry_hash` doit égaler l'engagement P0 de la tête retourné par l'API, **pas** SHA256 du JSON brut de cette tête. Les autres égalités installation/tenant/génération/révision sont celles du contexte indépendant.

Le hash n'inclut **aucune baseline, compteur mutable, transcript, assertion finale, signature V2, credential secret ou clé privée**, et n'inclut pas un `context_fingerprint` dépendant de now. La politique, cible et clés publiques sont déjà dans la tête signée, donc incluses avec leurs vrais octets publics. Les références credential/policy_binding/intention administrées indépendantes appartiennent au slot et à son pin, pas à ce corpus P0.

Un checkpoint nouveau produit un autre M et un autre hash. Une opération déjà liée ne change jamais de M pour prolonger son échéance ; il faut nouvelle opération/nouvelles confirmations. Pour W1 le checkpoint de fixture demeure émis pour40s et le transcript au plus30s, sans refresh automatique. La limite générale P0 de60s n'allonge pas cette fixture.

## 2. Baseline autoritaire — `authenticator_counter_baseline_hash`

### Objet exact

```text
B = canonical_ascii_json({
  schema: "pamolive.vault.counter-baseline/1",
  installation_id: UUID,
  organization_id: UUID,
  trust_generation: UUID,
  registry_revision: INT63_POSITIVE,
  registry_hash: SHA256HEX,
  policy_binding_id: UUID,
  policy_hash: SHA256HEX,
  effective_policy_sha256: SHA256HEX,
  witness_incarnation: UUID,
  witness_slot_sha256: SHA256HEX,
  activations: [
    {
      person_id: UUID,
      role: "requester" | "reviewer" | "sponsor",
      credential_id: CANONICAL_BASE64URL,
      spki_sha256: SHA256HEX,
      enrollment_id: UUID,
      rp_id: ASCII,
      origin: ASCII,
      activation_version: INT63_POSITIVE,
      state_version: INT63_POSITIVE,
      sign_count: UINT32
    }, ...
  ]
})
BASELINE_DOMAIN = ASCII("pamolive.vault.counter-baseline.v1") || 0x00
authenticator_counter_baseline_hash = SHA256(BASELINE_DOMAIN || L(B))
```

Tous les membres sont obligatoires et les champs inconnus refusés.1..18 entrées, ordre strict `(person_id,role,credential_id)` ASCII ; unicité `(person_id,role)`, un credential activé explicitement choisi par W pour chaque rôle demandé. Requester1, reviewers1..16, sponsor0..1 ; si une personne sponsor est aussi reviewer, deux entrées partagent son activation mais pas son rôle. Chaque rôle présent dans le draft doit être représenté ; les alias ne créent aucune personne ou voix supplémentaire.

Credential décodé1..1024 octets, donc texte<=1366 ; RP1..253 ASCII, origine HTTPS exacte commissionnée1..512 ASCII ; aucune conversion Unicode/IDNA induite par la requête. W1 utilise RP `confirm.pamolive.invalid` et origine `https://confirm.pamolive.invalid`. sign_count0..4294967295 ; versions1..2^63-1. Toutes les autres chaînes<=4096, profondeur<=8, nœuds<=2048 (clés et valeurs comptent), B1..65536 octets. Ce nouveau profil permet les18 lignes complètes ; **ne pas appeler le walker ADR022 limité à512 nœuds en supposant qu'il les accepte**. Aucun changement au walker du transcript/draft existant n'est proposé.

B vient exclusivement du SQL W activé et des matériaux/slot vérifiés, sous locks. Aucun membre n'est pris comme autorité dans un champ JSON V, aucune baseline client, aucun epoch dérivé d'UUID. W garde B exact et son hash ; le FullTranscript existant engage ce hash via son champ `authenticator_counter_baseline_hash`. Le snapshot n'inclut ni body_hash ni nonce/transcript ni assertion ; donc aucune dépendance cyclique.

### Hash effectif de politique dans B

`policy_hash=SHA256(p0_canonical(head.body.policy))` reste le hash P0 existant. `effective_policy_sha256` utilise le domaine nouveau `pamolive.vault.effective-policy.v1\0` suivi de L(E), où E est le JSON canonique ASCII fermé :

```text
{
  schema: "pamolive.vault.effective-policy/1",
  registry_hash: SHA256HEX,
  target_id: UUID,
  destination_scope_hash: SHA256HEX,
  standard_min: INT63_POSITIVE,
  critical_min: INT63_POSITIVE,
  criticality: "standard" | "critical",
  target_min_reviewers: INT63_POSITIVE,
  commissioned_min_reviewers: INT63_POSITIVE,
  required_reviewers: INT63_POSITIVE,
  sponsor_person_id: UUID | "",
  contract_id: ""
}
```

E<=4096 octets, profondeur<=8/nœuds<=512/chaînes<=4096. Tous les champs sont reconstruits selon ADDENDUM ; required_reviewers est le max des trois seuils applicables, pas une valeur à croire. Le profil W1 refuse tout contrat non vide. `policy_binding_id=draft.policy_revision` vient de la liaison indépendante du slot et ne prétend pas être un UUID de révision situé dans la policy P0. `witness_slot_sha256` engage l'artefact de configuration exact (sans secrets/DSN) qui fixe cette liaison, la live credential synthétique et l'intention.

Le scope hash reste SHA256 des octets canoniques P0 des douze champs historiques exacts ; ne pas ajouter un schema à l'ancien scope. Les champs signed `critical`, flags et objets P0 gardent leurs types d'origine ; E les exprime explicitement par criticality/IDs, sans changer leurs octets signés.

## 3. Bundle final — `final_assertions_digest`

### Objet externe exact

```text
F = canonical_ascii_json({
  schema: "pamolive.vault.final-proof-bundle/1",
  operation_id: UUID,
  body_hash: SHA256HEX,
  assertions: [
    {
      person_id: UUID,
      role: "requester" | "reviewer" | "sponsor",
      decision: "launch" | "approve" | "refuse" | "sponsor",
      credential_id: CANONICAL_BASE64URL,
      assertion_b64: BASE64URL_OF_EXACT_INNER_JSON
    }, ...
  ]
})
final_assertions_digest = SHA256(ASSERTIONS_DOMAIN || F)
ASSERTIONS_DOMAIN = ASCII("pamolive.vault.final-assertions.v1") || 0x00
```

Le domaine et la formule du digest final sont **exactement ceux déjà définis** par ADR022/canonical.final_assertions_digest ; pas de préfixe de longueur ajouté ici. F est un seul objet borné, sa structure exclut une ambiguïté de concaténation. W doit parser et valider F avant de considérer ce digest comme le bundle accepté. Le digest reste hors du FullTranscript et ne signe rien par lui-même.

Tous les membres sont obligatoires, inconnus refusés ;1..18 assertions ; F<=2097152 octets, profondeur<=8/nœuds<=2048, chaînes<=90000 (assertion_b64<=87382), les autres chaînes<=4096. Le wrapper doit donc utiliser le nouveau profil borné de bundle, **pas** canonical_v2 avec chaîne4096 en supposant accepter une assertion64KiB. Lecture structurale bornée et comptage d'octets pendant l'encodage, sans construire d'abord un JSON sans limite.

Ordre strict des membres `(person_id,role,credential_id)` ASCII ; unicité `(person_id,role)` ; un seul choix de décision par rôle. Les décisions admissibles par rôle sont celles de `confirmation_challenge` ADR022 : requester.launch ; reviewer.approve/refuse ; sponsor.sponsor/refuse. Chaque credential doit être celui du snapshot pour ce rôle/personne ; pas de public_key/kid/URL/issuer ajouté. Le body_hash est recomputé des octets FullTranscript immuables W et comparé, jamais choisi librement par le bundle.

Pour le traitement compteur, les membres d'un même credential sont évalués dans l'ordre de sign_count numérique croissant, tie-break par leur ordre canonique externe pour zéro ; les valeurs non nulles doivent être distinctes et chaque signature doit réussir au compteur courant. Ce tri sert l'évaluation **après** vérification de l'ordre canonique du F reçu ; il ne recanonise pas une entrée invalide. Toutes les assertions incluses doivent réussir avant le commit atomique positif/négatif.

### JSON WebAuthn interne exact

Chaque assertion_b64 décode1..65536 octets d'un objet JSON UTF-8 ASCII canonique avec champs exacts :

```text
{
  id: CANONICAL_BASE64URL,
  rawId: SAME_CANONICAL_BASE64URL,
  type: "public-key",
  response: {
    clientDataJSON: CANONICAL_BASE64URL,
    authenticatorData: CANONICAL_BASE64URL,
    signature: CANONICAL_BASE64URL,
    userHandle: null | CANONICAL_BASE64URL
  }
}
```

Le null userHandle est **seulement** celui de ce profil interne WebAuthn. L'objet externe F n'admet pas null. Le client de confirmation sélectionne ces champs dans la réponse navigateur ; champs d'extension/attachement ne deviennent pas des autorités. Le profil W1 ne demande aucune extension et refuse des extensions signées ED dans authenticatorData ; un support futur exige une revue explicite. Les bytes signées `clientDataJSON` et `authenticatorData`, la signature et le userHandle ne sont jamais réécrits après réception.

id==rawId==credential_id externe, decoded1..1024 ; clientDataJSON décodé1..8192 ; authenticatorData décodé exactement37 octets dans ce profil sans extensions ni attestation (flags AT/ED absents), signature décodée1..8192 (la bibliothèque valide ensuite les tailles/algorithmes), userHandle null ou exactement32 octets égaux au handle P0 dérivé organisation/personne déjà commissionné. Le calcul de handle réutilise exactement `trust_auth._user_handle` : SHA256 de UTF-8 `pamolive.pam.person.v1/{organization_uuid}/{person_uuid}`. Ne pas inventer une inclusion d'installation dans cette formule historique.

Le JSON interne canonique garde les chaînes base64url exactes ; profondeur<=4/nœuds<=64/chaînes<=12000 et taille totale<=65536. `clientDataJSON` décodé est lui-même analysé sans doublons et avec bornes8192/depth4/nodes64/chaînes4096 ; champs obligatoires `type,challenge,origin`, seul optionnel `crossOrigin:false`, tout topOrigin et autre champ refusé dans le profil W1. Type exact `webauthn.get`, origin exacte activée, challenge canonique32 octets égal au `confirmation_challenge(FullTranscript,person_id,role,decision)` existant. Le booléen false y est une exception WebAuthn locale, pas une extension des JSON V2 métier.

Les origin/RP/UV/UP/signature sont vérifiés par la bibliothèque maintenue sur les bytes signées, en plus des gardes de forme W. Une erreur de la bibliothèque, y compris compteur pré-signature, reste une erreur générique sans modification d'activation. Un client peut réencapsuler des réponses WebAuthn dans F canonique, mais jamais ajouter un rôle/décision au corps déjà signé : le challenge engage les quatre paramètres exacts.

## 4. Golden indépendants et cas adverses pré-code

`GOLDEN-CODEC.json` fige : domaines hex, payloads exacts en texte/hex, framing U32, hashes, policy E, baseline B, bundle F avec deux rôles dont un refus et un compteur0. Les assertions du golden sont **des placeholders de codec non vérifiables**, donc aucune fixture ne peut être acceptée comme autorité sans le corpus signé/activation reçu séparément. Ce n'est pas une réponse du futur W.

Le golden matériaux utilise des octets publics JSON miniatures non conformes à une chaîne PAM complète ; il teste exclusivement cadrage et absence d'ambiguïté. Les tests d'intégration devront réutiliser les corpus signés statiques V1 préexistants puis les fixtures W1 complètes sans transformer ces placeholders en permission. Les valeurs attendues ne devront pas être régénérées par l'assembleur produit en test.

Les variantes figées changent ordre, longueur, doc/cp, state_version, sign_count, personne/rôle/décision, ou retirent un membre du bundle. Attendu : digest différent lorsqu'on modifie des octets, ou rejet structurel/autorité avant usage selon la variante. `["a","bc"]` et `["ab","c"]` produisent des frames distincts sans prétendre être des documents P0 valides ; cela établit l'absence d'ambiguïté de framing, pas une propriété de collision SHA-256. Mutations des domaines/prefixes/suffixes et budgets seront testées avant code transactionnel.
