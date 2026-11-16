# ADR033 — MIT Kerberos1.22.3 candidat, packaging Debian en Trixie

Statut : accepté par Root pour une qualification Linux isolée ; aucune admission ABI/produit. ADR032 reste réservé au bootstrap navigateur et ADR034 à sa portée de certificat. Base source exacte PR19 `ddf1ccd18e73e952e22a37496ffd8d102d41723a`, arbre `b1769b122a2dd5a5d532eb3940ac4c0e67889cf6`.

Le produit actuel utilise `1.21.3-5+deb13u1+pamolive1`, avec le backport ASN1 existant. Le nouveau packaging candidat est **Debian1.22.1-3**, réutilisé avec **MIT1.22.3** et une version locale distincte `1.22.3-0+pamolive1`. Aucun binaire Sid ni dépôt binaire Sid n'est utilisé. Le packaging source reste identifié séparément de l'amont ; la disponibilité d'une correction amont ne clôt pas un finding Debian.

## Deux autorités avant toute extraction source

Le purpose Root demandé est `krb5-upstream-1.22.3-debian-packaging-1.22.1-3-v1`, avec primary/signing key `C4493CB739F4A89F9852CBC20CBA08575F8372DF`. Le TAR, sa signature et le bundle public sont pinnés séparément. La réception publique du bundle par HTTPS n'est pas une preuve OpenPGP ; les trois commandes GPG import/list/verify doivent réussir en Linux avec un homedir neuf, un environnement fermé, aucun réseau/keyserver et les contrôles de signature/capacité/expiration déjà qualifiés dans Expat. Le bundle ne prouve pas la complétude mondiale des révocations.

La seconde chaîne utilise le keyring Debian du builder Trixie : GPGV authentifie InRelease, puis son index Sources par SHA256, puis les tuples exacts du DSC et du debian.tar. Date/Valid-Until et la version/source/directory sont fermés. Sid n'est consulté que comme autorité **source**. La signature d'uploader DSC n'est pas déclarée vérifiée ; son octet exact est lié par l'index signé. Si le source1.22.1-3 n'est plus dans l'index frais, la collecte refuse : il faudra un snapshot signé et approuvé, sans fallback non signé.

Les inputs GPG sont copiés depuis les buffers capturés dans un work neuf. Le TAR amont et le TAR packaging sont capturés et hashés une seule fois ; ces mêmes buffers sont parsés après retour des deux chaînes. Le parseur refuse liens, chemins ambigus/traversants, doublons, parents-fichiers, PAX et budgets dépassés. Aucun `extractall` n'est utilisé. Cela n'est pas une protection contre une compromission root du builder de confiance.

## Packaging et politique TLS existante

Les16 patches originaux sont chacun classés par SHA/préimages/postimages dans `patch-plan.json`. Dix deltas Debian sont rebased sur des contextes complets uniques ; Gnu quilt applique ensuite les coordonnées générées avec `--fuzz=0`, sans message offset/fuzz, et les fichiers modifiés sont relus contre les buffers attendus. Quatre patches sont déjà intégrés, dont OpenSSL avec ses changements de contexte ultérieurs. `.gitignore` est exclu comme métadonnée de développement. La compatibilité keyring ajoute uniquement les deux refus ENOSYS/EPERM déjà admis pour les tests ; les autres sorties restent des erreurs et les skips ne sont pas des passes.

Le patch0015 Debian n'est **pas appliqué**. L'archive packaging actuelle02b873… ne contient aucun patch visant `k5tls/openssl.c`. Le source actuel b7a4… et MIT1.22.3 conservent les mêmes corps des helpers de hostname : seules cinq qualifications `const X509*` diffèrent. La preuve textuelle et les hashes exacts sont livrés séparément. Introduire X509_check_host sans contrôle modifierait la politique des wildcards partiels ; cela serait une extension nouvelle. Ce candidat conserve donc les corps existants, sans choisir un nouveau flag OpenSSL. Douze oracles C Linux doivent vérifier hostname exact/faux, wildcard complet/partiel/profond/TLD, priorité CN/SAN et adresses IP sur ces vrais helpers ; ils ne vérifient ni une chaîne de certificats ni une session AD. Aucun résultat natif n'est encore reçu.

## Qualification ABI puis décision v2

Le profilv1 et les six cas ASN1 restent octet pour octet inchangés. Les ancres de l'ancien produit reçu sont respectivement171/107/657/101 exports pour libgssapi/libk5crypto/libkrb5/libkrb5support, avec les quatre hashes de contrat ABI reçus. Le nouveau job mesure d'abord les listes complètes du baseline Trixie ; il refuse si leur hash ne correspond pas à ces contrats réels. Il ne remplace donc pas l'ancien produit par une hypothèse d'équivalence avec le stock.

Chaque ancien export doit conserver nom, binding/type, visibilité, version GNU, bit de version masquée et taille OBJECT/TLS. Les nouveaux exports sont des **candidats DATA**, jamais admis automatiquement. Le profilv2 est séparé et lie source, packaging, adaptation et chaque liste complète. Le fichier livré a `admitted:false` et aucune bibliothèque approuvée. Une modification du hash historique, un wildcard ou une normalisation de version ne remplace pas la revue Root des vrais résultats. Le champ patch historique du banc ASN1 signifie lignée du banc ; le backport ancien n'est pas réappliqué à1.22.3.

## Produit et SDK après réception

Les hunks produit sont rebased sur21ea4bc90bec7818ae06c9fa89550d1342a57e69 et conservent le nouvel install libc6-dev dans expat-sdk. Les hunks proposés remplacent seulement les stages Kerberos et leur export CI v2. Les textes Expat/Jansson, la chaîne scratch, les scopes P0, les tests SPN/CBT/certificats et les seuils des scanners sont préservés. Le produit refuse avant promotion tant que le profilv2 n'est pas admis. Les paquets runtime et SDK proviennent du même dpkg-buildpackage, puis les octets actifs sont comparés à ce build. Les consumers sont recompilés avec ce SDK via les chemins existants.

Le laboratoire prépare un consumer GSS réel lié aux nouveaux providers, énumère explicitement le mécanisme Kerberos puis sollicite une identité et un mot de passe **synthétiques** sur un KDC TCP silencieux limité à loopback. Un accept TCP, une réponse GSS en erreur, une fenêtre temporelle bornée et les H1 doivent tous être reçus ; une erreur rapide sans contact ne vaut pas preuve de deadline. Cela ne qualifie aucun KDC/AD réel, ni la santé d'une application, ni le P0. AUTH_GSSAPI historique n'est pas réactivé globalement.

Un SBOM CycloneDX v2 séparé lie le report aux octets actifs et à l'identité config de l'image qualifiée. Il ne déclare aucune compilation attestée, VEX, suppression ou clôture CVE. Le vrai validateur de schéma reste obligatoire en Linux ; aucun import/schema Windows bloqué n'est contourné. Les anciens chemins v1 restent vérifiables explicitement et ne peuvent admettre v2.

## Limites et critères de passage

Tout ce livrable est SOURCE/N0. GPG, compilation, dpkg, GNU quilt, les six ASN1, les douze TLS, le consumer GSS, les deadlines KDC, les dépendances Trixie et le schéma Linux sont non exécutés localement. Le job doit recevoir leurs vrais journaux, tous skips séparés, versions/installations SDK, ABI et erreurs. Un dpkg0 seul ne donne ni comptes internes ni absence de skips. Le workflow exporte uniquement une allowlist de JSON/journaux publics bornés, sans ELF/DEB/source/key-home ; les noms et chemins de build publics sont assumés dans les logs source. Une incompatibilité ABI ou une erreur du consumer conserve DATA/les journaux partiels, bloque l'installation ou les commandes suivantes et fait échouer le gate après l'export. En cas d'échec plus tôt avant l'export, seuls les journaux CI et les artefacts déjà produits sont disponibles ; aucun reçu natif absent n'est inventé.

Le contrôle H1 réutilisé concerne les processus enfants, pas une attestation du daemon Docker ou du nettoyage BuildKit. L'image produit complète, ses providers réels, ses vrais tests P0 et les scans stricts sur l'archive composée restent obligatoires après admission explicite. La réduction éventuelle de findings n'est pas prédite depuis la version amont. Aucun GO opérationnel, accès NAS, KDC/AD réel ni autorisation applicative n'est accordé.

## R2 — deux défauts de contrat corrigés avant commission

Le baseline JSON doit être cohérent avant tout ancrage : containers/types de tuples stricts, nombre exact de lignes et SHA256 recalculé sur canonical(sorted(symbols)). Copier les anciens compteurs/hashes à côté d'une liste réduite est refusé, même pour un futur profil synthétique admitted:true. Les quatre ancres historiques sont inchangées.

Le vrai helper H1 produit reason=nonzero_exit pour rc1 normal. La sonde keyring exige désormais exactement ce code, rc1, PID/reap/drains normaux, aucune terminaison/exception et les33 octets stderr attendus. None/timeout/signal/nonreap restent refusés. result.ok n'est jamais transformé en succès et unknown.json reste UNKNOWN. Le rejeu utilise le vrai run_capped avec Popen mémoire, puis le vrai keyring_probe avec proc/net synthétiques ; aucun processus ni appel keyctl réel n'a eu lieu.

## Commission Root du laboratoire de développement

Le branchement de qualification reprend le parent runtime0f2bf83, y compris le
diagnostic snapshot et le correctif SDK C. Aucun hunk produit ou CI Platform du
candidat n'est appliqué ; les14 pins produit et les35 sources Expat restent
exactes. Le profilv2 conserve admitted:false et libraries vide. L'autorité de
bootstrap MIT est limitée au purpose, à la clé et aux cinq matériaux pinnés
ci-dessus ; les deux chaînes cryptographiques doivent encore réussir en Linux.
L'acceptation de cet ADR n'admet aucune ABI, donnée, image ou CVE.

Les45 fichiers du contexte sont conservés octet pour octet avec des attributs
Git explicites, sauf le regroupement isort d'un import SBOM : mêmes imports,
tous autres noeuds AST exacts, et les45 empreintes sont revérifiées depuis Git.
Le SHA externe du workflow est recalculé après ce seul changement. Les espaces
de contexte des patches et le commentaire du bundle public restent intacts ;
les exceptions de whitespace sont limitées à ces matériaux pinnés.

L'archive publique amont de8758584octets est volontairement versionnée, avec
une exception gitignore limitée à son chemin exact, pour rejouer les modèles
N0 et capturer ces mêmes octets avant authentification/extraction Linux. Il
s'agit du source MIT inchangé, pas d'un dump, secret, ELF ou résultat généré.
Le copyright et les licences amont sont conservés dans cette distribution.
Sa présence dans Git ne constitue pas une signature vérifiée. Aucun TAR n'est
extrait vers le poste Windows, aucun payload natif n'y est exécuté.

## Chemin canonique du keyring Debian

Le premier job dcda refuse la lecture du keyring dans acquire avant GPGV :
le garde lstat/type/nlink/taille n'accepte pas le leaf .gpg. Le log ne donne
pas sa stat réelle et ne permet pas d'attribuer précisément ce refus.
Le Makefile officiel du paquet debian-archive-keyring2025.1 construit et
installe .pgp comme fichier ordinaire et .gpg comme lien symbolique.
Le chemin d'entrée est donc fixé directement à la feuille canonique .pgp.
Il n'y a ni resolve/fallback, ni alias générique accepté, ni garde relâché.
Les mêmes buffers capturés et les mêmes contrôles GPGV/MIT/H1 restent requis.
Quarante modèles purs passent, dont les37 anciens inchangés et trois refus
stricts/capture ; cela ne prouve pas encore la lecture ou signature en CI.

Références de disposition, sans signature du paquet revendiquée ici :
[Makefile2025.1](https://sources.debian.org/data/main/d/debian-archive-keyring/2025.1/Makefile)
et [liste Trixie](https://packages.debian.org/trixie/all/debian-archive-keyring/filelist).

## Diagnostic du refus du build natif

Le run59b termine l'acquisition puis atteint dpkg-buildpackage, après retour
des contrôles d'authentification, de source, de baseline et de patches. La trace
ne contient pas les reçus AUTH/ABI ni les faits H1 du processus échoué ; elle
ne prouve pas sa cause. Le temps de stage175.8s ne distingue pas cap, signal,
erreur normale ou UNKNOWN. Aucun plafond ni erreur de compilation n'est inféré.

Le seul caller dpkg émet désormais, en cas de refus, un JSON fermé de8Kio max :
flags H1, raison enum, nombres, tailles et empreintes des buffers capturés. Les
logs bruts, arguments, erreurs libres, environnement, clés et données KDC sont
exclus. La même exception est toujours relancée, même si le diagnostic échoue.
Succès : aucune lecture/sortie ajoutée. Commande, env, budget3000s, caps8MiB et
helpers communs restent exacts ; le nouveau reçu réel reste à collecter.

### Mesure native du refus normal et marqueurs bornés

Le [runae83891](https://github.com/pamolive/PamOlive-Platform/actions/runs/43890087890)
a reçu un vrai refus normal dpkg :rc2, enfant reapé, drains complets, pas de kill
ni exception, sorties1385754/78672octets concordantes. Ce ne sont donc ni un
dépassement de cap ni un délai. La cause de compilation/packaging reste inconnue.

Le diagnostic ajoute des marqueurs textuels fermés seulement pour NORMAL_RC2
et les mêmes buffers déjà capturés. Sept familles, seize codes, huit événements
max, compteurs et troncatures explicites ; un flot make ne masque pas les autres
familles. Aucun chemin, symbole, message brut ou erreur libre n'est publié.
Les marqueurs ne prouvent ni outil/version ni cause ; root_cause resteUNKNOWN.
Le JSON8Kio, les budgets et tous les contrôles source/GPG/ABI restent exacts.
Une nouvelle mesure Linux reste nécessaire avant toute correction de packaging.
