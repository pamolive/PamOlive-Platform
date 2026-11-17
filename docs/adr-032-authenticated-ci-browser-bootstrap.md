# ADR-032 — Navigateur authentifié dans le laboratoire CI

Statut : accepté pour qualification du banc synthétique ; aucune admission produit.

## Contexte

Le run43847329848 du896dd82 refuse avant TLS, SQL et navigateur. Le diagnostic
fermé est `tool_type_owner_mode` ; la feuille Chrome observée ensuite est un
fichier régulier0:0, mode0777, nlink1, sans alias. Cette observation ultérieure
ne rejoue pas atomiquement le contrôle et ne démontre pas la cause d'installation.
Le contrôle actuel doit continuer à refuser un exécutable modifiable par autrui.

## Choix

Réinstaller uniquement le paquet Google157.0.8103.78-1 exact dans la VM CI
jetable, puis appliquer le même contrôle au même chemin. Le fournisseur publie
la primaire EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796 sur sa
[page officielle](https://www.google.com/linuxrepositories/). Le manifeste
sélectionne cette primaire et le signer0E225917414670F4442C250DFD533C07C264648F
pour la signature de ce Release. Leur présence dans les paquets DATA n'est pas
une validation GPG ; celle-ci doit réellement réussir en Linux avant traitement
du paquet. Les trois prédicats GPG proviennent du laboratoire Expat revu.

Les petits fichiers publics clé/Release/signature/Packages sont conservés par
octets exacts. Le job vérifie le pin externe du manifeste, ses fichiers et le
contexte Git avant exécution. Release est authentifié hors réseau, puis lie le
SHA et la taille de Packages ; le stanza exact lie version, architecture, nom,
taille et SHA du DEB reçu par HTTPS. Il n'y a ni version current/latest, ni
récupération de clé pendant vérification, ni apprentissage depuis une observation
refusée. La signature porte sur Release, pas indépendamment sur chaque DEB.

Le Release sans Valid-Until ne peut dater de plus de sept jours ni dépasser
l'horloge UTC de plus de300secondes. Le rafraîchissement des matériaux exige une
nouvelle revue et des pins ; aucun téléchargement mutable n'est auto-admis.

Le frontend vérifie puis inspecte le paquet sans exécuter son contenu. Le
superviseur privilégié authentifie de nouveau, copie les octets dans un répertoire
privé root neuf et les revérifie avant les outils paquet. Control, dépendances
déjà satisfaites et payload Chrome régulier0:0/0755/ELF sont exigés avant
installation. APT utilise uniquement le DEB local avec absence de téléchargement,
suppression ou source distante. Aucun apt-fix, consentement de downgrade ou
chmod correcteur de l'ancien binaire0777 n'est ajouté. L'identité installée et
les octets/métadonnées doivent correspondre au payload authentifié avant l'UI.

## Alternatives et frontières

Le préfixe privé exigerait une nouvelle politique de chemins, ressources et
sandbox ; il n'authentifierait pas davantage le même paquet. Il reste une
alternative explicite, sans fallback automatique. Le chemin fournisseur permet
de conserver les cérémonies, le guard et la sandbox existants.

Les outils/root/runner et scripts mainteneur du fournisseur font partie du TCB
de la VM jetable. Ce bootstrap ne constitue pas une frontière contre un runner
ou root hostile. Les I/O de fichiers restent synchrones ; les budgets ne sont
pas une preuve d'interruption de chaque syscall ni de fermeture de tous les
descendants du système. Les reçus gardent les états UNKNOWN et ne déclarent pas
de libération globale. Les sorties brutes, DEB, clés privées de fixture et HOME
restent privés ; seuls les JSON de faits sont exportés.

## Validation et exploitation

Dix tests purs de bootstrap, les quatorze contrats UI conservés et cinq cas
indépendants passent sous audit, sans opération native. Ils couvrent notamment
source/pin, signatures et dates simulées, payload, dépendance additionnelle,
copie root liée aux octets vérifiés et absence d'admission après UNKNOWN.
Ils ne prouvent ni GPG, ni installation, ni sandbox ou parcours navigateur réels.

Le job passe à40minutes et le bootstrap reçoit15minutes : frontend870secondes,
superviseur root450secondes. Le budget du worker UI600secondes et sa réserve60
restent inchangés, ainsi que TLS, MFA/WebAuthn et les contrôles P0. La prochaine
CI doit recevoir signature, paquet, installation et parcours UI exacts. Aucun
contrôle du PC, accès NAS, compte réel ou changement de production n'est requis.
