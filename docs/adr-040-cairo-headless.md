# ADR-040 — Cairo sans dépendances X11 dans le moteur

FreeRDP désactive X11 et Wayland dans le profil PamOlive. Le Cairo Debian
utilisé par FreeRDP, Guacamole et PangoCairo lie encore libX11, libXext,
libXrender et XCB. L'analyse statique du témoin GDI historique a relevé
ces dépendances et aucun import des fonctions Cairo Xlib et XCB chez
les consommateurs directs du moteur.
[Dépendances Cairo dans Debian](https://packages.debian.org/trixie/libcairo2) ·
[Configuration FreeRDP](../deploy/build-freerdp.sh)

La reconstruction des bibliothèques X11 corrigées sur Trixie préserve
l'ABI X complète et le rendu de référence. Elle laisse les dépendances X
présentes. Pour le moteur sans écran, une variante Cairo avec Xlib et XCB
désactivés retire ces chemins de l'exécution. L'ABI de Cairo se réduit aux
fonctions des backends conservés. Cette variante doit donc vérifier le graphe
du produit exact avant d'être intégrée.
[Qualification des bibliothèques X11](https://github.com/pamolive/PamOlive-Platform/actions/runs/45122370541) ·
[Options officielles Cairo](https://sources.debian.org/src/cairo/1.18.4-1/meson.options)

Le laboratoire reconstruit Cairo à partir de la source Trixie authentifiée.
Il fixe trois SHA-256 et désactive les options `xlib`, `xcb` et `xlib-xcb`.
Le contrôle strict Debian est maintenu pour tous les exports conservés.
Le catalogue retire exactement les 26 exports Xlib et XCB ainsi que les
sept dépendances X et SM explicites du SDK. Les stages vérifient séparément
les dépendances du SDK et de l'image d'exécution.

Le témoin et le candidat chargent le même PangoCairo et dessinent le même
texte dans une surface mémoire. Le laboratoire exige le même PNG, l'absence
des bibliothèques X dans le candidat et la conservation des autres exports
Cairo. Le SDK compile et exécute aussi l'autopkgtest Debian hors réseau,
avec `pkg-config` pour les backends PNG, FreeType et Fontconfig.

L'intégration produit doit vérifier la fermeture des dépendances du
moteur complet, la compatibilité avec les plugins livrés et les parcours
SSH et RDP/NLA. Le scan Grype demeure obligatoire sur l'archive exacte.
Les extensions qui exigent Cairo Xlib ou XCB relèvent du profil avec les
bibliothèques X corrigées.

Le laboratoire Trixie amd64 a conservé 394 exports. Le PNG est identique
au témoin et le SDK compile et exécute le test Debian. Les quatre paquets
retenus et le fichier mappé ont des empreintes vérifiées.
[Qualification des paquets](https://github.com/pamolive/PamOlive-Platform/actions/runs/45123667282)

Le candidat produit partage la recette et exige ces quatre empreintes
avant installation. Le builder FreeRDP installe les quatre paquets du
SDK. Guacamole conserve le même Cairo pendant l'installation du SDK Pango.
Le runtime part d'un stage propre et installe le paquet Cairo d'exécution
dans la même transaction APT que PangoCairo. La CI contrôle les paquets
et fichiers X, les dépendances ELF et les imports directs des interfaces
Cairo désactivées à partir du même export de conteneur que la preuve ACL.
Les essais SSH et RDP/NLA et le scan de publication sont exécutés sur le
candidat complet.
