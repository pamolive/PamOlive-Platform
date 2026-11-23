# ADR-039 — Qualification de libX11 et libXrender sur Trixie

Le scan de l'image Debian signale libX11 et libXrender pour CVE-2026-88806
et CVE-2026-88807. Debian classe Trixie affectée et fournit les versions
corrigées `2:1.8.14-1` et `1:0.9.13-1` dans Forky.
[Scan de l'image](https://github.com/pamolive/PamOlive-Platform/actions/runs/45112004806) ·
[Suivi libX11](https://security-tracker.debian.org/tracker/CVE-2026-88806) ·
[Suivi libXrender](https://security-tracker.debian.org/tracker/CVE-2026-88807)

Le moteur FreeRDP est compilé avec X11 désactivé. Cairo, utilisé par
FreeRDP, Guacamole et PangoCairo, entraîne encore les bibliothèques X11
dans l'image. Une reconstruction de Cairo sans ses moteurs X peut réduire
cette surface, mais elle change des symboles exportés et doit qualifier tous
les consommateurs de Cairo. Les bibliothèques Debian X11 corrigées offrent
une voie de remédiation qui conserve la configuration de Cairo et Pango.

Le laboratoire les reconstruit sur Trixie amd64 depuis l'index source
Forky authentifié et les six SHA-256 épinglés. Il ajoute une entrée de
changelog et rétablit les cinq entrées de la table de symboles Debian
Trixie pour les objets xtrans globaux. Forky utilise une version de xtrans
qui garde ces objets internes. Le niveau strict de vérification des
symboles Debian est conservé. Le laboratoire compile hors réseau sous
UID non privilégié. Il compare
l'identité des paquets, les SONAME, les exports dynamiques, les fichiers
chargés par Cairo et le rendu PNG d'un texte synthétique. Le résultat
conserve les deux buildinfo, les paquets et les empreintes.

La qualification couvre une surface image Cairo/Pango sans serveur X.
Avant intégration et publication, la branche produit doit vérifier les
fichiers réellement chargés, les parcours SSH et RDP et le scan strict
de l'image exacte.
