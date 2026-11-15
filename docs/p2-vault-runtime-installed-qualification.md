# Qualification du runtime Vault installé — réception et correction

Le runtime de réservation reste limité à `pending_proofs`, sans remise. La
nouvelle [campagne CI](../.github/workflows/vault-runtime-installed.yml) et son
[runner](../qualification/vault_runtime_installed_ci/README.md) sont implémentés
localement. La campagne Linux du `1e81df6` a réellement construit et installé les
trois wheels, mais son enfant a rendu une erreur sur 52 tests. Elle reste en
échec. Les 30 tests du vérificateur public installé ne la remplacent pas.

Le packaging des contrats ajoute `license-files=["LICENSE"]` et la notice de
658 octets identique à celle du dépôt. Retirer cette seule ligne restitue
l'ancien pyproject exact ; les trois modules d'API restent inchangés, ainsi que
les huit modules runtime, son SQL, les six modules du vérificateur et P0.

Les 36 fichiers de build/tests sont capturés depuis les composants réels puis
comparés aux empreintes attendues. Aucun code d'implémentation parallèle n'est
committé dans la qualification ; les copies générées sont ignorées par Git.
Les neuf helpers hérités sont conservés byte pour byte. Les fichiers CRLF dont
les octets sont épinglés gardent explicitement cette identité Git.

Le harnais intégré passe désormais 65 tests sans exclusion ni tentative externe :
55 cas historiques et dix cas de diagnostics bornés. Sept tests adverses couvrent
la capture ; six refusent des hooks de démarrage inertes ; huit composent le
parseur réel de profil noyau et six vérifient le vrai helper public sous garde.
Ces résultats sont des essais de contrôleur et de fichiers synthétiques,
**pas une réception réussie des 52 tests du runtime installé**.

La contre-revue a reproduit un manque dans le prototype : `-I` n'empêche pas
`sitecustomize` dans le site-packages du venv avant la garde enfant. Le garde
parent refusait PTH/PYC, mais pas ce module. La copie intégrée refuse maintenant
les familles top-level `sitecustomize`/`usercustomize` (sources, extensions,
paquets et noms de liens), avant chaque invocation Python runtime. Les anciennes
preuves sont préservées ; aucun hook n'a été exécuté par les contretests. La
contre-revue du garde intégré a été reçue avant lancement réel.

## Campagnes reçues et défaut de fixture

Le [premier essai `01406f9`](https://github.com/pamolive/PamOlive-Platform/actions/runs/43744398214)
refuse avant tout build : le parent donnait `/proc/self/mountinfo` au parseur
hérité qui attend les six colonnes de `/proc/mounts`. Une correction ciblée du
chemin conserve le parseur et ses contrôles. Huit tests de composition et une
contre-revue indépendante vérifient ce correctif.

Le [second essai `1e81df6`](https://github.com/pamolive/PamOlive-Platform/actions/runs/43747230903)
passe les 16 processus, les trois builds et installations hors réseau, les trois
gates de wheel/RECORD et les deux contrôles pip. Les paquets chargés proviennent
des venvs installés ; zéro PTH et aucune tentative du garde ne sont constatés.
Le résultat exact de l'enfant est **52 exécutés, zéro failure, une error, zéro
skip**. Les processus sont récoltés/drainés ; le conteneur rend 42 sans OOM et
les ressources sont libérées. Ce nettoyage ne transforme pas l'échec en succès.

Le rapport ancien n'exportait pas l'identité du test en erreur. L'examen du code
retrouve un test original chargeant `integration/serve_lab.py`, absent des six
fixtures de son stage. Ce défaut est reproduit comme frontière de fichiers ;
il n'est pas présenté comme une traceback reçue de la CI. La correction ajoute
explicitement cette septième fixture, portant la capture à 29 entrées de build
et sept fixtures. Les 52 méthodes applicatives restent inchangées.

Le helper public ne modifie plus `sys.path` lors d'un import et n'importe psycopg
que dans la closure de connexion ; son démarrage `__main__` garde le bootstrap
du chemin source. La contre-revue a aussi reproduit un prérequis CI manquant :
les six tests du helper échouaient sans les dépendances tierces du venv Core.
Le lecteur RO est désormais importé dans `local_bytes` et les bibliothèques
serveur dans `main` après parsing des flags. Les vrais validateurs bornés
restent réutilisés ; le banc exige `-I -B -S`, sans site-packages ni stubs.
Aucun driver n'est installé ou simulé pour les tests installés.
L'enfant `/3` exporte au plus huit couples identifiant de test original/type
d'exception fermé, sans message, chemin ni traceback. Le consommateur refuse
l'ancien enfant `/2` ; les erreurs empêchent toujours la qualification. La
nouvelle exécution Linux reste à recevoir avant de solder ce défaut.

La campagne utilise un runner GitHub Linux éphémère, son daemon exclusif,
16 wheels publiques verrouillées et un seul conteneur network-none/user1000,
une CPU/512MiB, root RO, sans capacités. Les deux venvs et les builds sont
hors réseau. Les trois wheels puis leurs RECORD installés doivent correspondre
aux vraies sources, notices et SQL. Le succès exige les 16 phases bornées,
les 52 tests installés, les contrôles avant/après, le reap/drain et exit0/OOMfalse.
Un cleanup confirmé n'est pas à lui seul une qualification ; UNKNOWN ne guérit
pas au retry. Aucun volume, réseau ou service existant n'est manipulé.

Les essais SQL/mTLS/restauration, l'image minimale, la provenance de construction,
les deux hôtes indépendants et le KMS restent des portes séparées. Cette campagne
n'arbitre pas les 35 groupes High applicatifs et n'autorise pas main/image/NAS.
