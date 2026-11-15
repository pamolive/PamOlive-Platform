# Qualification du runtime Vault installé — état local

Le runtime de réservation reste limité à `pending_proofs`, sans remise. La
nouvelle [campagne CI](../.github/workflows/vault-runtime-installed.yml) et son
[runner](../qualification/vault_runtime_installed_ci/README.md) sont implémentés
localement ; aucune exécution de build/installation Linux de ce sujet n'est
encore reçue. Les 30 tests du vérificateur public installé ne la remplacent pas.

Le packaging des contrats ajoute `license-files=["LICENSE"]` et la notice de
658 octets identique à celle du dépôt. Retirer cette seule ligne restitue
l'ancien pyproject exact ; les trois modules d'API restent inchangés, ainsi que
les huit modules runtime, son SQL, les six modules du vérificateur et P0.

Les 35 fichiers de build/tests sont capturés depuis les composants réels puis
comparés aux empreintes attendues. Aucun code d'implémentation parallèle n'est
committé dans la qualification ; les copies générées sont ignorées par Git.
Les neuf helpers hérités sont conservés byte pour byte. Les fichiers CRLF dont
les octets sont épinglés gardent explicitement cette identité Git.

Le harnais intégré passe 55 tests sans exclusion ni tentative externe, y compris
après correction du garde de démarrage. Sept tests adverses supplémentaires
couvrent la capture ; six refusent des hooks de démarrage inertes. Ruff et les
contrôles de pins/YAML/Git-filtrage passent. Ces résultats sont des essais de
contrôleur et de fichiers synthétiques, **pas les 52 tests du runtime installé**.

La contre-revue a reproduit un manque dans le prototype : `-I` n'empêche pas
`sitecustomize` dans le site-packages du venv avant la garde enfant. Le garde
parent refusait PTH/PYC, mais pas ce module. La copie intégrée refuse maintenant
les familles top-level `sitecustomize`/`usercustomize` (sources, extensions,
paquets et noms de liens), avant chaque invocation Python runtime. Les anciennes
preuves sont préservées ; aucun hook n'a été exécuté par les contretests. La
contre-revue du correctif intégré reste à recevoir avant lancement réel.

La campagne future utilise un runner GitHub Linux éphémère, son daemon exclusif,
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
