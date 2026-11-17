# C4 — checkpoints diagnostiques de l'oracle natif

Base exacte e718be91bc902efab8cc69eed47c313d8fee4431. Le vrai run C3
44123914157 a reçu SIGILL4 pour le premier enfant `syscalls`, sans stdout ni
stderr. Son dernier appel exact reste inconnu. Ce delta ne corrige ni ne
qualifie le filtre ; il permet une réception suivante plus précise.

Le loader source existant reste byte-exact. Après son contrôle, `child()` écrit
des jalons avant/après capture code, capture helper, API ctypes, préparation et
close_range, installation NNP/filtre, GET checks, socket-pairs, table historique
network+escape, holes/future/x32 et émission terminale. Le chemin exec ajoute
capture Python et le jalon avant execveat ; le mode inherited poursuit la même
numérotation. Les appels de refus et leur ordre restent inchangés.

Chaque nom est fermé : `syscalls-checkpoint-NN.json` ou
`exec-checkpoint-NN.json`, sous `/c-fence-native` privé root-owned. Chaque fichier
nouveau est O_EXCL/NOFOLLOW/NONBLOCK/CLOEXEC, 0400, régulier, UID/GID0, nlink1 ;
write/fsync et cohérence FD/nom sont vérifiés, puis le FD est fermé avant la
couture suivante. Aucun FD diagnostique n'est transmis à execveat. Le proofroot
et son identité sont vérifiés ; pas d'atomicité revendiquée face à root/same-UID.

Les champs sont uniquement schema, case, mode, ordinal, phase littérale, PID,
code-pins SHA, native-source SHA, diagnostic_only=true et operational_GO=false.
Pas d'argv, environnement, exception, stack ou code filtre. Plafond32 fichiers
par case et1024octets par fichier :32KiB/case au maximum. La séquence actuelle
contient20 jalons syscalls et29 jalons exec+inherited ; les deux cases bornent
donc ensemble la sortie à64KiB maximum (49 fichiers/49KiB plafond actuel).

Les jalons n'ont ni PASS ni COMPLETE. Leur présence ne prouve pas qu'une
opération suivante a démarré ou terminé, ni que l'opération précédente est la
cause de l'interruption. Aucun signal handler, retry ou catch n'a été ajouté.
Une collision, erreur d'écriture ou fsync refuse. Le terminal PASS existant et
ses prédicats, les deux H1 positifs, les délais45s/10+5s et le refus du parent
restent inchangés. Le cas exec crée uniquement les mêmes processus qu'avant.

Les appels filesystem diagnostiques s'ajoutent à l'oracle et peuvent eux-mêmes
refuser ou consommer une partie du budget existant. Il faut mesurer le vrai
Linux après revue/intégration ; aucun résultat pur ne qualifie ce comportement.
Le workflow existant exporte déjà les JSON de ce seul proofroot. Seuls le pin
native dans le manifeste11 et son littéral agrégé workflow changent.
