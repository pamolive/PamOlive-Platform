# Qualification HA — perte temporaire de PostgreSQL et diagnostic primaire

11 novembre 2026. La CI `92df29c` a franchi les contrôles P1, les dix-neuf cas dédiés de confiance HA, la campagne PostgreSQL complète et les transports natifs. Elle a ensuite échoué à la suppression de la route de partition : cette erreur de `finally` ne permettait pas d'identifier le premier échec de la sonde. Il ne faut donc pas présenter l'origine précise de cette panne CI comme prouvée.

## Défaut du worker reproduit avant correction

Le chemin `runjobs.Command.handle` laissait sortir une `OperationalError` depuis la maintenance initiale (`cleanup_expired` et lectures d'organisation) ainsi que depuis `future.result()`. Une panne PostgreSQL pouvait donc terminer le worker. Le superviseur existant arrête tous ses enfants lorsqu'un enfant sort ; le Web et le moteur étaient alors arrêtés aussi. Ce lien est confirmé par le code et les tests adverses locaux, mais ne suffit pas, à lui seul, à prouver la cause du namespace disparu dans la CI antérieure.

Les nouveaux tests ont d'abord échoué sur ces deux frontières avant la modification du worker. Le premier passage rapportait deux erreurs `OperationalError` non interceptées et une assertion de délai non satisfaite. Les tests n'utilisent aucun réseau : ils injectent une panne du pilote à la frontière réelle du worker et bornent sa boucle sans lancer de thread applicatif ou attente réelle.

## Correction applicative ciblée

Seul le daemon intercepte `OperationalError` et `InterfaceError`. Il ferme les connexions du thread principal, émet un avertissement fixe sans SQL, DSN, arguments d'exception ni traceback, puis attend cinq secondes avant de refaire la maintenance et de relire les organisations. Aucun travail de cette boucle n'est repris à partir d'un état d'organisation supposé valide en cache.

Une future **terminée** est retirée du dictionnaire avant de lire son résultat, pour ne pas conserver indéfiniment la même exception terminée. Toutes les autres futures restent enregistrées, notamment celles encore actives : elles ne sont ni oubliées, ni annulées, ni soumises une seconde fois. Les files, claims, révisions et preuves durables ne sont pas réinitialisés. Les processeurs existants gardent leurs contrôles de permission, idempotence et destination.

`--once` continue de signaler une panne en erreur sans retry silencieux. `ValueError`, `ProgrammingError`, `IntegrityError` et les autres erreurs non classées comme connexion opérationnelle restent fatales. Ce mécanisme n'est pas une tolérance de l'autorité PAM hors ligne : **aucune modification du broker, du reaper, des contrôles de session, de leur durée ou des preuves P0**. Le broker doit toujours fermer le transport lorsqu'il ne peut vérifier l'autorité courante.

## Diagnostic de partition sans masquer l'erreur initiale

Le pilote retire toujours uniquement la route qu'il vient d'installer dans le namespace synthétique déjà prouvé. Si la sonde a échoué et que le retrait échoue aussi, l'exception et l'étape initiales restent le résultat principal ; le nettoyage est enregistré comme échec secondaire. Aucun autre namespace ni route de l'hôte n'est essayé. Si le retrait est le seul échec, il reste fatal et la récupération n'est pas annoncée réussie.

La sortie publique expose uniquement des catégories fixes telles que `container-not-running`, `namespace-unavailable`, `permission-denied` ou `unknown`, jamais le `stderr`, les noms privés ou arguments. Le détail brut éventuellement conservé par le collecteur d'échec antérieur reste dans ses fichiers privés hors dépôt ; il n'est pas un artefact à publier. Les diagnostics secondaires persistés ne contiennent que l'étape fixe, le type d'erreur et cette catégorie.

## Validation et limites

`tests.test_jobs_database_recovery` vérifie la reprise après panne globale, les deux classes de panne du pilote, la conservation d'une autre future active, la suppression de la future terminée en échec, la relecture des organisations, le délai borné, l'absence de données sensibles dans l'avertissement, et le maintien d'erreurs pour `--once` et les défauts logiques/intégrité. Les tests du pilote vérifient la conservation de l'erreur primaire quand le nettoyage échoue et l'absence d'écho du `stderr`.

Premier passage après correction : **21 tests réussis en 0,250 seconde** pour les quatre nouveaux tests worker et les dix-sept gardes du pilote. La requalification élargie PostgreSQL a ensuite réussi : **63 tests en 82,125 secondes, aucun ignoré**, sur `test_pamolive_ha_jobs` jetable, détruite en fin de campagne. Elle comprend worker, gardes HA, commissionnement synthétique, erreurs du broker PAM, recertification et signaux périodiques. La revue indépendante et surtout l'essai Docker réel de partition sont consignés par la coordination. Docker Engine n'étant pas disponible localement, aucun succès de partition native après ce changement n'est revendiqué avant son exécution CI.

Ces changements ne créent aucune migration et ne modifient aucune donnée de production. Aucun NAS ni système réel n'est contacté pour cette validation.
