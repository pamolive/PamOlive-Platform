# ADR-017 — Entrée TLS du laboratoire Synology

Statut : retenu pour implémentation locale ; qualification complète et installation NAS soumises à leurs portes distinctes. 11 novembre 2026.

## Constat et menace

La première exécution du Compose Synology sur Docker Desktop Engine 29.6.1 a validé PostgreSQL, migrations, démonstrateur, Web/worker, privilèges, redémarrage et restauration sur copie. Elle a cependant montré un refus de connexion depuis l’hôte : le port figurait dans HostConfig mais aucun mapping effectif n’était présent dans NetworkSettings pour le Web attaché au seul réseau internal. Un healthcheck interne ne démontre donc pas l’accessibilité utilisateur. Ce constat ne prétend pas décrire toutes les versions Docker.

L’accès humain nécessite également HTTPS pour les cookies Secure et la MFA. Ajouter simplement un réseau sortant au portail rendrait son isolation moins forte. Une terminaison TLS qui ferait suivre des headers client arbitraires créerait une confusion de provenance réseau.

## Décision

Conserver l’image applicative et PostgreSQL. Ajouter une passerelle Nginx distincte, UID101, capacités nulles, filesystem readonly, fichiers temporaires et ressources bornés. Ses seuls secrets sont son certificat et sa clé TLS ; elle ne reçoit aucune clé applicative ni aucun mot de passe PostgreSQL.

Trois réseaux neufs : ingress pour la passerelle ; frontend internal pour passerelle/Web ; database internal pour Web/PostgreSQL. Aucun port Web ou PostgreSQL publié. Seul TLS loopback est proposé pour les essais locaux ; un accès LAN futur requiert son nom, son certificat, son binding privé et son autorisation explicites.

L’upstream est fixe sur Web, sans hôte fourni par le client. Valider Host avec son port ; écraser X-Forwarded-Proto et X-Forwarded-For, vider Forwarded. L’application n’accorde la confiance de proxy qu’à l’adresse exacte de la passerelle côté frontend, /32, relevée et vérifiée. Une recréation exige cette revalidation ; ne jamais faire confiance à l’ensemble du réseau. Désactiver les journaux d’accès contenant potentiellement des query strings sensibles.

## Alternatives

- Web directement publié sur internal : observation locale négative, insuffisant comme seul chemin d’entrée.
- Web sur un réseau sortant : réduit l’isolation ; rejeté.
- Gateway/Web/PostgreSQL sur le même réseau interne : autoriserait un chemin réseau direct gateway/base ; trois réseaux donnent une séparation plus nette sans service supplémentaire.
- Réseau hôte, privilèges ou socket Docker dans les services : rejetés.
- Override Compose avec `!reset` : évité pour conserver la compatibilité Compose 2.20.1 du NAS.

## Validation et exploitation

Préflight strict de la topologie, images par digest et ressources requises ; vrai démarrage avec Compose 2.20.1. Vérifier TLS/CA/nom, accès HTTP refusé, cookies/CSRF/MFA, headers écrasés, peer exact, UID/modes des clés, absence de secrets applicatifs et de port base, puis isolation, redémarrage, preuves et restauration sur copie. Ne pas annoncer une qualification tant qu’une de ces portes reste ouverte.

Aucune migration ou réécriture de données. Les anciens volumes synthétiques restent conservés. Aucun remplacement d’une installation existante n’est autorisé par cet ADR. Un quota disque/IO et la restaurabilité ne découlent pas des plafonds CPU/RAM : ils restent à vérifier et approuver séparément avant NAS.
