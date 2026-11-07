# Contribuer à PAM-olive

Installer Python 3.12+, créer un environnement virtuel et installer `requirements-dev.lock`. Une contribution doit préciser le comportement attendu, ses effets sur les organisations et ses éventuelles migrations.

Avant de proposer une modification : `ruff check .`, `python manage.py makemigrations --check --dry-run`, puis `python manage.py test`. Utiliser PostgreSQL pour les changements de contraintes, de concurrence ou d’audit ; SQLite ne valide pas ces garanties.

Les modules appartiennent à leurs domaines. Une interface Web ne peut pas installer de code Python. Toute relation entre objets organisationnels doit être bornée à l’organisation authentifiée et couverte par un test négatif. Une explication conserve ses sources, ses incertitudes et la version de ses règles.

Ne jamais publier de secrets, de données réelles clients ou d’identifiants de test réutilisés en production. Les contributions à ce dépôt sont soumises à sa licence AGPL-3.0-or-later. Les fonctions cibles ne doivent être annoncées comme disponibles qu’après vérification de leur implémentation.
