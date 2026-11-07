# PostgreSQL et déploiement

La base peut résider sur une autre VM. PAM-olive ne doit disposer que d’un accès réseau restreint au port PostgreSQL, idéalement sur un réseau privé et chiffré.

1. Créez une base et un rôle dédiés sans privilèges superutilisateur.
2. Activez TLS côté PostgreSQL et utilisez `sslmode=require` (ou `verify-full` avec un CA installé).
3. Renseignez `DATABASE_URL` dans le secret d’environnement de l’application.
4. En production derrière un proxy TLS, définissez aussi `DEBUG=false` et `SECURE_SSL_REDIRECT=true`.
5. Exécutez `python manage.py migrate` une seule fois par livraison.
6. Sauvegardez PostgreSQL et testez la restauration avant la production.

Exemple de rôle, exécuté par l’administrateur PostgreSQL :

```sql
CREATE ROLE pamolive LOGIN PASSWORD 'secret-long-et-unique';
CREATE DATABASE pamolive OWNER pamolive;
```

L’utilisateur de l’application n’a pas besoin d’être superutilisateur PostgreSQL.
