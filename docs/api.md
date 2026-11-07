# API d’observation V1

Créer une source depuis **Connecteurs**. Le jeton n’est affiché qu’une fois ; seule son empreinte SHA-256 est conservée. Il autorise l’ingestion dans une seule organisation.

`POST /api/v1/events/`, `Content-Type: application/json`, `Authorization: Bearer <jeton>` :

```json
{
  "external_id": "event-2026-001",
  "occurred_at": "2026-11-07T14:32:00Z",
  "identity": "UUID de l’identité dans cette organisation",
  "account": "UUID du compte dans cette organisation",
  "resource": "UUID de la ressource dans cette organisation",
  "method": "SSH",
  "action": "session.start",
  "location": "192.0.2.10",
  "privilege": "Administrator",
  "result": "success",
  "evidence": "Référence publique vers la preuve source"
}
```

`identity`, `account`, `credential`, `location`, `privilege` et `evidence` sont facultatifs. `contract` peut contenir l’UUID d’un contrat de la même organisation et `country_code` le pays observé à deux lettres fourni par la source. Une identité absente reste inconnue. Aucun mot de passe, clé privée, jeton ou secret ne doit être envoyé dans les preuves.

Le pays déclaré dans une intention n’est jamais recopié comme pays observé. Si un contrat exige un pays et que la source ne le fournit pas, l’évaluation garde cette incertitude. Le contrat applicable est sa révision publiée à `occurred_at`, pas nécessairement sa révision actuelle. Une intention approuvée après `occurred_at` ne justifie pas rétroactivement cet événement. L’heure de la source doit donc être fiable et synchronisée.

La source est imposée par le jeton ; aucun `organization_id` ni `source` n’est accepté du client. Une nouvelle observation renvoie HTTP 201 ; son rejeu avec le même identifiant source renvoie HTTP 200 et le même UUID. Le fait initial n’est pas modifié.

Le détail de l’événement et son export `/api/v1/events/<uuid>/export/` nécessitent une session interactive autorisée dans l’organisation. Les sources d’ingestion ne peuvent pas lire les données ou approuver des accès.
