# P1-C/D/E — revue indépendante cryptographie et PAM

11 novembre 2026. Revue complémentaire distincte du développement des lots et de la revue Red Team globale. Périmètre : ADR-013/014/015/016, projections Identity 360/Governance/Observe, preuves d'exception et restauration, mécanisme d'attestation réutilisé, contrôles d'autorité IGA corrigés et invariants de provenance V7/V8. Aucun code applicatif modifié par cette revue, aucun NAS ou système réel contacté.

## Conclusions vérifiées

- Les nouvelles projections restent des lectures non signées. Elles ne commissionnent aucune personne PAM, ne créent aucun vote du registre indépendant et ne chargent aucun secret de cible. Une fiche IAM, un propriétaire déclaré ou un mapping SCIM ne deviennent pas une attestation d'identité PAM.
- Le registre d'exceptions utilise les attestations du noyau avec HMAC SHA-256, espace versionné `pamolive.governance.exception/1` et finalités distinctes demande/décision. Organisation, véritable acteur, sujets, dates, fenêtre MFA et ancre d'audit sont liés. Aucun consommateur du registre n'a été trouvé dans les moteurs d'autorisation, PAM, SoD ou provisioning examinés : une acceptation reste un suivi de risque.
- Observe vérifie séparément l'évaluation V7 et le reçu de provenance V8. Une dernière évaluation invalide ou une provenance invalide ne devient pas une conformité courante. Les anciennes observations restent `legacy_unknown`. Un reçu établit l'acceptation par PamOlive, pas la vérité indépendante de la télémétrie ni l'indépendance du détenteur d'un jeton.
- Les références historiques de destination et confirmations enregistrées restent distinctes de l'état actuel d'un fournisseur. La comparaison explicite d'une observation et d'une intention ne devient pas une association causale ni une autorisation.
- La restauration vérifie les preuves d'exception, leurs sujets de la même organisation, ancres, cardinalités, ordre et bornes temporelles, sans réactiver une exception expirée ni une autorité PAM restaurée. Les gardes de retour arrière P0-4 et du registre d'exceptions restent distincts.
- Les changements de publication IGA rechargent l'acteur sous verrou et conservent les exigences MFA. Ils ne remplacent pas les cérémonies, ancres et checkpoints indépendants P0-3.

Aucun nouveau blocage cryptographique ou contournement PAM confirmé dans ce périmètre. Cette conclusion est limitée aux sources et tests examinés, sans qualification d'exploitation réelle.

## Clés et compatibilité

Les attestations d'exception réutilisent **`PAMOLIVE_ENCRYPTION_KEY`** via `platform_core.attestations`, comme les autres attestations métier existantes. Les signatures et reçus V7/V8 emploient **`SECRET_KEY`**, avec vérification des anciennes clés par `PAMOLIVE_EVIDENCE_VERIFICATION_KEYS`.

Ce trousseau V7/V8 n'est pas un mécanisme de rotation de la clé d'attestation/chiffrement. Conserver la valeur exacte de `PAMOLIVE_ENCRYPTION_KEY` avec les anciennes données et sauvegardes ; changer cette valeur sans migration contrôlée invalide les anciennes attestations et peut empêcher le déchiffrement. P1 n'effectue aucune rotation, ré-signature automatique ou réécriture historique. Ne pas revendiquer une preuve opposable au détenteur des clés applicatives ni à un propriétaire PostgreSQL compromis. Aucune nouvelle primitive ou garantie post-quantique n'est introduite par ce lot.

## Validation indépendante

Commande sur PostgreSQL loopback synthétique, base dédiée `test_pamolive_crypto_p1` :

```text
manage.py test tests.test_event_provenance_crypto tests.test_event_evidence_key_settings tests.test_governance_exception_restore tests.test_observe_story --noinput
```

**30 tests réussis en 5,602 secondes, aucun ignoré.** Base détruite en fin de campagne. Les tests couvrent canonicalisation, altération des faits, rotation du jeton sans changement de collecteur, vérification V7/V8 après rotation de clé serveur avec trousseau, restauration des preuves d'exception et sujets inter-organisations, trois verdicts, autre autorisation valable, preuves invalides et démonstrateur sans réseau.

Les tests n'exercent ni coffre/HSM isolé, ni détenteurs indépendants réels, ni authentificateur matériel, ni transport PAM natif, ni AD/LDAP/Entra/TeamViewer réel. La contention, la volumétrie, la garde opérationnelle des clés et la qualification des conteneurs Synology restent des portes séparées. Les résultats consolidés et la CI sont consignés par la coordination ; les 30 tests ne les remplacent pas.
