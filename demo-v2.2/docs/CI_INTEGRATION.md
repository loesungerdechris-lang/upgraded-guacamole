# SENTINEL als reguläre CI-Pipeline

Der Demonstrator und die CI verwenden `scripts/run_demo.py`. Es gibt keinen zweiten
Build- oder Evidence-Pfad. Der Runner erzeugt das Image, scannt dessen Digest,
signiert SBOM, Governance-Mock und Evidence Manifest, liest die Nachweise aus der
Registry zurück und prüft sie mit demselben Verifikator wie beim Offline-Aufruf.

## Auslöser und Gate

| Auslöser | Verhalten |
|---|---|
| Pull Request | Sechs isolierte Abnahmejobs gegen den von GitHub ausgecheckten Prüfstand. |
| Push auf `main` | Dieselbe Matrix auf dem integrierten Stand. |
| `merge_group` | Dieselbe Prüfung für eine vorhandene Merge Queue. |
| `workflow_dispatch` | Manueller Diagnoselauf. |
| `workflow_call` | Aufruf aus einer übergeordneten Pipeline. |

Diese Trigger sind in `.github/workflows/sentinel-demo.yml` konfiguriert. Es gibt keinen
Pfadfilter, der die Prüfung bei bestimmten Änderungen auslassen könnte. Der Job
`demo-gate` hat den Anzeigenamen **SENTINEL demo gate**, benötigt die komplette
Matrix `acceptance` und wird mit `if: always()` ausgewertet. Die Erfolgserwartung
ist wörtlich `success`; fehlende, fehlerhafte, abgebrochene und übersprungene
Ergebnisse öffnen das Gate nicht. Wird der gesamte Workflow abgebrochen, kann
auch die Berichtserstellung ausbleiben; daraus entsteht kein erfolgreicher Check.

Die Matrix bewertet jeden erwarteten Fehlerfall als Test. Ein absichtlich
beschädigtes Bundle muss abgewiesen werden, damit sein Testjob erfolgreich ist.
Das bleibt von der Annahme des vollständigen Bundles getrennt.

## Einbindung

Dieser PR integriert den Quellcode unter `demo-v2.2/`. Der Workflow liegt im
Repository unter `.github/workflows/sentinel-demo.yml`; seine Run-Schritte verwenden
`demo-v2.2` als Arbeitsverzeichnis. Checkout und Artefakt-Uploads beziehen sich auf
das Repository-Wurzelverzeichnis und verwenden entsprechend angepasste Pfade.

Eine vorhandene übergeordnete Pipeline kann diesen Workflow als Job aufrufen:

```yaml
jobs:
  sentinel:
    uses: ./.github/workflows/sentinel-demo.yml
    permissions:
      contents: read
```

Der bereits vorhandene Releasejob muss `sentinel` in seine `needs`-Abhängigkeiten
aufnehmen. Bestehende Abhängigkeiten bleiben erhalten. Ein `always()` oder
`continue-on-error`, das einen fehlgeschlagenen SENTINEL-Job im Releasepfad
übergeht, würde diese Sperre aufheben. Ein Releaseworkflow ist in diesem MVP noch
nicht implementiert; der Abschlussjob gibt keine Produktionsfreigabe.

Für eine verbindliche Merge-Sperre muss der entsprechende Check zusätzlich in
den Repository-Regeln als erforderlich hinterlegt werden. Diese Regeln wurden
hier nicht verändert. Bei Wiederverwendung ist der tatsächlich auf GitHub
angezeigte Checkname nach dem ersten Lauf maßgeblich. Standalone-Ausführung und
Aufruf aus einer Hauptpipeline sollten im Zielrepository bewusst gewählt werden,
damit nicht unnötig zwei identische vollständige Prüfläufe ausgelöst werden.

## Nachweise und Vertrauen

Jeder Matrixjob lädt die öffentlichen Dateien aus `release/` als
`sentinel-demo-<scenario>` hoch. Das Gesamtgate speichert seinen Bericht als
`sentinel-demo-gate`. Die Artefakte sind sieben Tage aufbewahrt; ein dauerhaftes
Auditarchiv ist damit noch nicht eingerichtet.

`scripts/ci_gate.py` bewertet den von GitHub gelieferten Jobstatus. Ein manueller
Aufruf mit `--acceptance-result success` ist kein Nachweis, dass eine Matrix
ausgeführt wurde. Der Gate-Bericht ist keine signierte Release-Receipt. Die
kryptografische Prüfung findet weiterhin im echten Pipeline-Runner statt.

Das Demo-Profil verwendet temporäre lokale Schlüssel und einen gekennzeichneten
Governance-Mock. Keine `cabApproved:true`-Behauptung, keine Produktions-Secrets und
keine unabhängige Release-Autorisierung. Das ist die technische erste CI-Stufe;
Trivy, SLSA-Provenance, HSM und Azure Key Vault bleiben außerhalb dieses Sprints.
Cosign verwendet bereits in-toto/DSSE-Umschläge; „ohne in-toto“ wird hier als
Verzicht auf eine zusätzliche Provenance-Stufe umgesetzt.

## Stand der Prüfung

Der Evidence-Kern hat den dokumentierten lokalen Registry-Lauf mit sechs
Abnahmefällen bestanden. Die CI-Ergänzung wird lokal auf Gate-Entscheidungen und
Workflow-Syntax geprüft. Ein gehosteter GitHub-Actions-Lauf, eine Branch-Protection-Änderung und ein Release sind keine Aussage dieses Dokuments.
Der Draft-PR und seine Checks dokumentieren den jeweils aktuellen gehosteten Stand.

Offizielle Referenzen:

- [GitHub: Workflow-Syntax, Trigger und Job-Abhängigkeiten](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax)
- [GitHub: Wiederverwendbare Workflows](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows)
