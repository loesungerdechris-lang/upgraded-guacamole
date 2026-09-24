# Validierungsbericht – SENTINEL Demo

**Historischer lokaler Referenzlauf vor dem Repository-Import.** Die genannten
`release/`-Dateien gehören zum zuvor erzeugten lokalen Paket und sind nicht in Git
committet. Dieser Bericht belegt keinen gehosteten GitHub-Lauf. Aktueller Reifegrad:
[MATURITY.md](MATURITY.md).

Stand: 2026-09-17. Profil: `sentinel-demo-mvp/v0.1`.

## Ergebnis

Die lokale Pipeline wurde tatsächlich mit einer nativen OCI-Registry ausgeführt.
Sie bestand alle sechs Abnahmefälle. Das vollständige Bundle erhielt `PASS`,
Exit 0; die fünf veränderten Bundles wurden mit den erwarteten Gründen abgewiesen.
Online-Prüfung, Offline-Prüfung und erneute Offline-Prüfung lieferten identische
Entscheidungsobjekte. Ein separater Aufruf der ausgelieferten CLI lieferte ebenfalls
`PASS`, Exit 0.

| Abnahmefall | Bundle-Befund | Exit | Grund |
|---|---|---:|---|
| happy-path | PASS | 0 | VERIFIED |
| missing-sbom | HOLD | 2 | MISSING_SBOM |
| missing-governance | HOLD | 2 | MISSING_GOVERNANCE |
| digest-mismatch | BLOCKED | 3 | DIGEST_MISMATCH |
| bad-signature | BLOCKED | 3 | INVALID_SIGNATURE |
| missing-manifest | HOLD | 2 | MISSING_MANIFEST |

`HOLD` und `BLOCKED` sperren beide die Bundle-Annahme. Die Testmatrix wird nur grün,
wenn diese Ablehnungen genau wie erwartet auftreten.

## Ausgeführte Prüfungen

- `python3 scripts/bootstrap.py --directory .tools`: Installation und Hashprüfung
  der vier Werkzeuge sowie 33 gepinnten Compiler-/Bibliotheksdateien erfolgreich.
  Die acht benötigten bzw. vom Paket vorgegebenen Compiler-Symlinks sind im Lockfile festgehalten.
- `COSIGN_BIN="$PWD/.tools/cosign" python3 -m unittest discover -s tests -v`:
  **10 Tests, 0 Fehler**, 31,744 Sekunden. Echte temporäre Cosign-Schlüssel und Signaturen.
- Rust: ein Verhaltenstest bestanden; statische Binärdatei kompiliert und ausgeführt;
  Ausgabe `Hello, SENTINEL.`.
- `python3 scripts/run_demo.py --tools .tools --output release`:
  **6/6 Abnahmefälle**, Exit 0, erneut nach der Schlüssel-Snapshot-Korrektur ausgeführt.
- Separat: `python3 sentinel verify-bundle --request release/verification-request.json
  --policy release/governance-policy.yml --key release/demo.pub --offline release/bundle
  --cosign .tools/cosign --output release/reverification.json`: **PASS**, Exit 0.
- Python-Kompilation und `git diff --check`: erfolgreich.
- GitHub-Workflow: YAML-Struktur, sechs Matrixwerte und Action-Commit-Pins geprüft.
  **Kein gehosteter Actions-Lauf ausgeführt**, kein Remote-Repository verändert.

Die anfänglichen Integrationsfehler wurden behoben: `cosign attest` 3.1.3 verarbeitet
`--statement` nicht; der Runner verwendet nun `--predicate`/`--type`, erwartet exakt
Statement v0.1 und prüft das Resultat. Eine unvollständige Compilerextraktion wurde
bei der Hashprüfung erkannt. Der Installer extrahiert nun ausschließlich gepinnte
Dateien aus dem geprüften Archiv, prüft deren vollständige Bytes vor dem Schreiben
und ersetzt Dateien atomar. Bereits gecachte Tool-Binaries erhalten ebenfalls das
Ausführungsrecht.

## Identitäten des Referenzlaufs

| Gegenstand | Wert |
|---|---|
| Image-Digest | `sha256:9384a68e69fb574f8e76d41153b957fdb49987372ce352d009beda488ef5c7d4` |
| Evidence-Manifest, OCI-Digest | `sha256:14bf91abcba5522559244b0788ea136d078fb4675bdf4d96a51bebc2ccf8576f` |
| Evidence-Manifest, Bundle-Digest | `sha256:50099f45a2c0afa5c82489c46af28fa4bb6e55b7162497759db1bf7160e32c67` |
| Rust-Quelltext | `sha256:331c34df983ac3e02c7987dcc4a618ea2011d4ed373910647287dcf7dd5a7cd5` |
| Binärdatei | `sha256:6fdf1aa300ae4bae6672874ca38e28069ecc9f498560037bb6e5a4ce0a779018` |
| Policy | `sha256:3bde75852523b362fdbc36bca392554cab1a723cbde6d9672573234f16091343` |
| Werkzeug-Lockfile | `sha256:0ebfceacd48c750ec06a7ee25e86e1d5a40e1963a396f32bab58aa95f11bbe70` |

Werkzeuge: Cosign 3.1.3; Syft 1.51.1; Crane 0.22.1; Distribution 3.1.1.
Compiler: `rustc 1.63.0`. Host-Linker: `cc (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0`.
Python verwendet ausschließlich die Standardbibliothek.

## Öffentliche Nachweise im Paket

`release/run-summary.json` enthält Laufmetadaten; `acceptance-results.json` enthält
alle sechs tatsächlichen Entscheidungen. `verification-online.json`,
`verification-offline.json` und `reverification.json` dokumentieren die wiederholten
Prüfungen. SBOM, Governance, Manifest-Predicate, drei Sigstore-Bundles, Public Key,
Prüfauftrag, Policy und Befehls-/Registry-Logs liegen daneben.
`release/bundle/blobs/sha256/` enthält die aus der Registry abgerufenen Bytes,
einschließlich Image-Manifest, Config und der Layer mit der Binärdatei.

Die privaten Testschlüssel und die temporäre Registry werden nach dem Lauf entfernt.
Der gepackte Referenzlauf lässt sich mit dem Public Key offline erneut prüfen;
der Testschlüssel ist nicht zum weiteren Signieren verfügbar.

## Aussagegrenzen

Das reale Syft-SBOM nennt das Container-Image als Wurzelkomponente und erkennt
**0 Paketkomponenten** in diesem minimalen Scratch-Image. Das Ergebnis ist kein
Nachweis vollständiger Softwareinventarisierung oder Schwachstellenfreiheit.

Der Governance-Bericht ist ausdrücklich ein Mock. Dieses selbstsignierte Demo-Paket
belegt eine technische Evidence-Kette; eine unabhängige Release-Autorisierung entsteht
erst mit außerhalb des Pakets vertrauenswürdig verankertem Prüfauftrag, Public Key und
Policy. `productionAcceptance` bleibt immer `false`.

Keine kanonische SENTINEL-v2.2-Konformität, keine SLSA-Stufe, keine Trivy-, HSM-, Azure-
oder CAB-Prüfung. Keine Zeit-/Widerrufsprüfung und kein Transparenzlog-Nachweis.
Die bestehende Erweiterungsspezifikation wird durch dieses reduzierte Demo-Profil
nicht als vollständig implementiert erklärt. Host-Linker und libc sind nicht hermetisch
gepinnt; deterministische Entscheidungen bei identischen Eingaben bedeuten keine
bitidentischen Builds oder Signaturen über verschiedene Erzeugungsläufe.

## Abschlussprüfung

Die unabhängige Codeprüfung fand eine relevante Lücke bei der Schlüsselbindung:
Cosign öffnete den ursprünglichen Public-Key-Pfad nach der Hashprüfung erneut.
Ein gezielter Test konnte die Datei dazwischen austauschen. Die Korrektur reicht
nun ausschließlich die bereits geprüften Schlüsselbytes weiter und übergibt Cosign
einen temporären Snapshot. Ein eigener Regressionstest deckt genau diesen Austausch
ab. Der zweite Befund betraf nur den Ausgabepfad der Startanleitung und ist behoben.
Die abschließende Unit-Suite, der komplette Registry-Lauf und der separate CLI-Aufruf
bestanden nach der Korrektur erneut. Das vollständige Unit-Testprotokoll liegt unter
`release/unit-tests.log`. Die Codeprüfung bestätigt den Snapshot-Fix; es bleiben keine
blockierenden Befunde im vereinbarten Demo-Umfang.


## CI-Ergänzung: reguläre Pipeline statt nur manuellem Demo-Lauf

Die unveränderte Evidence-Implementierung wird jetzt durch Pull Requests, Pushes auf
`main`, `merge_group`, `workflow_dispatch` und `workflow_call` angebunden. Das neue
Gesamtgate verlangt den erfolgreichen Abschluss der gesamten Matrix und führt auch
bei einem nicht erfolgreichen Matrixstatus eine ausdrückliche Bewertung durch.

Neue lokale Prüfung:

- **13/13 Tests bestanden** in 33,758 Sekunden: zehn bestehende Verifikator-Tests und
  drei neue CI-Gate-Tests. Der Negativtest enthält sechs unterschiedliche
  nicht erfolgreiche oder unbekannte Statuswerte; zusätzlich ist die fehlgeschlagene
  Berichtsspeicherung geprüft. Protokoll: `release/ci-integration-tests.log`.
- Die drei neuen Tests schlugen vor der Implementierung des Gate-Befehls fehl und
  bestanden anschließend mit dem tatsächlichen CLI-Prozess.
- **actionlint 1.7.12: Exit 0**, keine Meldungen für `.github/workflows/demo.yml`.
  Geprüft wurde mit `-shellcheck= -pyflakes=`; diese optionalen Zusatzprüfer wurden
  nicht verwendet. Python-Kompilation und Verhaltenstests wurden separat ausgeführt.
  Das Actionlint-Archiv wurde gegen die veröffentlichte SHA-256-Liste geprüft.
- Die YAML-Prüfung bestätigt die fünf Trigger, die exakten sechs Matrixwerte,
  `needs: acceptance`, `if: always()` und den Bezug auf `needs.acceptance.result`.
- Diff-Prüfung: Evidence-Runner, Verifikator, Content Stores und Werkzeug-Lockfile
  sind gegenüber dem bereits abgenommenen Referenzlauf unverändert.

Die zusätzliche unabhängige Agentenprüfung dieser CI-Ergänzung wurde vom Dienst mit
einem allgemeinen Cybersecurity-Hinweis abgebrochen. Sie wird nicht als erfolgreiche
Prüfung gezählt. Die abschließende Sichtprüfung der kleinen CI-Änderung erfolgte durch
den koordinierenden Agenten; die frühere unabhängige Prüfung des Evidence-Kerns bleibt
im vorstehenden Bericht dokumentiert. Metadaten und Dateihashes der Ergänzung stehen
in `release/ci-integration-validation.json`.

**Weiterhin nicht ausgeführt:** gehosteter Actions-Lauf, Veröffentlichung des Codes,
Änderung von Repository-Regeln oder Produktionsrelease. Der manuell vorgegebene
Jobstatus eines lokalen Gate-Tests ist kein GitHub-Ausführungsnachweis.


## Repository-Import für den Draft-PR

Basis: `e5d48ab094c3c5d1c4d7d551b869bf080adf6a9f` auf `main`.
Der Quellcode liegt unter `demo-v2.2/`; der Workflow liegt unter
`.github/workflows/sentinel-demo.yml`. Arbeitsverzeichnisse, Cosign-Pfad und
Artefakt-Uploads wurden für diese Einbindung angepasst. Generierte Bundles,
Schlüssel, Tool-Binaries und Lauf-Logs sind nicht Teil des Git-Imports.

Nach dem Import tatsächlich geprüft:

- Demo: **13/13 Tests bestanden**, 34,007 Sekunden, mit dem zuvor gepinnten Cosign.
- Bestehender Core: **172 pytest-Tests bestanden**; `ruff check src tests` erfolgreich.
- Repository-Validator: **13 Workflowdateien akzeptiert**, einschließlich des neuen Workflows.
- `actionlint` 1.7.12: neuer Workflow ohne Meldungen; optionale Shellcheck-/Pyflakes-Prüfer deaktiviert.
- Arbeitsverzeichnisse, sechs Matrixfälle, Gate-Abhängigkeit und Upload-Pfade geprüft.
- Staged-Diff: JSON gültig, keine Schlüssel-/Zertifikatsdateien oder generierten Nachweise.

Ein gehosteter Lauf ist dadurch weiterhin nicht bewiesen. Dessen Befund muss aus
den GitHub-Checks des Draft-PRs für den tatsächlich geprüften Commit stammen.
