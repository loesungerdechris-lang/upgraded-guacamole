# SENTINEL Evidence Demonstrator

**Reifegrad: Architecture Demonstrator — M1 nachgewiesen, M2 als Draft-Erweiterung.**
M1 ist durch [Draft PR #69](https://github.com/loesungerdechris-lang/upgraded-guacamole/pull/69)
und den [erfolgreichen GitHub-Lauf](https://github.com/loesungerdechris-lang/upgraded-guacamole/actions/runs/35213885803)
belegt. Governance-Akzeptanz und menschliches Review bleiben offen.

**M2:** Ein live erzeugtes Golden Bundle, zehn deklarative Mutationen und exakte
Prozess-Exit-Codes. Der [M2-Vertrag mit Startbefehlen](docs/M2_PROFILE.md) beschreibt
das zusätzliche Profil, die Demo-Provenance und die Vertrauensgrenzen.
Die [vertragliche Coverage-Matrix](../docs/mutation-coverage-matrix.md) verbindet
zehn M2-Anforderungen mit Mutationen, exakten Exit-Codes und GitHub-Nachweisen;
sie enthält auch die Statusübersicht und das Mermaid-Diagramm.
Die [M2-Baseline](../docs/acceptance/m2-baseline.md) fixiert den Referenzlauf.
Der [v2.2-Crosswalk](../docs/evidence-bundle-v2.2/crosswalk.md) ergänzt den
maschinenlesbaren Vertrag, generierte Ansichten und die Grenzen der Abdeckung.
Die folgenden Build-/Verifier-Details beschreiben weiterhin den kompatiblen M1-Pfad.

Ein kleiner, ausführbarer erster Sprint: **ein Rust-Binary, ein reales SBOM, ein ausdrücklich markierter Governance-Mock, ein signiertes Evidence Manifest und ein lesender Verifier.** Die Pipeline prüft das Bundle direkt aus einer lokalen OCI-Registry und wiederholt die Prüfung am exportierten Paket.

**Profil:** `sentinel-demo-mvp/v0.1`. Der Ordnername `demo-v2.2` bezeichnet den vereinbarten Arbeitsstand. Dieses Projekt ist **nicht** das kanonische SENTINEL-v2.2-Testpaket und kein Konformitätsnachweis für die vollständige Cloud-Native-Spezifikation.

## Start

Voraussetzung: Linux/amd64, Python >= 3.10, `cc`/GCC, statische libc-Entwicklungsdateien und `dpkg-deb`. Auf Windows kann der Lauf in einer geeigneten WSL2-Linux-Umgebung erfolgen. Docker ist für den kanonischen Lauf nicht erforderlich. Die Toolchain wird in ein eigenes Verzeichnis heruntergeladen, ohne systemweite Installation.

```bash
cd demo-v2.2
python3 scripts/bootstrap.py --directory .tools
COSIGN_BIN="$PWD/.tools/cosign" python3 -m unittest discover -s tests -v
python3 scripts/run_demo.py --tools .tools --output release
```

Der Git-Stand enthält Quellcode und Prüfberichte, aber keine generierten Bundles,
Registry-Daten, Tool-Binaries oder Schlüsseldateien. Der Lauf erzeugt `release/`;
dieser Ausgabepfad muss neu oder leer sein. Für einen weiteren Lauf einen anderen Pfad wählen:

```bash
python3 scripts/run_demo.py --tools .tools --output release-second
```

Der Lauf startet selbst eine nur an Loopback gebundene Distribution-Registry an einem freien Port und beendet sie anschließend. Registry-Daten und privater Testschlüssel liegen in einem temporären Arbeitsverzeichnis und werden entfernt. Es werden keine Container ausgeführt, keine Cloud-Registry beschrieben und keine GitHub-Releases veröffentlicht. Das Rust-Binary wird lokal gestartet und getestet, bevor es in das Image gelangt.

## Ablauf

1. Rust-Quelltext testen, statisch kompilieren und Ausgabeverhalten prüfen.
2. Mit Crane eine normalisierte Ein-Datei-Layer in ein OCI-Scratch-Image verpacken; Entrypoint und Plattform setzen.
3. Einmal nach Image-Digest auflösen und fortan ausschließlich diesen Digest verwenden.
4. Mit Syft ein echtes CycloneDX-1.6-SBOM dieses Registry-Images erzeugen.
5. Governance-Testdatensatz erzeugen: `fixture:true`, `productionApproval:false`. Die drei technischen Checks folgen tatsächlich erfolgreichen Pipeline-Schritten.
6. SBOM und Governance mit Cosign signieren und hochladen; OCI- und Payload-Digests rücklesen.
7. Ein Manifest mit den exakten Evidence-Descriptors signieren und hochladen.
8. Mit unabhängig übergebener Policy, Public Key und Prüfauftrag verifizieren.
9. Online-, Offline- und Wiederholungsbefund vergleichen; sechs Abnahmefälle prüfen.

Die Cosign-Umschläge sind echte in-toto Statement v0.1 / DSSE / Sigstore Bundles. Das bedeutet **keine** implementierte SLSA-Provenance-Stufe. Dieses Demo-Profil fixiert ausdrücklich das von `cosign attest` 3.1.3 erzeugte Statement-Format v0.1 und kontrolliert dessen Inhalt vollständig gegen das erwartete Statement. Eine Migration auf Statement v1 gehört zur späteren Architekturintegration; `cosign attest --statement` verarbeitet das Statement in dieser Werkzeugversion nicht.

## Verifier separat ausführen

Nach dem Lauf ist die temporäre Registry beendet. Der Offline-Export enthält das Image mit Config/Layer und die tatsächlich aus der Registry abgerufenen Attestationen.

```bash
python3 sentinel verify-bundle \
  --request release/verification-request.json \
  --policy release/governance-policy.yml \
  --key release/demo.pub \
  --offline release/bundle \
  --cosign .tools/cosign \
  --output release/reverification.json
```

Während eine entsprechende lokale Registry verfügbar ist, kann `--offline` entfallen. Es werden nur explizite Loopback-Registry-Adressen akzeptiert. Cloud-Authentisierung ist außerhalb dieses Sprints.

**Vertrauensgrenze:** Der Prüfauftrag, die Policy und der Public Key sind vom Prüfenden unabhängig bereitzustellen. Das ausgelieferte Beispielpaket dokumentiert einen Demo-Lauf. Wer das gesamte Paket einschließlich Prüfauftrag und Public Key austauschen darf, könnte ein anderes konsistentes Demo-Paket erzeugen. Eine unabhängige Release-Autorisierung ist noch nicht implementiert.

| Ergebnis | Exit | Aussage |
|---|---:|---|
| PASS | 0 | Technische Demo-Prüfung erfolgreich. |
| HOLD | 2 | Ein erforderlicher Nachweis fehlt. |
| BLOCKED | 3 | Integritäts-, Signatur-, Kontext- oder Policy-Verstoß. |
| ERROR | 4 | Prüflauf technisch nicht entscheidungsfähig. |

Der Runner selbst liefert Exit 0 nur, wenn die positive Prüfung **und die erwarteten Ablehnungen** erfolgreich sind. Ein erwartetes HOLD/BLOCKED im Negativtest ist ein bestandener Test, aber kein angenommenes Bundle.

## Abnahmefälle

| Fall | Erwarteter Bundle-Befund |
|---|---|
| Vollständiges Bundle | PASS |
| Referenzierte SBOM-Attestation entfernt | HOLD |
| Referenzierte Governance-Attestation entfernt | HOLD |
| Image-Bytes passen nicht zum erwarteten Digest | BLOCKED |
| Signatur beschädigt, äußere Descriptors neu berechnet | BLOCKED durch Signaturprüfung |
| Referenziertes Manifest entfernt | HOLD |

Die Negativfälle verändern Kopien eines **real erzeugten und signierten** Pakets. Sie simulieren keine Cosign-Ergebnisse. Der Signaturtest aktualisiert äußere Hashes gezielt, damit nicht bloß der Hashvergleich fehlschlägt.

## GitHub Actions

Der Repository-Workflow [`.github/workflows/sentinel-demo.yml`](../.github/workflows/sentinel-demo.yml)
startet bei Pull Requests, Pushes auf `main`, Merge-Queue-Ereignissen, manuell und
per `workflow_call`. `verify-golden` erzeugt und prüft genau ein M2-Bundle.
`mutation-suite` lädt dasselbe gepinnte Artefakt in zehn Matrixjobs und prüft pro
Fall den erwarteten Exit-Code. Private Schlüssel gelangen nicht in diese Jobs.

**SENTINEL demo gate** benötigt beide Jobs mit Ergebnis `success`. Fehler,
Abbrüche, übersprungene Jobs und unbekannte Werte sperren das technische Gate.
Das Gate ist keine Produktionsfreigabe. Details: [CI-Integration](docs/CI_INTEGRATION.md).
Zusätzlich prüft `crosswalk-validation` den Traceability-Vertrag; `crosswalk-gate`
und `evidence-total-gate` verlangen ausdrücklich erfolgreiche Vorgängerjobs.
Der [Reviewvertrag](../docs/evidence-bundle-v2.2/review-and-gates.md) erklärt den
Unterschied zwischen diesen CI-Gates und noch nicht aktiviertem Merge-Schutz.

## Dateien

| Pfad | Zweck |
|---|---|
| `source/hello-sentinel.rs` | Ein Rust-Programm und sein Verhaltenstest. |
| `policy/governance.yml` | Explizite Demo-Policy, JSON-Untermenge von YAML. |
| `expected/acceptance.json` | Die sechs unabhängig definierten Erwartungswerte. |
| `sentinel_demo/verify.py` | Fail-closed-Verifikationslogik. |
| `sentinel_demo/store.py` | Lesender Registry-/Offline-Zugriff. |
| `sentinel_demo/cli.py`, `sentinel` | CLI und atomare Berichtsausgabe. |
| `scripts/run_demo.py` | Gemeinsame lokale/CI-Pipeline. |
| `scripts/scenarios.py` | Echte Fehlerfälle am exportierten Paket. |
| `scripts/ci_gate.py` | Gesamtgate für den von GitHub gelieferten Matrixstatus. |
| `scripts/bootstrap.py`, `toolchain.lock.json` | Prüfsummengebundene Tool-Installation. |
| `release/` (erst nach Lauf) | Öffentliche Demo-Nachweise, Public Key, Befunde und Logs; kein privater Schlüssel. |
| `docs/DEMO_PROFILE.md` | Exakter enger Vertrag dieses Sprints. |
| `docs/VALIDATION.md` | Tatsächlich ausgeführte Prüfungen und verbleibende Grenzen. |
| `docs/CI_INTEGRATION.md` | Trigger, Wiederverwendung und Anschluss an einen bestehenden Releasejob. |

## Bewusste Grenzen

- Governance bleibt ein Mock, keine CAB-/menschliche Freigabe. `productionAcceptance` ist immer `false`.
- Lokale Testschlüssel; kein HSM, Azure Key Vault, OIDC, Widerrufs- oder Zeitnachweis. Die ausdrückliche Cosign-Ausnahme zur Transparenzlog-Prüfung ist nur Teil dieses Demo-Profils. Keine automatische Übernahme in Produktion.
- Keine vollständige v2.2-Brücke, SLSA-Provenance, Trivy-Auswertung, Runtime-Evidenz oder Multiarch-Unterstützung.
- Ein echtes SBOM eines sehr kleinen Scratch-Images kann wenige oder keine erkannten Paketkomponenten enthalten. Ein Scan beweist weder vollständige Erkennung noch Schwachstellenfreiheit.
- Verifikation ist bei identischen Bytes deterministisch. Schlüssel, ECDSA-Signaturen und Zeitfelder ändern sich zwischen Erzeugungsläufen. Host-Linker/libc sind protokolliert, nicht hermetisch gepinnt; keine Garantie bitidentischer Builds auf verschiedenen Maschinen.
- Die vier Go-Tools und die Debian-Rust-Pakete sind auf SHA-256 fixiert. Release-Prüfsummen sind Integritätsanker; eine separate unabhängige Attestierungsbewertung aller Werkzeughersteller ist nicht Bestandteil dieses Sprints.
- `compose.yml` und `Dockerfile` sind optionale Komfortdateien. Der Compose-Tag ist nicht die kanonische, gehashte Toolchain. Der tatsächlich getestete Registry-Lauf nutzt die gepinnte native Registry-Binärdatei.

Kein Compliance Score, keine prozentuale Risikoreduktionsbehauptung und keine automatische Produktfreigabe.

## Offizielle technische Referenzen

- [Cosign Attestations](https://docs.sigstore.dev/cosign/verifying/attestation/)
- [in-toto Statement v0.1](https://github.com/in-toto/attestation/blob/main/spec/v0.1/statement.md)
- [Sigstore Bundle Format](https://docs.sigstore.dev/about/bundle/)
- [Syft-Ausgabeformate](https://oss.anchore.com/docs/guides/sbom/formats/)
- [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec/blob/main/spec.md)

Werkzeugverhalten wurde zusätzlich gegen die tatsächlich heruntergeladenen, gepinnten CLI-Binaries geprüft.
