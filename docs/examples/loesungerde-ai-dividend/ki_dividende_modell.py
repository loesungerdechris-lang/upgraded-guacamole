#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""LoesungErde-KI-Dividende, ausführbares Referenzmodell für eine Pilotperiode.

Aufrufe: python3 ki_dividende_modell.py und python3 -m unittest -v test_claims
Voraussetzung: Python ab 3.8, nur Standardbibliothek.

Alle Beträge sind ganzzahlige Cent. Das Modell erzeugt einen Verteilungsplan.
Kennungen, bestätigte Einnahmen, Vertragsquote und Geldeingang sind synthetische
Eingaben. Der Aufrufer bestätigt, dass die Liste der Berechtigten vollständig
geklärt ist. Der Verteilungsplan prüft weder Identitäten noch externe Belege
und bucht kein Geld. Ein erfolgreicher Einspruch nach dem Abschluss erfordert
eine gesondert gedeckte Nachzahlung.
Diese spätere Korrektur ist hier nicht implementiert.

DemoRegister simuliert, getrennt davon, die Einlösung synthetischer Nachweise.
Der «Scan» wählt eine von drei erfundenen Kennungen. Ohne Sensor, biometrische
Daten, Signatur oder Zero-Knowledge-Beweis. In diesem zentralen Modell kann der
Betreiber Daten verknüpfen. Der Besitz des Demo-Tokens reicht zur Einlösung.
"""

from contextlib import closing, contextmanager
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import re
import secrets
import sqlite3
from typing import Iterable, Optional, Tuple
import unittest


class Hold(ValueError):
    """Fehlende oder widersprüchliche Nachweise verhindern die Freigabe."""


class Reject(ValueError):
    """Eine Eingabe verletzt die Regeln des Modells."""


@dataclass(frozen=True)
class Anspruch:
    person: str
    zahlungsziel: Optional[str] = None  # None: Anspruch anerkannt, Zahlung offen
    gewicht: int = 1


@dataclass(frozen=True)
class Position:
    person: str
    zahlungsziel: Optional[str]
    cent: int


@dataclass(frozen=True)
class Plan:
    zahlbar: Tuple[Position, ...]
    reserviert: Tuple[Position, ...]
    rest_cent: int


def verteilen(erloes_cent: int, quote_bp: int, eingang_cent: int,
              ansprueche: Iterable[Anspruch], *, personenkreis_geklaert: bool) -> Plan:
    """Plant eine Periode. 100 Basispunkte entsprechen einem Prozent."""
    for wert in (erloes_cent, quote_bp, eingang_cent):
        if type(wert) is not int or wert < 0:
            raise Reject("Beträge und Basispunkte müssen nichtnegative ganze Zahlen sein.")
    if quote_bp > 10000:
        raise Reject("Eine Vertragsquote über 100 Prozent ist unzulässig.")

    # Im Mustervertrag wird die Forderung am Periodenende auf volle Cent abgerundet.
    soll_cent = erloes_cent * quote_bp // 10000
    if soll_cent != eingang_cent:
        raise Hold(f"Vertragssoll {soll_cent} Cent, belegter Eingang {eingang_cent} Cent.")
    if personenkreis_geklaert is not True:
        raise Hold("Der Kreis der Berechtigten ist noch offen.")

    personen = list(ansprueche)
    if not personen:
        raise Hold("Die Liste der Berechtigten ist leer.")
    kennungen = set()
    for anspruch in personen:
        if not isinstance(anspruch.person, str) or not anspruch.person.strip():
            raise Reject("Eine Personenkennung fehlt.")
        if anspruch.person in kennungen:
            raise Reject(f"Doppelter Anspruch für {anspruch.person}.")
        kennungen.add(anspruch.person)
        if type(anspruch.gewicht) is not int or anspruch.gewicht != 1:
            raise Reject("Jeder persönliche Anspruch hat genau Gewicht eins.")
        ziel = anspruch.zahlungsziel
        if ziel is not None and (not isinstance(ziel, str) or not ziel.strip()):
            raise Reject("Ein ungeklärtes Zahlungsziel ist als None anzugeben.")

    pro_kopf_cent, rest_cent = divmod(eingang_cent, len(personen))
    zahlbar, reserviert = [], []
    for anspruch in personen:
        position = Position(anspruch.person, anspruch.zahlungsziel, pro_kopf_cent)
        if anspruch.zahlungsziel is None:
            reserviert.append(position)
        else:
            zahlbar.append(position)
    # Der Rest ist für einen Vortrag gebunden. Dieser Plan weist ihn gesondert aus.
    return Plan(tuple(zahlbar), tuple(reserviert), rest_cent)


@dataclass(frozen=True)
class DemoToken:
    aussteller: str
    wert: str


class DemoRegister:
    """Ein vertrauenswürdiges lokales SQLite-Register pro Demo, für alle Perioden.

    Programm und Periode bestimmt der Betreiber bei Scan und Einlösung. Die
    Sperre gilt für dieselbe Datenbank. Kopien, Rücksicherung alter Stände und
    mehrere unabhängige Register erfordern eine übergeordnete Abstimmung.
    """

    AUSSTELLER = "LOESUNGERDE-DEMO"
    PERSONEN = frozenset(("DEMO-A", "DEMO-B", "DEMO-C"))

    def __init__(self, pfad):
        if str(pfad) in ("", ":memory:"):
            raise ValueError("Das DemoRegister benötigt einen dauerhaften Dateipfad.")
        self._pfad = Path(pfad).resolve()
        with self._transaktion() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS berechtigungen (
                programm TEXT NOT NULL, periode TEXT NOT NULL, person TEXT NOT NULL,
                marker TEXT NOT NULL UNIQUE, PRIMARY KEY (programm, periode, person)
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS nachweise (
                fingerabdruck TEXT PRIMARY KEY NOT NULL,
                marker TEXT NOT NULL REFERENCES berechtigungen(marker)
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS einloesungen (
                marker TEXT PRIMARY KEY NOT NULL REFERENCES berechtigungen(marker)
            )""")

    @contextmanager
    def _transaktion(self):
        with closing(sqlite3.connect(self._pfad, timeout=5)) as db:
            db.execute("PRAGMA foreign_keys = ON")
            with db:
                db.execute("BEGIN IMMEDIATE")
                yield db

    @staticmethod
    def _pruefe_geltung(programm, periode):
        for kennung in (programm, periode):
            if not isinstance(kennung, str) or not re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", kennung):
                raise Reject("Programm und Periode benötigen eindeutige technische Kennungen.")

    def scan(self, person: str, programm: str, periode: str) -> DemoToken:
        """Gibt pro Aufruf einen neuen opaken Test-Token für eine Demo-Person aus."""
        self._pruefe_geltung(programm, periode)
        if not isinstance(person, str) or person not in self.PERSONEN:
            raise Reject("Kein anerkannter synthetischer Testeintrag.")
        wert = secrets.token_hex(32)
        fingerabdruck = sha256(wert.encode("ascii")).hexdigest()
        with self._transaktion() as db:
            berechtigung = db.execute(
                "SELECT marker FROM berechtigungen WHERE programm=? AND periode=? AND person=?",
                (programm, periode, person)
            ).fetchone()
            if berechtigung is None:
                marker = secrets.token_hex(32)
                db.execute(
                    "INSERT INTO berechtigungen(programm, periode, person, marker) VALUES(?, ?, ?, ?)",
                    (programm, periode, person, marker)
                )
            else:
                marker = berechtigung[0]
            db.execute("INSERT INTO nachweise(fingerabdruck, marker) VALUES(?, ?)",
                       (fingerabdruck, marker))
        return DemoToken(self.AUSSTELLER, wert)

    def einloesen(self, token: DemoToken, programm: str, periode: str) -> str:
        """Bucht die einmalige lokale Demo-Einlösung; liefert deren Bereichskennung."""
        self._pruefe_geltung(programm, periode)
        if not isinstance(token, DemoToken) or token.aussteller != self.AUSSTELLER:
            raise Reject("Der Nachweis stammt nicht vom Demo-Aussteller.")
        if not isinstance(token.wert, str) or not re.fullmatch(r"[0-9a-f]{64}", token.wert):
            raise Reject("Ungültiges Demo-Tokenformat.")
        fingerabdruck = sha256(token.wert.encode("ascii")).hexdigest()
        with self._transaktion() as db:
            eintrag = db.execute("""
                SELECT b.marker FROM nachweise n JOIN berechtigungen b ON n.marker = b.marker
                WHERE n.fingerabdruck=? AND b.programm=? AND b.periode=?
            """, (fingerabdruck, programm, periode)).fetchone()
            if eintrag is None:
                raise Reject("Kein registrierter Nachweis für dieses Programm und diese Periode.")
            marker = eintrag[0]
            if db.execute("SELECT 1 FROM einloesungen WHERE marker=?", (marker,)).fetchone():
                raise Reject("Dieser Anspruch wurde in dieser Periode bereits eingelöst.")
            db.execute("INSERT INTO einloesungen(marker) VALUES(?)", (marker,))
        return marker


class Modelltests(unittest.TestCase):
    def setUp(self):
        self.abc = [Anspruch("A", "Ziel-1"), Anspruch("B", "Ziel-2"), Anspruch("C")]

    def test_drei_gleiche_ansprueche_mit_reservierung_und_rest(self):
        plan = verteilen(10000, 10000, 10000, self.abc, personenkreis_geklaert=True)
        self.assertEqual(plan.zahlbar, (Position("A", "Ziel-1", 3333),
                                       Position("B", "Ziel-2", 3333)))
        self.assertEqual(plan.reserviert, (Position("C", None, 3333),))
        self.assertEqual(plan.rest_cent, 1)

    def test_doppelte_kennung_bei_verschiedenen_zielen(self):
        ansprueche = self.abc + [Anspruch("A", "anderes-Ziel")]
        with self.assertRaisesRegex(Reject, "Doppelter Anspruch"):
            verteilen(10000, 10000, 10000, ansprueche, personenkreis_geklaert=True)

    def test_gemeinsames_zahlungsziel_fuer_zwei_menschen(self):
        beide = [Anspruch("A", "gemeinsam"), Anspruch("B", "gemeinsam")]
        plan = verteilen(10000, 10000, 10000, beide, personenkreis_geklaert=True)
        self.assertEqual(plan.zahlbar, (Position("A", "gemeinsam", 5000),
                                       Position("B", "gemeinsam", 5000)))

    def test_gruendergewicht_wird_zurueckgewiesen(self):
        personen = self.abc + [Anspruch("Gruender", "Ziel-4", gewicht=2)]
        with self.assertRaisesRegex(Reject, "genau Gewicht eins"):
            verteilen(10000, 10000, 10000, personen, personenkreis_geklaert=True)

    def test_fehlende_deckung_bei_zwei_prozent(self):
        with self.assertRaisesRegex(Hold, "Vertragssoll 200000 Cent, belegter Eingang 180000 Cent"):
            verteilen(10_000_000, 200, 180_000, self.abc, personenkreis_geklaert=True)

    def test_gedeckte_zwei_prozent(self):
        plan = verteilen(10_000_000, 200, 200_000, self.abc, personenkreis_geklaert=True)
        self.assertEqual([p.cent for p in plan.zahlbar + plan.reserviert], [66666] * 3)
        self.assertEqual(plan.rest_cent, 2)

    def test_offener_personenkreis_haelt_gesamten_lauf_an(self):
        with self.assertRaisesRegex(Hold, "noch offen"):
            verteilen(10000, 10000, 10000, self.abc, personenkreis_geklaert=False)

    def test_leere_liste_haelt_lauf_an(self):
        with self.assertRaisesRegex(Hold, "Liste der Berechtigten ist leer"):
            verteilen(10000, 10000, 10000, [], personenkreis_geklaert=True)

    def test_gelderhaltung_auch_bei_kleinen_betraegen(self):
        for pool in range(20):
            for anzahl in range(1, 8):
                with self.subTest(pool=pool, anzahl=anzahl):
                    personen = [Anspruch(str(i), "Ziel" if i % 2 else None)
                                for i in range(anzahl)]
                    plan = verteilen(pool, 10000, pool, personen, personenkreis_geklaert=True)
                    positionen = plan.zahlbar + plan.reserviert
                    self.assertEqual(len(positionen), anzahl)
                    self.assertEqual({p.cent for p in positionen}, {pool // anzahl})
                    self.assertEqual(sum(p.cent for p in positionen) + plan.rest_cent, pool)
                    self.assertLess(plan.rest_cent, anzahl)


if __name__ == "__main__":
    unittest.main(verbosity=2)
