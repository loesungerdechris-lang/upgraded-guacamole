# SPDX-License-Identifier: AGPL-3.0-only
"""Lokale Akzeptanztests für synthetische Demo-Scans und die Einlösung."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier
import unittest

from ki_dividende_modell import DemoRegister, DemoToken, Reject


class NachweisTests(unittest.TestCase):
    PROGRAMM = "erdpilot"
    PERIODE = "2026-Q4"

    def setUp(self):
        ordner = TemporaryDirectory()
        self.addCleanup(ordner.cleanup)
        self.pfad = Path(ordner.name) / "demo.sqlite"
        self.register = DemoRegister(self.pfad)

    def scan(self, person="DEMO-A"):
        return self.register.scan(person, self.PROGRAMM, self.PERIODE)

    def einloesen(self, token):
        return self.register.einloesen(token, self.PROGRAMM, self.PERIODE)

    def test_frische_tokens_gleicher_anspruch(self):
        eins, zwei = self.scan(), self.scan()
        self.assertNotEqual(eins.wert, zwei.wert)
        self.einloesen(eins)
        with self.assertRaisesRegex(Reject, "bereits eingelöst"):
            self.einloesen(zwei)

    def test_wiederholte_vorlage_desselben_tokens(self):
        token = self.scan()
        self.einloesen(token)
        with self.assertRaisesRegex(Reject, "bereits eingelöst"):
            self.einloesen(token)

    def test_zwei_personen_im_selben_programm(self):
        a = self.einloesen(self.scan("DEMO-A"))
        b = self.einloesen(self.scan("DEMO-B"))
        self.assertNotEqual(a, b)

    def test_neue_periode_und_anderes_programm(self):
        marker = {self.einloesen(self.scan())}
        for programm, periode in ((self.PROGRAMM, "2027-Q1"), ("zweiter-pilot", self.PERIODE)):
            token = self.register.scan("DEMO-A", programm, periode)
            marker.add(self.register.einloesen(token, programm, periode))
        self.assertEqual(len(marker), 3)

    def test_falsche_periode_und_falsches_programm_verbrauchen_nichts(self):
        token = self.scan()
        for programm, periode in ((self.PROGRAMM, "2027-Q1"), ("zweiter-pilot", self.PERIODE)):
            with self.subTest(programm=programm, periode=periode):
                with self.assertRaisesRegex(Reject, "Kein registrierter Nachweis"):
                    self.register.einloesen(token, programm, periode)
        self.einloesen(token)

    def test_unbekannter_aussteller_verbraucht_nichts(self):
        token = self.scan()
        with self.assertRaisesRegex(Reject, "Aussteller"):
            self.einloesen(DemoToken("anderer-demo-aussteller", token.wert))
        self.einloesen(token)

    def test_unbekannter_oder_fehlerhafter_nachweis(self):
        # 64 Nullen sind in dieser leeren lokalen Datenbank kein ausgestellter Token.
        for wert in ("0" * 64, "", "kein-test-token"):
            with self.subTest(wert=wert):
                with self.assertRaises(Reject):
                    self.einloesen(DemoToken(DemoRegister.AUSSTELLER, wert))
        self.einloesen(self.scan())

    def test_nur_benannte_fiktive_kennungen(self):
        with self.assertRaisesRegex(Reject, "Testeintrag"):
            self.scan("NICHT-EINGESCHRIEBEN")
        self.einloesen(self.scan())

    def test_fehlender_geltungsbereich(self):
        token = self.scan()
        with self.assertRaisesRegex(Reject, "Kennungen"):
            self.register.einloesen(token, self.PROGRAMM, "")
        with self.assertRaisesRegex(Reject, "Kennungen"):
            self.register.scan("DEMO-A", "", self.PERIODE)
        self.einloesen(token)

    def test_neustart_mit_derselben_datenbank(self):
        token = self.scan()
        neu = DemoRegister(self.pfad)
        neu.einloesen(token, self.PROGRAMM, self.PERIODE)
        wieder = DemoRegister(self.pfad)
        frisch = wieder.scan("DEMO-A", self.PROGRAMM, self.PERIODE)
        with self.assertRaisesRegex(Reject, "bereits eingelöst"):
            wieder.einloesen(frisch, self.PROGRAMM, self.PERIODE)

    def test_gleichzeitige_einloesungen_sind_atomar(self):
        tokens = [self.scan(), self.scan()]
        start = Barrier(2, timeout=10)

        def einloesungsversuch(token):
            start.wait()
            try:
                self.einloesen(token)
            except Reject as fehler:
                self.assertIn("bereits eingelöst", str(fehler))
                return False
            return True

        with ThreadPoolExecutor(max_workers=2) as pool:
            ergebnisse = list(pool.map(einloesungsversuch, tokens))
        self.assertCountEqual(ergebnisse, [True, False])


if __name__ == "__main__":
    unittest.main(verbosity=2)
