# -*- coding: utf-8 -*-
import os
import shutil
import tempfile
import unittest

from pvault import portable


ENTRIES = [
    {"id": "a", "title": "Почта Ёлка", "login": "u@e.com", "password": "п;ароль,1",
     "url": "https://e.com", "notes": "строка\nвторая", "created": "2026-01-01T00:00:00Z",
     "modified": "2026-01-02T00:00:00Z"},
    {"id": "b", "title": "Удалённая", "login": "", "password": "x", "url": "",
     "notes": "", "created": "2026-01-01T00:00:00Z",
     "modified": "2026-01-02T00:00:00Z", "deleted": True},
]


class ExportTest(unittest.TestCase):
    def test_csv_roundtrip_survives_separators_and_newlines(self):
        text = portable.export_csv(ENTRIES)
        back = portable.parse_csv(text)
        self.assertEqual(len(back), 1)                 # удалённая пропущена
        self.assertEqual(back[0]["title"], "Почта Ёлка")
        self.assertEqual(back[0]["password"], "п;ароль,1")
        self.assertEqual(back[0]["notes"], "строка\nвторая")

    def test_csv_can_include_deleted(self):
        self.assertEqual(len(portable.parse_csv(
            portable.export_csv(ENTRIES, include_deleted=True))), 2)

    def test_json_roundtrip(self):
        back = portable.parse_json(portable.export_json(ENTRIES))
        self.assertEqual(len(back), 1)
        self.assertEqual(back[0]["url"], "https://e.com")

    def test_json_history_optional(self):
        entries = [dict(ENTRIES[0], history=[{"password": "старый", "changed": ""}])]
        self.assertNotIn("history", portable.export_json(entries))
        self.assertIn("history", portable.export_json(entries, include_history=True))


class ImportTest(unittest.TestCase):
    def test_bitwarden_headers(self):
        text = ("name,login_username,login_password,login_uri,notes\r\n"
                "Почта,user,pass,https://e.com,заметка\r\n")
        e = portable.parse_csv(text)[0]
        self.assertEqual(e["title"], "Почта")
        self.assertEqual(e["login"], "user")
        self.assertEqual(e["password"], "pass")
        self.assertEqual(e["url"], "https://e.com")

    def test_keepass_headers(self):
        text = ("Account,Login Name,Password,Web Site,Comments\r\n"
                "Банк,ivan,secret,https://bank.ru,важное\r\n")
        e = portable.parse_csv(text)[0]
        self.assertEqual(e["title"], "Банк")
        self.assertEqual(e["login"], "ivan")
        self.assertEqual(e["notes"], "важное")

    def test_semicolon_delimiter(self):
        text = "title;login;password\r\nСайт;u;p\r\n"
        self.assertEqual(portable.parse_csv(text)[0]["title"], "Сайт")

    def test_unknown_headers_rejected_with_clear_message(self):
        with self.assertRaises(portable.ImportError_) as ctx:
            portable.parse_csv("колонка1,колонка2\r\nа,б\r\n")
        self.assertIn("заголовк", str(ctx.exception))

    def test_empty_rows_skipped(self):
        text = "title,login,password\r\nСайт,u,p\r\n,,\r\n\r\n"
        self.assertEqual(len(portable.parse_csv(text)), 1)

    def test_untitled_row_gets_placeholder(self):
        text = "title,login,password\r\n,u,p\r\n"
        self.assertEqual(portable.parse_csv(text)[0]["title"], "(без названия)")

    def test_foreign_ids_are_not_reused(self):
        """Чужой id может столкнуться с нашим и «слипнуться» при слиянии."""
        text = '{"entries":[{"id":"мой-id","title":"Т","password":"p"}]}'
        self.assertNotEqual(portable.parse_json(text)[0]["id"], "мой-id")

    def test_bare_json_list(self):
        text = '[{"title":"Т","password":"p"}]'
        self.assertEqual(len(portable.parse_json(text)), 1)

    def test_broken_json(self):
        with self.assertRaises(portable.ImportError_):
            portable.parse_json("{это не json")


class FileTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="pvport-")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_write_and_read_back(self):
        path = os.path.join(self.dir, "e.csv")
        portable.write_export(path, portable.export_csv(ENTRIES))
        self.assertEqual(portable.read_import(path)[0]["title"], "Почта Ёлка")

    def test_cp1251_file_is_understood(self):
        path = os.path.join(self.dir, "old.csv")
        with open(path, "wb") as f:
            f.write("title,login,password\r\nПочта,u,p\r\n".encode("cp1251"))
        self.assertEqual(portable.read_import(path)[0]["title"], "Почта")

    def test_json_detected_by_extension(self):
        path = os.path.join(self.dir, "e.json")
        portable.write_export(path, portable.export_json(ENTRIES))
        self.assertEqual(len(portable.read_import(path)), 1)
