#!/usr/bin/env python3
"""
=============================================================================
RAKIB EXIF METADATA READER - Automated Test Suite
Developer: RAKIB HOSSEN
=============================================================================
Automated tests for hash computation, GPS coordinate math, EXIF parsing,
and forensic report generation.
=============================================================================
"""

import hashlib
import json
import os
import tempfile
import unittest

from gps_parser import _convert_dms_to_dd, _format_dms_string, _to_float, parse_gps_info
from hash_utils import calculate_hashes, get_md5, get_sha1, get_sha256
from report_generator import generate_json_report, generate_txt_report


class TestHashUtils(unittest.TestCase):
    """Verifies cryptographic hash computation against known vectors."""

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.sample_data = b"Rakib Exif Metadata Reader - Forensic Integrity Test\n"
        self.temp_file.write(self.sample_data)
        self.temp_file.close()

    def tearDown(self):
        if os.path.exists(self.temp_file.name):
            os.remove(self.temp_file.name)

    def test_hashes_accuracy(self):
        expected_sha256 = hashlib.sha256(self.sample_data).hexdigest()
        expected_sha1 = hashlib.sha1(self.sample_data).hexdigest()
        expected_md5 = hashlib.md5(self.sample_data).hexdigest()

        result = calculate_hashes(self.temp_file.name)
        self.assertEqual(result["sha256"], expected_sha256)
        self.assertEqual(result["sha1"], expected_sha1)
        self.assertEqual(result["md5"], expected_md5)

    def test_convenience_helpers(self):
        expected_sha256 = hashlib.sha256(self.sample_data).hexdigest()
        self.assertEqual(get_sha256(self.temp_file.name), expected_sha256)

        expected_sha1 = hashlib.sha1(self.sample_data).hexdigest()
        self.assertEqual(get_sha1(self.temp_file.name), expected_sha1)

        expected_md5 = hashlib.md5(self.sample_data).hexdigest()
        self.assertEqual(get_md5(self.temp_file.name), expected_md5)

    def test_missing_file_handling(self):
        with self.assertRaises(FileNotFoundError):
            calculate_hashes("/non/existent/path/file.jpg")


class TestGpsParser(unittest.TestCase):
    """Verifies mathematical conversion of DMS to Decimal Degrees and URL generation."""

    def test_dms_to_dd_north_east(self):
        # 23° 48' 49.32" N
        # 23 + 48/60 + 49.32/3600 = 23 + 0.8 + 0.0137 = 23.8137
        dms = (23, 48, 49.32)
        dd = _convert_dms_to_dd(dms, "N")
        self.assertIsNotNone(dd)
        self.assertAlmostEqual(dd, 23.8137, places=4)

        # 90° 24' 45.0" E
        # 90 + 24/60 + 45/3600 = 90 + 0.4 + 0.0125 = 90.4125
        dms_lon = (90, 24, 45.0)
        dd_lon = _convert_dms_to_dd(dms_lon, "E")
        self.assertIsNotNone(dd_lon)
        self.assertAlmostEqual(dd_lon, 90.4125, places=4)

    def test_dms_to_dd_south_west_negatives(self):
        # 34° 36' 12" S -> should be negative
        dms_s = (34, 36, 12)
        dd_s = _convert_dms_to_dd(dms_s, "S")
        self.assertIsNotNone(dd_s)
        self.assertTrue(dd_s < 0)
        self.assertAlmostEqual(dd_s, -34.603333, places=4)

        # 58° 22' 54" W -> should be negative
        dms_w = (58, 22, 54)
        dd_w = _convert_dms_to_dd(dms_w, "W")
        self.assertIsNotNone(dd_w)
        self.assertTrue(dd_w < 0)
        self.assertAlmostEqual(dd_w, -58.381667, places=4)

    def test_tuple_rationals(self):
        # ((23, 1), (48, 1), (4932, 100))
        dms_rational = ((23, 1), (48, 1), (4932, 100))
        dd = _convert_dms_to_dd(dms_rational, "N")
        self.assertIsNotNone(dd)
        self.assertAlmostEqual(dd, 23.8137, places=4)

    def test_parse_gps_full_payload(self):
        raw_gps = {
            1: "N",
            2: ((23, 1), (48, 1), (4932, 100)),
            3: "E",
            4: ((90, 1), (24, 1), (4507, 100)),
            5: 0,
            6: (1500, 100),
            7: ((12, 1), (30, 1), (0, 1)),
            29: "2026:11:02",
        }

        parsed = parse_gps_info(raw_gps)
        self.assertTrue(parsed["has_gps"])
        self.assertAlmostEqual(parsed["latitude"], 23.8137, places=4)
        self.assertAlmostEqual(parsed["longitude"], 90.4125, places=4)
        self.assertIn("google.com/maps", parsed["google_maps_url"])
        self.assertIn("openstreetmap.org", parsed["osm_url"])
        self.assertIsNotNone(parsed["privacy_warning"])
        self.assertIn("PRIVACY ALERT", parsed["privacy_warning"])

    def test_empty_gps(self):
        parsed = parse_gps_info({})
        self.assertFalse(parsed["has_gps"])
        self.assertEqual(parsed["latitude"], "Not Available")
        self.assertEqual(parsed["longitude"], "Not Available")
        self.assertEqual(parsed["google_maps_url"], "Not Available")
        self.assertIsNone(parsed["privacy_warning"])


class TestReportGenerator(unittest.TestCase):
    """Verifies TXT and JSON report creation and content validation."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.mock_data = {
            "file_info": {
                "file_name": "forensic_target.jpg",
                "file_path": "/evidence/forensic_target.jpg",
                "file_size": "1.2 MB (1,258,291 bytes)",
                "image_format": "JPEG",
                "dimensions": "4000 x 3000 pixels",
                "aspect_ratio": "4:3 (1.33:1)",
                "color_mode": "RGB",
                "mime_type": "image/jpeg",
                "hashes": {
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                    "md5": "d41d8cd98f00b204e9800998ecf8427e",
                },
            },
            "has_exif": True,
            "has_gps": True,
            "camera_info": {
                "make": "Canon",
                "model": "Canon EOS R5",
                "software": "Firmware 1.5.0",
                "datetime_original": "2026:11:02 10:15:30",
                "datetime_digitized": "2026:11:02 10:15:30",
                "datetime_modified": "2026:11:02 10:15:30",
                "exposure_time": "1/500s",
                "iso": "100",
                "aperture": "f/4.0",
                "focal_length": "70.0 mm",
                "focal_length_35mm": "70",
                "lens_make": "Canon",
                "lens_model": "RF 24-70mm F2.8 L IS USM",
                "shutter_speed": "Not Available",
                "exposure_program": "Manual",
                "exposure_bias": "0",
                "metering_mode": "Pattern",
                "flash": "Did not fire",
                "white_balance": "Auto",
                "orientation": "Horizontal (normal)",
                "artist": "Rakib Hossen",
                "copyright": "Copyright 2026 Rakib Hossen",
            },
            "gps_info": {
                "has_gps": True,
                "latitude": 23.810331,
                "longitude": 90.412521,
                "latitude_ref": "N",
                "longitude_ref": "E",
                "latitude_dms": "23° 48' 37.19\" N",
                "longitude_dms": "90° 24' 45.08\" E",
                "altitude": "15.00 m (49.21 ft) [Above Sea Level]",
                "timestamp": "2026:11:02 04:15:30 UTC",
                "google_maps_url": "https://www.google.com/maps?q=23.810331,90.412521",
                "osm_url": "https://www.openstreetmap.org/?mlat=23.810331&mlon=90.412521#map=16/23.810331/90.412521",
                "privacy_warning": "[!] PRIVACY ALERT: Geolocation detected!",
            },
            "all_tags": {
                "Make": "Canon",
                "Model": "Canon EOS R5",
            },
            "error": None,
        }

    def tearDown(self):
        for f in os.listdir(self.temp_dir):
            os.remove(os.path.join(self.temp_dir, f))
        os.rmdir(self.temp_dir)

    def test_txt_report_creation(self):
        out_txt = os.path.join(self.temp_dir, "test_report.txt")
        saved = generate_txt_report(self.mock_data, output_path=out_txt)
        self.assertTrue(os.path.exists(saved))

        with open(saved, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("RAKIB EXIF METADATA READER", content)
        self.assertIn("DEVELOPER: RAKIB HOSSEN", content)
        self.assertIn("Canon EOS R5", content)
        self.assertIn("23.810331", content)
        self.assertIn("Google Maps Link", content)
        self.assertIn("SHA-256", content)

    def test_json_report_creation(self):
        out_json = os.path.join(self.temp_dir, "test_report.json")
        saved = generate_json_report(self.mock_data, output_path=out_json)
        self.assertTrue(os.path.exists(saved))

        with open(saved, "r", encoding="utf-8") as f:
            parsed = json.load(f)

        self.assertEqual(parsed["tool"], "RAKIB EXIF METADATA READER")
        self.assertEqual(parsed["developer"], "RAKIB HOSSEN")
        self.assertIn("analysis", parsed)
        self.assertEqual(parsed["analysis"]["file_info"]["file_name"], "forensic_target.jpg")
        self.assertEqual(parsed["analysis"]["gps_info"]["latitude"], 23.810331)


if __name__ == "__main__":
    unittest.main()
