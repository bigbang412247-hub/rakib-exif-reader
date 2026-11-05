"""
=============================================================================
RAKIB EXIF METADATA READER - GPS Geolocation Parser Module
Developer: RAKIB HOSSEN
Platform Compatibility: Kali Linux, NetHunter, Termux, Windows, Linux
=============================================================================
This module extracts, decodes, and standardizes GPS coordinates from image
EXIF metadata. Converts DMS (Degrees, Minutes, Seconds) to Decimal Degrees
(DD) with cardinal reference adjustments (N/S, E/W). Formats direct map links
(Google Maps and OpenStreetMap) and triggers privacy alerts for forensic safety.
=============================================================================
"""

from typing import Any, Dict, Optional, Tuple, Union


def _to_float(value: Any) -> float:
    """
    Safely converts varying EXIF rational representations to a standard Python float.
    Handles Pillow IFDRational, tuples (num, den), Fraction objects, ints, and floats.
    """
    if value is None:
        return 0.0

    # Handle Pillow IFDRational or objects with numerator/denominator
    if hasattr(value, "numerator") and hasattr(value, "denominator"):
        try:
            if value.denominator == 0:
                return 0.0
            return float(value.numerator) / float(value.denominator)
        except Exception:
            return float(value)

    # Handle tuple/list rational: (numerator, denominator)
    if isinstance(value, (tuple, list)):
        if len(value) == 2:
            num, den = value
            try:
                num = float(num)
                den = float(den)
                return num / den if den != 0 else 0.0
            except Exception:
                return 0.0
        elif len(value) == 1:
            return _to_float(value[0])
        elif len(value) == 0:
            return 0.0

    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _convert_dms_to_dd(
    dms: Any,
    reference: Optional[str]
) -> Optional[float]:
    """
    Converts Degrees, Minutes, Seconds (DMS) tuple into Decimal Degrees (DD).

    Formula: DD = Degrees + (Minutes / 60) + (Seconds / 3600)
    If the reference direction is South ('S') or West ('W'), the DD is negative.

    Args:
        dms: A sequence of (degrees, minutes, seconds) in various rational formats.
        reference: Direction indicator ('N', 'S', 'E', 'W').

    Returns:
        float: Decimal degrees value rounded to 6 decimal places, or None on failure.
    """
    if not dms or not isinstance(dms, (tuple, list)) or len(dms) < 3:
        return None

    try:
        degrees = _to_float(dms[0])
        minutes = _to_float(dms[1])
        seconds = _to_float(dms[2])

        decimal_degrees = degrees + (minutes / 60.0) + (seconds / 3600.0)

        if reference and isinstance(reference, str):
            ref_clean = reference.strip().upper()
            if ref_clean in ("S", "W"):
                decimal_degrees = -abs(decimal_degrees)

        return round(decimal_degrees, 6)
    except Exception:
        return None


def _format_dms_string(
    dms: Any,
    reference: Optional[str]
) -> str:
    """
    Formats DMS sequence into a readable standard format, e.g., 23° 49' 14.28" N.
    """
    if not dms or not isinstance(dms, (tuple, list)) or len(dms) < 3:
        return "Not Available"

    try:
        deg = _to_float(dms[0])
        minutes = _to_float(dms[1])
        sec = _to_float(dms[2])
        ref = reference.strip().upper() if reference else ""
        return f"{int(deg)}° {int(minutes)}' {sec:.2f}\" {ref}".strip()
    except Exception:
        return "Not Available"


def parse_gps_info(raw_gps_data: Dict[Union[int, str], Any]) -> Dict[str, Any]:
    """
    Parses raw GPS EXIF dictionary into a comprehensive forensic geolocation report.

    Args:
        raw_gps_data: Dictionary extracted from EXIF GPSInfo tag (tag 34853).
                      Keys can be either integer EXIF tag IDs or string tag names.

    Returns:
        dict: Structured dictionary containing:
            - 'has_gps': bool
            - 'latitude': float or 'Not Available'
            - 'longitude': float or 'Not Available'
            - 'latitude_ref': str or 'Not Available'
            - 'longitude_ref': str or 'Not Available'
            - 'latitude_dms': str or 'Not Available'
            - 'longitude_dms': str or 'Not Available'
            - 'altitude': str or 'Not Available'
            - 'altitude_meters': float or None
            - 'google_maps_url': str or 'Not Available'
            - 'osm_url': str or 'Not Available'
            - 'timestamp': str or 'Not Available'
            - 'privacy_warning': str or None
            - 'raw_tags': dict of all decoded tags
    """
    result: Dict[str, Any] = {
        "has_gps": False,
        "latitude": "Not Available",
        "longitude": "Not Available",
        "latitude_ref": "Not Available",
        "longitude_ref": "Not Available",
        "latitude_dms": "Not Available",
        "longitude_dms": "Not Available",
        "altitude": "Not Available",
        "altitude_meters": None,
        "google_maps_url": "Not Available",
        "osm_url": "Not Available",
        "timestamp": "Not Available",
        "privacy_warning": None,
        "raw_tags": {},
    }

    if not raw_gps_data or not isinstance(raw_gps_data, dict):
        return result

    # Standard Exif GPS Tag ID to Tag Name mapping
    gps_tag_mapping = {
        0: "GPSVersionID",
        1: "GPSLatitudeRef",
        2: "GPSLatitude",
        3: "GPSLongitudeRef",
        4: "GPSLongitude",
        5: "GPSAltitudeRef",
        6: "GPSAltitude",
        7: "GPSTimeStamp",
        8: "GPSSatellites",
        9: "GPSStatus",
        10: "GPSMeasureMode",
        11: "GPSDOP",
        12: "GPSSpeedRef",
        13: "GPSSpeed",
        14: "GPSTrackRef",
        15: "GPSTrack",
        16: "GPSImgDirectionRef",
        17: "GPSImgDirection",
        18: "GPSMapDatum",
        19: "GPSDestLatitudeRef",
        20: "GPSDestLatitude",
        21: "GPSDestLongitudeRef",
        22: "GPSDestLongitude",
        23: "GPSDestBearingRef",
        24: "GPSDestBearing",
        25: "GPSDestDistanceRef",
        26: "GPSDestDistance",
        27: "GPSProcessingMethod",
        28: "GPSAreaInformation",
        29: "GPSDateStamp",
        30: "GPSDifferential",
    }

    # Normalize raw GPS data dictionary so lookups work by string name
    normalized_gps: Dict[str, Any] = {}
    for key, val in raw_gps_data.items():
        if isinstance(key, int) and key in gps_tag_mapping:
            tag_name = gps_tag_mapping[key]
        else:
            tag_name = str(key)
        normalized_gps[tag_name] = val
        result["raw_tags"][tag_name] = str(val)

    # Extract coordinates
    lat_val = normalized_gps.get("GPSLatitude")
    lat_ref = normalized_gps.get("GPSLatitudeRef")
    lon_val = normalized_gps.get("GPSLongitude")
    lon_ref = normalized_gps.get("GPSLongitudeRef")

    lat_ref_str = str(lat_ref).strip() if lat_ref else None
    lon_ref_str = str(lon_ref).strip() if lon_ref else None

    if lat_ref_str:
        result["latitude_ref"] = lat_ref_str
    if lon_ref_str:
        result["longitude_ref"] = lon_ref_str

    lat_dd = _convert_dms_to_dd(lat_val, lat_ref_str)
    lon_dd = _convert_dms_to_dd(lon_val, lon_ref_str)

    if lat_dd is not None and lon_dd is not None:
        result["has_gps"] = True
        result["latitude"] = lat_dd
        result["longitude"] = lon_dd
        result["latitude_dms"] = _format_dms_string(lat_val, lat_ref_str)
        result["longitude_dms"] = _format_dms_string(lon_val, lon_ref_str)

        # Standard navigation links
        result["google_maps_url"] = f"https://www.google.com/maps?q={lat_dd:.6f},{lon_dd:.6f}"
        result["osm_url"] = (
            f"https://www.openstreetmap.org/?mlat={lat_dd:.6f}&mlon={lon_dd:.6f}#map=16/{lat_dd:.6f}/{lon_dd:.6f}"
        )

        # Forensic Privacy Risk Alert
        result["privacy_warning"] = (
            "[!] PRIVACY ALERT: Precise GPS geolocation coordinates detected in image metadata!\n"
            "    Publishing or sharing this file publicly can reveal physical home/work locations.\n"
            "    Recommendation: Scrub EXIF metadata prior to public distribution."
        )

    # Altitude extraction
    alt_val = normalized_gps.get("GPSAltitude")
    alt_ref = normalized_gps.get("GPSAltitudeRef")
    if alt_val is not None:
        try:
            alt_m = _to_float(alt_val)
            # alt_ref == 1 indicates below sea level
            is_below = False
            if alt_ref is not None:
                try:
                    is_below = int(alt_ref) == 1
                except Exception:
                    pass

            if is_below:
                alt_m = -abs(alt_m)

            alt_ft = alt_m * 3.28084
            result["altitude_meters"] = round(alt_m, 2)
            ref_label = "Below Sea Level" if is_below else "Above Sea Level"
            result["altitude"] = f"{alt_m:.2f} m ({alt_ft:.2f} ft) [{ref_label}]"
        except Exception:
            result["altitude"] = "Not Available"

    # Date and Time extraction from GPS
    gps_date = normalized_gps.get("GPSDateStamp")
    gps_time = normalized_gps.get("GPSTimeStamp")
    if gps_date and gps_time and isinstance(gps_time, (tuple, list)) and len(gps_time) >= 3:
        try:
            h = int(_to_float(gps_time[0]))
            m = int(_to_float(gps_time[1]))
            s = int(_to_float(gps_time[2]))
            result["timestamp"] = f"{gps_date} {h:02d}:{m:02d}:{s:02d} UTC"
        except Exception:
            if gps_date:
                result["timestamp"] = str(gps_date)
    elif gps_date:
        result["timestamp"] = str(gps_date)

    return result
