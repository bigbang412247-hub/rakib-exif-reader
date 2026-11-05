"""
=============================================================================
RAKIB EXIF METADATA READER - Forensic Report Generation Module
Developer: RAKIB HOSSEN
Platform Compatibility: Kali Linux, NetHunter, Termux, Windows, Linux
=============================================================================
This module generates standardized digital forensics reports in both TXT and
JSON formats. Reports are automatically organized and saved in the 'reports/'
directory with cryptographic timestamps and file integrity checksums.
=============================================================================
"""

import json
import os
import re
from datetime import datetime
from typing import Any, Dict, Optional


DEFAULT_REPORT_DIR = "reports"


def _ensure_report_dir(output_dir: str = DEFAULT_REPORT_DIR) -> str:
    """Ensures destination reports folder exists."""
    os.makedirs(output_dir, exist_ok=True)
    return output_dir


def _sanitize_filename(name: str) -> str:
    """Sanitizes filename for safe storage across Windows, Linux, and Android/Termux."""
    clean = re.sub(r'[\\/*?:"<>| ]', "_", name)
    return clean[:60]


def generate_txt_report(
    analysis_data: Dict[str, Any],
    output_path: Optional[str] = None,
    output_dir: str = DEFAULT_REPORT_DIR
) -> str:
    """
    Renders and saves a forensic-grade ASCII plain text report.

    Args:
        analysis_data (dict): Result dictionary from extract_metadata().
        output_path (str, optional): Custom destination file path.
        output_dir (str): Folder where reports are saved if output_path is None.

    Returns:
        str: Absolute path to the generated TXT report.
    """
    _ensure_report_dir(output_dir)

    file_info = analysis_data.get("file_info", {})
    hashes = file_info.get("hashes", {})
    camera = analysis_data.get("camera_info", {})
    gps = analysis_data.get("gps_info", {})
    raw_tags = analysis_data.get("all_tags", {})
    has_exif = analysis_data.get("has_exif", False)
    has_gps = analysis_data.get("has_gps", False)
    error = analysis_data.get("error")

    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    timestamp_slug = datetime.now().strftime("%Y%m%d_%H%M%S")

    base_name = file_info.get("file_name", "image")
    safe_base = _sanitize_filename(os.path.splitext(base_name)[0])

    if not output_path:
        filename = f"report_{safe_base}_{timestamp_slug}.txt"
        output_path = os.path.join(output_dir, filename)

    line_sep = "=" * 78
    sub_sep = "-" * 78

    lines = [
        line_sep,
        "              RAKIB EXIF METADATA READER - FORENSIC REPORT",
        "                         DEVELOPER: RAKIB HOSSEN",
        line_sep,
        f"Generated At    : {timestamp_str}",
        f"Analysis Status : {'EXIF Metadata Detected' if has_exif else 'No EXIF Metadata Found'}",
        line_sep,
        "",
        "[ 1. FILE & INTEGRITY INFORMATION ]",
        sub_sep,
        f"  File Name         : {file_info.get('file_name', 'Not Available')}",
        f"  File Path         : {file_info.get('file_path', 'Not Available')}",
        f"  File Size         : {file_info.get('file_size', 'Not Available')}",
        f"  Image Format      : {file_info.get('image_format', 'Not Available')}",
        f"  Image Dimensions  : {file_info.get('dimensions', 'Not Available')}",
        f"  Aspect Ratio      : {file_info.get('aspect_ratio', 'Not Available')}",
        f"  Color Mode        : {file_info.get('color_mode', 'Not Available')}",
        f"  MIME Type         : {file_info.get('mime_type', 'Not Available')}",
        "",
        "[ 2. CRYPTOGRAPHIC HASHES (INTEGRITY CHECK) ]",
        sub_sep,
        f"  SHA-256 : {hashes.get('sha256', 'Not Available')}",
        f"  SHA-1   : {hashes.get('sha1', 'Not Available')}",
        f"  MD5     : {hashes.get('md5', 'Not Available')}",
        "",
        "[ 3. CAMERA & DEVICE METADATA ]",
        sub_sep,
        f"  Manufacturer (Make) : {camera.get('make', 'Not Available')}",
        f"  Camera Model        : {camera.get('model', 'Not Available')}",
        f"  Software / Firmware : {camera.get('software', 'Not Available')}",
        f"  Date & Time Original: {camera.get('datetime_original', 'Not Available')}",
        f"  Date & Time Digitize: {camera.get('datetime_digitized', 'Not Available')}",
        f"  Date & Time Modified: {camera.get('datetime_modified', 'Not Available')}",
        f"  Artist / Author     : {camera.get('artist', 'Not Available')}",
        f"  Copyright Notice    : {camera.get('copyright', 'Not Available')}",
        "",
        "[ 4. PHOTOGRAPHIC SHOOTING PARAMETERS ]",
        sub_sep,
        f"  Exposure Time       : {camera.get('exposure_time', 'Not Available')}",
        f"  Aperture (F-Stop)   : {camera.get('aperture', 'Not Available')}",
        f"  ISO Speed Rating    : {camera.get('iso', 'Not Available')}",
        f"  Focal Length        : {camera.get('focal_length', 'Not Available')}",
        f"  Focal Length (35mm) : {camera.get('focal_length_35mm', 'Not Available')}",
        f"  Lens Make           : {camera.get('lens_make', 'Not Available')}",
        f"  Lens Model          : {camera.get('lens_model', 'Not Available')}",
        f"  Exposure Program    : {camera.get('exposure_program', 'Not Available')}",
        f"  Exposure Bias Value : {camera.get('exposure_bias', 'Not Available')}",
        f"  Metering Mode       : {camera.get('metering_mode', 'Not Available')}",
        f"  Flash Status        : {camera.get('flash', 'Not Available')}",
        f"  White Balance       : {camera.get('white_balance', 'Not Available')}",
        f"  Orientation         : {camera.get('orientation', 'Not Available')}",
        "",
        "[ 5. GPS GEOLOCATION INFORMATION ]",
        sub_sep,
    ]

    if has_gps:
        lines.extend([
            f"  GPS Latitude (DD)   : {gps.get('latitude', 'Not Available')}",
            f"  GPS Longitude (DD)  : {gps.get('longitude', 'Not Available')}",
            f"  Latitude (DMS)      : {gps.get('latitude_dms', 'Not Available')}",
            f"  Longitude (DMS)     : {gps.get('longitude_dms', 'Not Available')}",
            f"  GPS Altitude        : {gps.get('altitude', 'Not Available')}",
            f"  GPS Timestamp       : {gps.get('timestamp', 'Not Available')}",
            f"  Google Maps Link    : {gps.get('google_maps_url', 'Not Available')}",
            f"  OpenStreetMap Link  : {gps.get('osm_url', 'Not Available')}",
            "",
            "  >>> PRIVACY WARNING <<<",
            "  " + gps.get("privacy_warning", "").replace("\n", "\n  "),
        ])
    else:
        lines.append("  GPS Information     : Not Available (No Geotag Found)")

    lines.extend([
        "",
        "[ 6. COMPLETE RAW EXIF DUMP ]",
        sub_sep,
    ])

    if raw_tags:
        for tag_name in sorted(raw_tags.keys()):
            lines.append(f"  {tag_name:<28} : {raw_tags[tag_name]}")
    else:
        lines.append("  No additional raw EXIF tags found.")

    if error:
        lines.extend([
            "",
            "[ ANALYSIS ANOMALIES / ERRORS ]",
            sub_sep,
            f"  {error}",
        ])

    lines.extend([
        "",
        line_sep,
        "                    END OF FORENSIC METADATA REPORT",
        "  CONFIDENTIALITY NOTICE: This report was processed 100% locally.",
        "  Zero external requests were dispatched. The original image was not modified.",
        line_sep,
    ])

    content = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    return os.path.abspath(output_path)


def generate_json_report(
    analysis_data: Dict[str, Any],
    output_path: Optional[str] = None,
    output_dir: str = DEFAULT_REPORT_DIR
) -> str:
    """
    Serializes and saves metadata analysis in structured JSON format.

    Args:
        analysis_data (dict): Result dictionary from extract_metadata().
        output_path (str, optional): Custom destination file path.
        output_dir (str): Folder where reports are saved if output_path is None.

    Returns:
        str: Absolute path to the generated JSON report.
    """
    _ensure_report_dir(output_dir)

    file_info = analysis_data.get("file_info", {})
    base_name = file_info.get("file_name", "image")
    safe_base = _sanitize_filename(os.path.splitext(base_name)[0])
    timestamp_slug = datetime.now().strftime("%Y%m%d_%H%M%S")

    if not output_path:
        filename = f"report_{safe_base}_{timestamp_slug}.json"
        output_path = os.path.join(output_dir, filename)

    payload = {
        "tool": "RAKIB EXIF METADATA READER",
        "developer": "RAKIB HOSSEN",
        "report_generated_at": datetime.now().isoformat(),
        "privacy_notice": "Processed 100% locally. Zero remote telemetry. No file modification.",
        "analysis": analysis_data,
    }

    def _json_serial(obj: Any) -> Any:
        """Handles non-serializable objects cleanly."""
        try:
            return float(obj)
        except Exception:
            return str(obj)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=4, default=_json_serial, ensure_ascii=False)

    return os.path.abspath(output_path)
