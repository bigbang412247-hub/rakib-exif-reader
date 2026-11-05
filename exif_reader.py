"""
=============================================================================
RAKIB EXIF METADATA READER - Core EXIF Extraction Engine
Developer: RAKIB HOSSEN
Platform Compatibility: Kali Linux, NetHunter, Termux, Windows, Linux
=============================================================================
This module handles low-level image file analysis and EXIF metadata extraction.
It safely parses EXIF IFD tags, camera manufacturer details, shooting settings,
timestamps, and GPS blocks using Pillow while gracefully handling images with
missing, corrupted, or non-standard metadata.
=============================================================================
"""

import math
import mimetypes
import os
from fractions import Fraction
from typing import Any, Dict, Optional, Tuple, Union

# Attempt Pillow import with clear diagnostic flag
try:
    from PIL import Image, ExifTags
    from PIL.ExifTags import TAGS, GPSTAGS
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False
    TAGS = {}
    GPSTAGS = {}

from gps_parser import parse_gps_info, _to_float
from hash_utils import calculate_hashes


def format_bytes(size_bytes: int) -> str:
    """Formats raw byte counts into human-readable strings (KB, MB, GB)."""
    if size_bytes <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {units[i]}"


def _format_exposure_time(val: Any) -> str:
    """Formats exposure time into standard photographic notation, e.g., 1/250s."""
    if val is None:
        return "Not Available"
    try:
        f_val = _to_float(val)
        if f_val <= 0:
            return "Not Available"
        if f_val < 1.0:
            frac = Fraction(f_val).limit_denominator(8000)
            return f"1/{round(1.0 / f_val)}s ({frac}s)"
        return f"{f_val:.2f}s"
    except Exception:
        return str(val)


def _format_fnumber(val: Any) -> str:
    """Formats aperture into standard notation, e.g., f/2.8."""
    if val is None:
        return "Not Available"
    try:
        f_val = _to_float(val)
        if f_val <= 0:
            return "Not Available"
        return f"f/{f_val:.1f}"
    except Exception:
        return str(val)


def _format_focal_length(val: Any) -> str:
    """Formats focal length into millimeter notation, e.g., 50.0 mm."""
    if val is None:
        return "Not Available"
    try:
        f_val = _to_float(val)
        if f_val <= 0:
            return "Not Available"
        return f"{f_val:.1f} mm"
    except Exception:
        return str(val)


def get_image_info(image_path: str) -> Dict[str, Any]:
    """
    Extracts fundamental filesystem and image format properties.

    Args:
        image_path (str): File system path to the image.

    Returns:
        dict: Basic image properties and integrity hashes.
    """
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"File not found: {image_path}")

    file_size_bytes = os.path.getsize(image_path)
    file_name = os.path.basename(image_path)
    file_ext = os.path.splitext(file_name)[1].lower()

    # Determine MIME type
    mime_type, _ = mimetypes.guess_type(image_path)
    if not mime_type:
        mime_map = {
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".webp": "image/webp",
            ".tiff": "image/tiff",
            ".tif": "image/tiff",
            ".bmp": "image/bmp",
            ".gif": "image/gif",
        }
        mime_type = mime_map.get(file_ext, "application/octet-stream")

    # Cryptographic file hashes
    hashes = calculate_hashes(image_path)

    # Basic Pillow dimensions & color mode extraction
    format_name = "Unknown"
    dimensions = "Not Available"
    color_mode = "Not Available"
    aspect_ratio = "Not Available"

    if PILLOW_AVAILABLE:
        try:
            with Image.open(image_path) as img:
                format_name = img.format or file_ext.replace(".", "").upper()
                width, height = img.size
                dimensions = f"{width} x {height} pixels"
                color_mode = img.mode or "Not Available"
                if height > 0:
                    gcd = math.gcd(width, height)
                    aspect_ratio = f"{width // gcd}:{height // gcd} ({width / height:.2f}:1)"
        except Exception:
            pass

    return {
        "file_name": file_name,
        "file_path": os.path.abspath(image_path),
        "file_size": f"{format_bytes(file_size_bytes)} ({file_size_bytes:,} bytes)",
        "file_size_bytes": file_size_bytes,
        "mime_type": mime_type,
        "image_format": format_name,
        "dimensions": dimensions,
        "color_mode": color_mode,
        "aspect_ratio": aspect_ratio,
        "hashes": hashes,
    }


def extract_metadata(image_path: str) -> Dict[str, Any]:
    """
    Comprehensively extracts and parses EXIF metadata, camera settings,
    shooting parameters, and embedded GPS records from an image.

    Args:
        image_path (str): Target image path.

    Returns:
        dict: Complete structured analysis dictionary.
    """
    if not PILLOW_AVAILABLE:
        raise RuntimeError(
            "Pillow library is not installed.\n"
            "Please install it using: pip3 install Pillow"
        )

    # Base image properties and hashes
    info = get_image_info(image_path)

    raw_exif_dict: Dict[str, Any] = {}
    gps_raw_dict: Dict[Any, Any] = {}
    has_exif = False

    try:
        with Image.open(image_path) as img:
            # Attempt modern getexif() API (Pillow 6+)
            exif_obj = None
            if hasattr(img, "getexif"):
                try:
                    exif_obj = img.getexif()
                except Exception:
                    exif_obj = None

            # Fallback to legacy _getexif() for JPEG
            if not exif_obj and hasattr(img, "_getexif"):
                try:
                    exif_obj = img._getexif()
                except Exception:
                    exif_obj = None

            if exif_obj:
                for tag_id, val in exif_obj.items():
                    tag_name = TAGS.get(tag_id, str(tag_id))
                    # Handle GPSInfo IFD (tag 34853)
                    if tag_id == 34853 or tag_name == "GPSInfo":
                        has_exif = True
                        if isinstance(val, dict):
                            gps_raw_dict = val
                        elif hasattr(exif_obj, "get_ifd"):
                            try:
                                gps_raw_dict = dict(exif_obj.get_ifd(34853))
                            except Exception:
                                pass
                        continue

                    # Check for EXIF IFD sub-dictionary (tag 34665)
                    if tag_id == 34665 and hasattr(exif_obj, "get_ifd"):
                        try:
                            sub_ifd = exif_obj.get_ifd(34665)
                            for sub_id, sub_val in sub_ifd.items():
                                sub_name = TAGS.get(sub_id, str(sub_id))
                                raw_exif_dict[sub_name] = sub_val
                        except Exception:
                            pass

                    # Clean string conversion for display
                    if isinstance(val, bytes):
                        try:
                            clean_val = val.decode("utf-8", errors="replace").strip("\x00")
                        except Exception:
                            clean_val = str(val)
                    else:
                        clean_val = val

                    raw_exif_dict[tag_name] = clean_val
                    has_exif = True

            # If GPS sub-dictionary wasn't loaded from modern API, check legacy
            if not gps_raw_dict and hasattr(img, "_getexif"):
                try:
                    legacy_exif = img._getexif()
                    if legacy_exif and 34853 in legacy_exif:
                        gps_raw_dict = legacy_exif[34853]
                except Exception:
                    pass

    except Exception as e:
        # File is either corrupted or not an image
        return {
            "file_info": info,
            "has_exif": False,
            "has_gps": False,
            "error": f"Failed to parse image EXIF: {str(e)}",
            "camera_info": _build_empty_camera_info(),
            "gps_info": parse_gps_info({}),
            "all_tags": {},
        }

    # Parse GPS data through dedicated module
    gps_result = parse_gps_info(gps_raw_dict)
    if gps_result["has_gps"]:
        has_exif = True

    # Build standardized camera & capture settings
    camera_info = {
        "make": raw_exif_dict.get("Make", "Not Available"),
        "model": raw_exif_dict.get("Model", "Not Available"),
        "software": raw_exif_dict.get("Software", "Not Available"),
        "datetime_original": raw_exif_dict.get("DateTimeOriginal", "Not Available"),
        "datetime_digitized": raw_exif_dict.get("DateTimeDigitized", "Not Available"),
        "datetime_modified": raw_exif_dict.get("DateTime", "Not Available"),
        "exposure_time": _format_exposure_time(raw_exif_dict.get("ExposureTime")),
        "iso": str(raw_exif_dict.get("ISOSpeedRatings") or raw_exif_dict.get("PhotographicSensitivity") or "Not Available"),
        "aperture": _format_fnumber(raw_exif_dict.get("FNumber") or raw_exif_dict.get("ApertureValue")),
        "focal_length": _format_focal_length(raw_exif_dict.get("FocalLength")),
        "focal_length_35mm": str(raw_exif_dict.get("FocalLengthIn35mmFilm", "Not Available")),
        "lens_make": str(raw_exif_dict.get("LensMake", "Not Available")),
        "lens_model": str(raw_exif_dict.get("LensModel", "Not Available")),
        "shutter_speed": str(raw_exif_dict.get("ShutterSpeedValue", "Not Available")),
        "exposure_program": str(raw_exif_dict.get("ExposureProgram", "Not Available")),
        "exposure_bias": str(raw_exif_dict.get("ExposureBiasValue", "Not Available")),
        "metering_mode": str(raw_exif_dict.get("MeteringMode", "Not Available")),
        "flash": str(raw_exif_dict.get("Flash", "Not Available")),
        "white_balance": str(raw_exif_dict.get("WhiteBalance", "Not Available")),
        "orientation": str(raw_exif_dict.get("Orientation", "Not Available")),
        "artist": str(raw_exif_dict.get("Artist", "Not Available")),
        "copyright": str(raw_exif_dict.get("Copyright", "Not Available")),
    }

    # Format all tags safely for raw output
    sanitized_all_tags: Dict[str, str] = {}
    for k, v in raw_exif_dict.items():
        if isinstance(v, bytes):
            try:
                sanitized_all_tags[str(k)] = v.decode("utf-8", errors="replace").strip("\x00")
            except Exception:
                sanitized_all_tags[str(k)] = str(v)
        else:
            sanitized_all_tags[str(k)] = str(v)

    return {
        "file_info": info,
        "has_exif": has_exif,
        "has_gps": gps_result["has_gps"],
        "camera_info": camera_info,
        "gps_info": gps_result,
        "all_tags": sanitized_all_tags,
        "error": None,
    }


def _build_empty_camera_info() -> Dict[str, str]:
    """Returns a dictionary filled with 'Not Available' for when EXIF is absent."""
    return {
        "make": "Not Available",
        "model": "Not Available",
        "software": "Not Available",
        "datetime_original": "Not Available",
        "datetime_digitized": "Not Available",
        "datetime_modified": "Not Available",
        "exposure_time": "Not Available",
        "iso": "Not Available",
        "aperture": "Not Available",
        "focal_length": "Not Available",
        "focal_length_35mm": "Not Available",
        "lens_make": "Not Available",
        "lens_model": "Not Available",
        "shutter_speed": "Not Available",
        "exposure_program": "Not Available",
        "exposure_bias": "Not Available",
        "metering_mode": "Not Available",
        "flash": "Not Available",
        "white_balance": "Not Available",
        "orientation": "Not Available",
        "artist": "Not Available",
        "copyright": "Not Available",
    }
