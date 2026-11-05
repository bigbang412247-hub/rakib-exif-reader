#!/usr/bin/env python3
"""
=============================================================================
RAKIB EXIF METADATA READER - Forensic Test Sample Generator
Developer: RAKIB HOSSEN
=============================================================================
Generates test images with simulated EXIF metadata and GPS coordinates
for verifying digital forensic extraction, geolocation, and hash workflows.
=============================================================================
"""

import os
from PIL import Image

try:
    import piexif
except ImportError:
    piexif = None

def create_samples(output_dir="samples"):
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Plain image without EXIF metadata
    img_plain = Image.new("RGB", (400, 300), color=(30, 144, 255))
    plain_path = os.path.join(output_dir, "sample_no_exif.jpg")
    img_plain.save(plain_path, "JPEG", quality=95)
    print(f"[+] Created plain image (no EXIF): {plain_path}")

    # 2. Image with EXIF & GPS metadata using Pillow's native Exif API (Pillow 6.0+)
    img_exif = Image.new("RGB", (800, 600), color=(46, 139, 87))
    exif = img_exif.getexif()

    # 0x010f: Make, 0x0110: Model, 0x0131: Software, 0x0132: DateTime
    exif[0x010F] = "Nikon"
    exif[0x0110] = "Nikon D850 Forensics Edition"
    exif[0x0131] = "Ver.1.20 - Rakib Forensics Lab"
    exif[0x0132] = "2026:11:02 14:32:00"

    # EXIF IFD (0x8769)
    try:
        exif_ifd = exif.get_ifd(0x8769)
        exif_ifd[0x9003] = "2026:11:02 14:30:15"  # DateTimeOriginal
        exif_ifd[0x9004] = "2026:11:02 14:30:15"  # DateTimeDigitized
        exif_ifd[0x829A] = (1, 250)                # ExposureTime: 1/250s
        exif_ifd[0x829D] = (28, 10)                # FNumber: f/2.8
        exif_ifd[0x8827] = 400                     # ISOSpeedRatings: 400
        exif_ifd[0x920A] = (500, 10)               # FocalLength: 50.0mm
        exif_ifd[0xA434] = "NIKKOR 50mm f/1.8G"   # LensModel
    except Exception as e:
        print(f"[*] Note on EXIF IFD: {e}")

    # GPS IFD (0x8825)
    # Coordinates: Dhaka, Bangladesh: 23° 48' 49.32" N, 90° 24' 45.07" E
    try:
        gps_ifd = exif.get_ifd(0x8825)
        gps_ifd[1] = "N"                                     # GPSLatitudeRef
        gps_ifd[2] = ((23, 1), (48, 1), (4932, 100))        # GPSLatitude
        gps_ifd[3] = "E"                                     # GPSLongitudeRef
        gps_ifd[4] = ((90, 1), (24, 1), (4507, 100))        # GPSLongitude
        gps_ifd[5] = 0                                       # GPSAltitudeRef (above sea level)
        gps_ifd[6] = (1450, 100)                             # GPSAltitude (14.5 meters)
        gps_ifd[7] = ((8, 1), (30, 1), (15, 1))              # GPSTimeStamp
        gps_ifd[29] = "2026:11:02"                           # GPSDateStamp
    except Exception as e:
        print(f"[*] Note on GPS IFD: {e}")

    gps_path = os.path.join(output_dir, "sample_with_gps.jpg")
    img_exif.save(gps_path, "JPEG", exif=exif, quality=95)
    print(f"[+] Created image with simulated EXIF & GPS: {gps_path}")

    # 3. Second sample with different GPS location (Sundarbans, Bangladesh: 21° 56' 57" N, 89° 10' 48" E)
    img_drone = Image.new("RGB", (640, 480), color=(178, 34, 34))
    exif_drone = img_drone.getexif()
    exif_drone[0x010F] = "DJI"
    exif_drone[0x0110] = "Mavic 3 Enterprise Forensics"
    exif_drone[0x0131] = "DJI Fly 1.9.0"
    try:
        gps_d = exif_drone.get_ifd(0x8825)
        gps_d[1] = "N"
        gps_d[2] = ((21, 1), (56, 1), (5700, 100))
        gps_d[3] = "E"
        gps_d[4] = ((89, 1), (10, 1), (4800, 100))
        gps_d[5] = 0
        gps_d[6] = (12050, 100)  # 120.5 meters drone altitude
        gps_d[7] = ((11, 1), (15, 1), (45, 1))
        gps_d[29] = "2026:11:02"
    except Exception:
        pass

    drone_path = os.path.join(output_dir, "sample_drone_surveillance.jpg")
    img_drone.save(drone_path, "JPEG", exif=exif_drone, quality=95)
    print(f"[+] Created drone surveillance sample: {drone_path}")
    print("[*] Sample generation finished successfully.")

if __name__ == "__main__":
    create_samples()
