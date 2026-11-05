#!/usr/bin/env python3
"""
=============================================================================
RAKIB EXIF METADATA READER
Developer: RAKIB HOSSEN
Platform Compatibility: Kali Linux, NetHunter Rootless, Termux, Windows, Linux
Version: 1.0.0
=============================================================================
Main executable entrypoint providing an interactive forensic terminal user
interface (CLI) and scriptable command-line arguments for automated pipelines.
=============================================================================
"""

import argparse
import glob
import os
import sys
import time
from typing import Any, Dict, List, Optional

# ANSI Color Codes & Styles
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"

    # Standard Foreground
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Bright Foreground
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

    # Backgrounds
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_DARK = "\033[40m"


# Windows VT100 ANSI activation
if os.name == "nt":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # Enable ENABLE_VIRTUAL_TERMINAL_PROCESSING
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


def check_dependencies() -> bool:
    """Verifies that Pillow is installed and provides friendly diagnostics."""
    try:
        import PIL
        return True
    except ImportError:
        clear_screen()
        print(f"{Colors.BRIGHT_RED}{Colors.BOLD}[!] MISSING DEPENDENCY: Pillow is not installed!{Colors.RESET}\n")
        print(f"{Colors.YELLOW}Please install the required dependency using one of the following commands:{Colors.RESET}\n")
        print(f"  {Colors.CYAN}Standard Linux / Windows :{Colors.RESET} pip3 install -r requirements.txt")
        print(f"  {Colors.CYAN}Kali Linux / Debian       :{Colors.RESET} sudo apt-get install python3-pil")
        print(f"  {Colors.CYAN}Termux (Android)          :{Colors.RESET} pkg install python-pillow")
        print(f"  {Colors.CYAN}Kali NetHunter Rootless   :{Colors.RESET} sudo apt update && sudo apt install python3-pil\n")
        return False


# Import project modules safely
try:
    from exif_reader import extract_metadata, get_image_info
    from hash_utils import calculate_hashes, get_sha256
    from report_generator import generate_txt_report, generate_json_report
except ImportError as err:
    print(f"{Colors.RED}Module Import Error: {err}{Colors.RESET}")
    print("Ensure you run the application from its root directory.")
    sys.exit(1)


def clear_screen() -> None:
    """Cleans terminal screen across Windows, Linux, and Termux."""
    os.system("cls" if os.name == "nt" else "clear")


def show_spinner(duration: float = 0.5, message: str = "Processing") -> None:
    """Renders a responsive terminal spinner animation."""
    spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    end_time = time.time() + duration
    idx = 0
    while time.time() < end_time:
        char = spinner_chars[idx % len(spinner_chars)]
        sys.stdout.write(f"\r  {Colors.BRIGHT_CYAN}{char}{Colors.RESET} {Colors.WHITE}{message}...{Colors.RESET}")
        sys.stdout.flush()
        time.sleep(0.08)
        idx += 1
    sys.stdout.write("\r" + " " * (len(message) + 12) + "\r")
    sys.stdout.flush()


def print_banner() -> None:
    """Displays the application's signature forensic ASCII banner."""
    banner = f"""{Colors.BRIGHT_CYAN}{Colors.BOLD}
  ██████╗  █████╗ ██╗  ██╗██╗██████╗     ███████╗██╗   ██╗██╗███████╗
  ██╔══██╗██╔══██╗██║ ██╔╝██║██╔══██╗    ██╔════╝██║   ██║██║██╔════╝
  ██████╔╝███████║█████╔╝ ██║██████╔╝    █████╗  ██║   ██║██║█████╗  
  ██╔══██╗██╔══██║██╔═██╗ ██║██╔══██╗    ██╔══╝  ╚██╗ ██╔╝██║██╔══╝  
  ██║  ██║██║  ██║██║  ██╗██║██████╔╝    ███████╗ ╚████╔╝ ██║██║     
  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═════╝     ╚══════╝  ╚═══╝  ╚═╝╚═╝     
{Colors.BRIGHT_YELLOW}            E X I F   M E T A D A T A   R E A D E R{Colors.RESET}
{Colors.CYAN}       Digital Forensics & Geolocation Analysis Toolkit v1.0.0{Colors.RESET}
{Colors.DIM}------------------------------------------------------------------------
  Developer: {Colors.BRIGHT_GREEN}RAKIB HOSSEN{Colors.RESET}{Colors.DIM} | Platform: Kali • NetHunter • Termux • Win • Linux
  Privacy  : {Colors.BRIGHT_WHITE}100% Offline Analysis • Zero Data Transmission • Read-Only{Colors.RESET}
{Colors.DIM}------------------------------------------------------------------------{Colors.RESET}
"""
    print(banner)


def display_privacy_warning() -> None:
    """Highlights geolocation privacy threat when GPS tags are detected."""
    print(f"\n{Colors.BG_RED}{Colors.BRIGHT_WHITE}{Colors.BOLD} [!] CRITICAL PRIVACY ALERT: GPS METADATA DETECTED! {Colors.RESET}")
    print(f"{Colors.BRIGHT_YELLOW}  Exact geographic coordinates were recovered from this image.{Colors.RESET}")
    print(f"{Colors.YELLOW}  Sharing this raw image exposes physical residence, workplace, or route.{Colors.RESET}")
    print(f"{Colors.YELLOW}  Forensic recommendation: Strip EXIF tags before public release.{Colors.RESET}\n")


def display_analysis_summary(data: Dict[str, Any]) -> None:
    """Nicely formats full image analysis onto the terminal."""
    f_info = data.get("file_info", {})
    hashes = f_info.get("hashes", {})
    cam = data.get("camera_info", {})
    gps = data.get("gps_info", {})
    has_exif = data.get("has_exif", False)
    has_gps = data.get("has_gps", False)

    print(f"\n{Colors.BRIGHT_BLUE}{Colors.BOLD}┌── [ 1. FILE & FORMAT INFORMATION ]{Colors.RESET}")
    print(f"│ {Colors.WHITE}File Name        :{Colors.RESET} {Colors.BRIGHT_CYAN}{f_info.get('file_name')}{Colors.RESET}")
    print(f"│ {Colors.WHITE}File Path        :{Colors.RESET} {Colors.DIM}{f_info.get('file_path')}{Colors.RESET}")
    print(f"│ {Colors.WHITE}File Size        :{Colors.RESET} {f_info.get('file_size')}")
    print(f"│ {Colors.WHITE}Image Format     :{Colors.RESET} {Colors.BRIGHT_GREEN}{f_info.get('image_format')}{Colors.RESET}")
    print(f"│ {Colors.WHITE}Dimensions       :{Colors.RESET} {f_info.get('dimensions')} ({f_info.get('aspect_ratio')})")
    print(f"│ {Colors.WHITE}Color Mode       :{Colors.RESET} {f_info.get('color_mode')}")
    print(f"│ {Colors.WHITE}MIME Type        :{Colors.RESET} {f_info.get('mime_type')}")

    print(f"{Colors.BRIGHT_BLUE}{Colors.BOLD}├── [ 2. CRYPTOGRAPHIC CHECKSUMS (INTEGRITY) ]{Colors.RESET}")
    print(f"│ {Colors.WHITE}SHA-256          :{Colors.RESET} {Colors.BRIGHT_YELLOW}{hashes.get('sha256')}{Colors.RESET}")
    print(f"│ {Colors.WHITE}SHA-1            :{Colors.RESET} {hashes.get('sha1')}")
    print(f"│ {Colors.WHITE}MD5              :{Colors.RESET} {hashes.get('md5')}")

    print(f"{Colors.BRIGHT_BLUE}{Colors.BOLD}├── [ 3. CAMERA & DEVICE METADATA ]{Colors.RESET}")
    if has_exif:
        print(f"│ {Colors.WHITE}Manufacturer     :{Colors.RESET} {Colors.BRIGHT_WHITE}{cam.get('make')}{Colors.RESET}")
        print(f"│ {Colors.WHITE}Model            :{Colors.RESET} {Colors.BRIGHT_WHITE}{cam.get('model')}{Colors.RESET}")
        print(f"│ {Colors.WHITE}Software         :{Colors.RESET} {cam.get('software')}")
        print(f"│ {Colors.WHITE}Date/Time (Orig) :{Colors.RESET} {Colors.BRIGHT_GREEN}{cam.get('datetime_original')}{Colors.RESET}")
        print(f"│ {Colors.WHITE}Date/Time (Digit):{Colors.RESET} {cam.get('datetime_digitized')}")
        print(f"│ {Colors.WHITE}Date/Time (Mod)  :{Colors.RESET} {cam.get('datetime_modified')}")

        print(f"{Colors.BRIGHT_BLUE}{Colors.BOLD}├── [ 4. SHOOTING & EXPOSURE PARAMETERS ]{Colors.RESET}")
        print(f"│ {Colors.WHITE}Exposure Time    :{Colors.RESET} {cam.get('exposure_time')}")
        print(f"│ {Colors.WHITE}Aperture (F-Stop):{Colors.RESET} {cam.get('aperture')}")
        print(f"│ {Colors.WHITE}ISO Speed        :{Colors.RESET} {cam.get('iso')}")
        print(f"│ {Colors.WHITE}Focal Length     :{Colors.RESET} {cam.get('focal_length')} (35mm equiv: {cam.get('focal_length_35mm')})")
        print(f"│ {Colors.WHITE}Lens Model       :{Colors.RESET} {cam.get('lens_model')}")
        print(f"│ {Colors.WHITE}Metering Mode    :{Colors.RESET} {cam.get('metering_mode')}")
        print(f"│ {Colors.WHITE}Flash            :{Colors.RESET} {cam.get('flash')}")
        print(f"│ {Colors.WHITE}White Balance    :{Colors.RESET} {cam.get('white_balance')}")
    else:
        print(f"│ {Colors.YELLOW}Status           : No EXIF metadata block found in this image.{Colors.RESET}")

    print(f"{Colors.BRIGHT_BLUE}{Colors.BOLD}└── [ 5. GPS GEOLOCATION DATA ]{Colors.RESET}")
    if has_gps:
        display_privacy_warning()
        print(f"  {Colors.WHITE}Latitude (DD)    :{Colors.RESET} {Colors.BRIGHT_GREEN}{gps.get('latitude')}{Colors.RESET}")
        print(f"  {Colors.WHITE}Longitude (DD)   :{Colors.RESET} {Colors.BRIGHT_GREEN}{gps.get('longitude')}{Colors.RESET}")
        print(f"  {Colors.WHITE}Latitude (DMS)   :{Colors.RESET} {gps.get('latitude_dms')}")
        print(f"  {Colors.WHITE}Longitude (DMS)  :{Colors.RESET} {gps.get('longitude_dms')}")
        print(f"  {Colors.WHITE}Altitude         :{Colors.RESET} {gps.get('altitude')}")
        print(f"  {Colors.WHITE}GPS Timestamp    :{Colors.RESET} {gps.get('timestamp')}")
        print(f"  {Colors.WHITE}Google Maps Link :{Colors.RESET} {Colors.BRIGHT_CYAN}{Colors.UNDERLINE}{gps.get('google_maps_url')}{Colors.RESET}")
        print(f"  {Colors.WHITE}OpenStreetMap    :{Colors.RESET} {Colors.DIM}{gps.get('osm_url')}{Colors.RESET}")
    else:
        print(f"  {Colors.WHITE}GPS Status       :{Colors.RESET} {Colors.DIM}Not Available (No embedded GPS coordinates){Colors.RESET}")

    print()


def display_raw_exif(data: Dict[str, Any]) -> None:
    """Displays raw decoded EXIF tags."""
    all_tags = data.get("all_tags", {})
    if not all_tags:
        print(f"\n{Colors.YELLOW}[!] No raw EXIF tags found for this image.{Colors.RESET}\n")
        return

    print(f"\n{Colors.BRIGHT_CYAN}{Colors.BOLD}=== RAW EXIF METADATA TAGS ({len(all_tags)} TAGS) ==={Colors.RESET}")
    print(f"{Colors.DIM}{'TAG NAME':<32} {'VALUE'}{Colors.RESET}")
    print(f"{Colors.DIM}{'-'*70}{Colors.RESET}")
    for tag_name in sorted(all_tags.keys()):
        val_str = str(all_tags[tag_name])
        if len(val_str) > 75:
            val_str = val_str[:72] + "..."
        print(f"{Colors.WHITE}{tag_name:<32}{Colors.RESET} : {Colors.BRIGHT_WHITE}{val_str}{Colors.RESET}")
    print(f"{Colors.DIM}{'-'*70}{Colors.RESET}\n")


def prompt_image_path(default: Optional[str] = None) -> Optional[str]:
    """Prompts user for image path with validation."""
    prompt_text = f"{Colors.BRIGHT_CYAN}Enter Image Path"
    if default:
        prompt_text += f" [{Colors.WHITE}{os.path.basename(default)}{Colors.BRIGHT_CYAN}]"
    prompt_text += f": {Colors.RESET}"

    path = input(prompt_text).strip().strip("'\"")
    if not path and default:
        return default

    if not path:
        print(f"{Colors.RED}[!] Error: No path provided.{Colors.RESET}")
        return None

    if not os.path.exists(path):
        print(f"{Colors.RED}[!] Error: File does not exist: {path}{Colors.RESET}")
        return None

    if not os.path.isfile(path):
        print(f"{Colors.RED}[!] Error: Path is not a regular file: {path}{Colors.RESET}")
        return None

    return path


def prompt_folder_path() -> Optional[str]:
    """Prompts user for directory path with validation."""
    prompt_text = f"{Colors.BRIGHT_CYAN}Enter Image Folder Path: {Colors.RESET}"
    path = input(prompt_text).strip().strip("'\"")
    if not path:
        print(f"{Colors.RED}[!] Error: No folder path provided.{Colors.RESET}")
        return None

    if not os.path.exists(path):
        print(f"{Colors.RED}[!] Error: Directory does not exist: {path}{Colors.RESET}")
        return None

    if not os.path.isdir(path):
        print(f"{Colors.RED}[!] Error: Path is not a directory: {path}{Colors.RESET}")
        return None

    return path


def action_analyze_single(current_path: Optional[str]) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """Handles Single Image Analysis workflow."""
    img_path = prompt_image_path(current_path)
    if not img_path:
        return current_path, None

    show_spinner(0.5, "Analyzing image metadata and computing cryptographic hashes")
    try:
        data = extract_metadata(img_path)
        display_analysis_summary(data)
        return img_path, data
    except Exception as exc:
        print(f"\n{Colors.RED}[!] Analysis Failed: {exc}{Colors.RESET}\n")
        return current_path, None


def action_batch_analysis() -> None:
    """Handles folder batch analysis and per-image report generation."""
    folder_path = prompt_folder_path()
    if not folder_path:
        return

    # Supported image extensions
    valid_extensions = (".jpg", ".jpeg", ".png", ".webp", ".tiff", ".tif", ".bmp")
    image_files: List[str] = []

    for entry in os.listdir(folder_path):
        full = os.path.join(folder_path, entry)
        if os.path.isfile(full) and entry.lower().endswith(valid_extensions):
            image_files.append(full)

    if not image_files:
        print(f"\n{Colors.YELLOW}[!] No supported images found in '{folder_path}'{Colors.RESET}")
        print(f"Supported extensions: {', '.join(valid_extensions)}\n")
        return

    print(f"\n{Colors.BRIGHT_GREEN}[+] Found {len(image_files)} image(s) for batch processing.{Colors.RESET}")
    auto_export = input(f"{Colors.WHITE}Automatically export reports for all images? (y/n) [y]: {Colors.RESET}").strip().lower()
    auto_export_bool = auto_export != "n"

    report_format = "both"
    if auto_export_bool:
        fmt_choice = input(f"{Colors.WHITE}Export format: [1] TXT, [2] JSON, [3] Both [3]: {Colors.RESET}").strip()
        if fmt_choice == "1":
            report_format = "txt"
        elif fmt_choice == "2":
            report_format = "json"

    print(f"\n{Colors.CYAN}{'#':<4} {'FILE NAME':<35} {'EXIF':<8} {'GPS':<8} {'STATUS'}{Colors.RESET}")
    print(f"{Colors.DIM}{'-'*70}{Colors.RESET}")

    total_exif = 0
    total_gps = 0

    for idx, img_p in enumerate(sorted(image_files), start=1):
        file_name = os.path.basename(img_p)
        display_name = file_name if len(file_name) <= 34 else file_name[:31] + "..."
        try:
            data = extract_metadata(img_p)
            has_ex = data.get("has_exif", False)
            has_g = data.get("has_gps", False)

            if has_ex:
                total_exif += 1
            if has_g:
                total_gps += 1

            ex_str = f"{Colors.GREEN}YES{Colors.RESET}" if has_ex else f"{Colors.DIM}NO{Colors.RESET}"
            g_str = f"{Colors.BRIGHT_RED}YES{Colors.RESET}" if has_g else f"{Colors.DIM}NO{Colors.RESET}"

            status_str = f"{Colors.GREEN}Processed{Colors.RESET}"
            if auto_export_bool:
                if report_format in ("txt", "both"):
                    generate_txt_report(data)
                if report_format in ("json", "both"):
                    generate_json_report(data)
                status_str = f"{Colors.BRIGHT_CYAN}Saved{Colors.RESET}"

            print(f"{idx:<4} {display_name:<35} {ex_str:<17} {g_str:<17} {status_str}")
        except Exception as e:
            print(f"{idx:<4} {display_name:<35} {Colors.RED}ERROR: {e}{Colors.RESET}")

    print(f"{Colors.DIM}{'-'*70}{Colors.RESET}")
    print(f"{Colors.BRIGHT_WHITE}{Colors.BOLD}Batch Analysis Summary:{Colors.RESET}")
    print(f"  Total Images Analyzed : {len(image_files)}")
    print(f"  Images with EXIF      : {total_exif}")
    print(f"  Images with GPS Tags  : {Colors.BRIGHT_RED if total_gps > 0 else Colors.WHITE}{total_gps}{Colors.RESET}")
    if auto_export_bool:
        print(f"  Reports Stored In     : {Colors.BRIGHT_CYAN}reports/{Colors.RESET}")
    if total_gps > 0:
        print(f"\n{Colors.BG_RED}{Colors.BRIGHT_WHITE} [!] NOTICE: {total_gps} image(s) contain GPS geolocation metadata! {Colors.RESET}\n")


def action_view_raw_exif(current_path: Optional[str], current_data: Optional[Dict[str, Any]]) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """Displays raw decoded EXIF metadata tags."""
    if not current_data or not current_path:
        img_path = prompt_image_path(current_path)
        if not img_path:
            return current_path, None
        show_spinner(0.4, "Reading raw EXIF tags")
        current_data = extract_metadata(img_path)
        current_path = img_path

    display_raw_exif(current_data)
    return current_path, current_data


def action_generate_sha256(current_path: Optional[str]) -> Optional[str]:
    """Standalone SHA256 checksum calculator."""
    img_path = prompt_image_path(current_path)
    if not img_path:
        return current_path

    show_spinner(0.3, "Computing cryptographic hashes")
    try:
        h = calculate_hashes(img_path)
        print(f"\n{Colors.BRIGHT_GREEN}{Colors.BOLD}[+] Cryptographic Integrity Checksums:{Colors.RESET}")
        print(f"  {Colors.WHITE}Target File :{Colors.RESET} {os.path.abspath(img_path)}")
        print(f"  {Colors.WHITE}File Size   :{Colors.RESET} {os.path.getsize(img_path):,} bytes")
        print(f"  {Colors.WHITE}SHA-256     :{Colors.RESET} {Colors.BRIGHT_YELLOW}{h['sha256']}{Colors.RESET}")
        print(f"  {Colors.WHITE}SHA-1       :{Colors.RESET} {h['sha1']}")
        print(f"  {Colors.WHITE}MD5         :{Colors.RESET} {h['md5']}\n")
    except Exception as exc:
        print(f"{Colors.RED}[!] Error: {exc}{Colors.RESET}\n")

    return img_path


def action_export_txt(current_path: Optional[str], current_data: Optional[Dict[str, Any]]) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """Exports TXT forensic report."""
    if not current_data or not current_path:
        img_path = prompt_image_path(current_path)
        if not img_path:
            return current_path, None
        show_spinner(0.4, "Analyzing image for report")
        current_data = extract_metadata(img_path)
        current_path = img_path

    try:
        saved_path = generate_txt_report(current_data)
        print(f"\n{Colors.BRIGHT_GREEN}[+] TXT Forensic Report successfully generated!{Colors.RESET}")
        print(f"  {Colors.WHITE}Saved to: {Colors.BRIGHT_CYAN}{saved_path}{Colors.RESET}\n")
    except Exception as e:
        print(f"{Colors.RED}[!] Failed to export TXT report: {e}{Colors.RESET}\n")

    return current_path, current_data


def action_export_json(current_path: Optional[str], current_data: Optional[Dict[str, Any]]) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """Exports JSON forensic report."""
    if not current_data or not current_path:
        img_path = prompt_image_path(current_path)
        if not img_path:
            return current_path, None
        show_spinner(0.4, "Analyzing image for report")
        current_data = extract_metadata(img_path)
        current_path = img_path

    try:
        saved_path = generate_json_report(current_data)
        print(f"\n{Colors.BRIGHT_GREEN}[+] JSON Forensic Report successfully generated!{Colors.RESET}")
        print(f"  {Colors.WHITE}Saved to: {Colors.BRIGHT_CYAN}{saved_path}{Colors.RESET}\n")
    except Exception as e:
        print(f"{Colors.RED}[!] Failed to export JSON report: {e}{Colors.RESET}\n")

    return current_path, current_data


def action_about_developer() -> None:
    """Displays developer credentials and ethics manifesto."""
    print(f"""
{Colors.BRIGHT_CYAN}{Colors.BOLD}========================================================================
             RAKIB EXIF METADATA READER - ABOUT DEVELOPER
========================================================================{Colors.RESET}
  {Colors.WHITE}Developer       :{Colors.RESET} {Colors.BRIGHT_GREEN}{Colors.BOLD}RAKIB HOSSEN{Colors.RESET}
  {Colors.WHITE}Project Purpose :{Colors.RESET} Educational & Authorized Digital Forensics Analysis
  {Colors.WHITE}Version         :{Colors.RESET} 1.0.0 Professional Edition
  {Colors.WHITE}Core Engine     :{Colors.RESET} Python 3 + Pillow (PIL)

{Colors.BRIGHT_YELLOW}{Colors.BOLD}FORENSIC INTEGRITY & PRIVACY PRINCIPLES:{Colors.RESET}
  1. {Colors.GREEN}Strict Local Processing{Colors.RESET}: Zero external network requests.
     No images or metadata are ever uploaded to remote servers.
  2. {Colors.GREEN}Evidence Preservation{Colors.RESET} : Files are opened in read-only binary
     mode. Original image contents, hashes, and timestamps remain untouched.
  3. {Colors.GREEN}No Fabrication{Colors.RESET}        : Missing tags are displayed honestly as
     "Not Available". No speculative fields are synthesized.
  4. {Colors.GREEN}Cross-Platform Power{Colors.RESET}  : Engineered for Kali Linux, NetHunter
     Rootless, Android Termux, Windows PowerShell, and standard Linux.
{Colors.DIM}========================================================================{Colors.RESET}
""")


def interactive_menu() -> None:
    """Main interactive terminal loop."""
    current_path: Optional[str] = None
    current_data: Optional[Dict[str, Any]] = None

    while True:
        print_banner()

        if current_path:
            print(f"  {Colors.DIM}Active Image: {Colors.BRIGHT_WHITE}{os.path.basename(current_path)}{Colors.RESET}\n")

        print(f"  {Colors.BRIGHT_CYAN}[1]{Colors.RESET} Analyze Single Image")
        print(f"  {Colors.BRIGHT_CYAN}[2]{Colors.RESET} Analyze Image Folder (Batch Mode)")
        print(f"  {Colors.BRIGHT_CYAN}[3]{Colors.RESET} View EXIF Metadata (Raw Tags)")
        print(f"  {Colors.BRIGHT_CYAN}[4]{Colors.RESET} Generate SHA256 Hash")
        print(f"  {Colors.BRIGHT_CYAN}[5]{Colors.RESET} Export TXT Report")
        print(f"  {Colors.BRIGHT_CYAN}[6]{Colors.RESET} Export JSON Report")
        print(f"  {Colors.BRIGHT_CYAN}[7]{Colors.RESET} About Developer")
        print(f"  {Colors.BRIGHT_RED}[0]{Colors.RESET} Exit")

        try:
            choice = input(f"\n{Colors.BRIGHT_YELLOW}Select Option [0-7]: {Colors.RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n\n{Colors.YELLOW}Operation cancelled by user. Exiting...{Colors.RESET}")
            break

        if choice == "1":
            current_path, current_data = action_analyze_single(current_path)
            input(f"\n{Colors.DIM}Press Enter to return to main menu...{Colors.RESET}")
            clear_screen()
        elif choice == "2":
            action_batch_analysis()
            input(f"\n{Colors.DIM}Press Enter to return to main menu...{Colors.RESET}")
            clear_screen()
        elif choice == "3":
            current_path, current_data = action_view_raw_exif(current_path, current_data)
            input(f"\n{Colors.DIM}Press Enter to return to main menu...{Colors.RESET}")
            clear_screen()
        elif choice == "4":
            current_path = action_generate_sha256(current_path)
            input(f"\n{Colors.DIM}Press Enter to return to main menu...{Colors.RESET}")
            clear_screen()
        elif choice == "5":
            current_path, current_data = action_export_txt(current_path, current_data)
            input(f"\n{Colors.DIM}Press Enter to return to main menu...{Colors.RESET}")
            clear_screen()
        elif choice == "6":
            current_path, current_data = action_export_json(current_path, current_data)
            input(f"\n{Colors.DIM}Press Enter to return to main menu...{Colors.RESET}")
            clear_screen()
        elif choice == "7":
            action_about_developer()
            input(f"\n{Colors.DIM}Press Enter to return to main menu...{Colors.RESET}")
            clear_screen()
        elif choice in ("0", "q", "exit"):
            print(f"\n{Colors.BRIGHT_GREEN}Thank you for using RAKIB EXIF METADATA READER!{Colors.RESET}")
            print(f"{Colors.DIM}Developer: RAKIB HOSSEN. Stay safe & practice ethical forensics.{Colors.RESET}\n")
            break
        else:
            print(f"\n{Colors.RED}[!] Invalid selection: '{choice}'. Please choose a number between 0 and 7.{Colors.RESET}")
            time.sleep(1.2)
            clear_screen()


def cli_entrypoint() -> None:
    """Parses optional CLI arguments or boots the interactive menu."""
    if not check_dependencies():
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="RAKIB EXIF METADATA READER - Digital Forensics Tool by RAKIB HOSSEN",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-i", "--image", help="Path to single image for analysis")
    parser.add_argument("-d", "--directory", help="Path to folder for batch analysis")
    parser.add_argument("-o", "--output", help="Custom output directory for reports", default="reports")
    parser.add_argument("--txt", action="store_true", help="Auto-export TXT report")
    parser.add_argument("--json", action="store_true", help="Auto-export JSON report")
    parser.add_argument("--hash", action="store_true", help="Display only cryptographic hashes")
    parser.add_argument("-v", "--version", action="version", version="RAKIB EXIF METADATA READER 1.0.0")

    args = parser.parse_args()

    # CLI direct argument modes
    if args.image:
        if args.hash:
            h = calculate_hashes(args.image)
            print(f"File   : {args.image}")
            print(f"SHA-256: {h['sha256']}")
            print(f"SHA-1  : {h['sha1']}")
            print(f"MD5    : {h['md5']}")
            return

        print_banner()
        data = extract_metadata(args.image)
        display_analysis_summary(data)

        if args.txt:
            p = generate_txt_report(data, output_dir=args.output)
            print(f"{Colors.GREEN}[+] TXT report saved: {p}{Colors.RESET}")
        if args.json:
            p = generate_json_report(data, output_dir=args.output)
            print(f"{Colors.GREEN}[+] JSON report saved: {p}{Colors.RESET}")
        return

    if args.directory:
        print_banner()
        valid_exts = (".jpg", ".jpeg", ".png", ".webp", ".tiff", ".tif", ".bmp")
        imgs = [os.path.join(args.directory, f) for f in os.listdir(args.directory) if f.lower().endswith(valid_exts)]
        print(f"{Colors.GREEN}[+] Found {len(imgs)} images in '{args.directory}'{Colors.RESET}")
        for img in sorted(imgs):
            d = extract_metadata(img)
            display_analysis_summary(d)
            if args.txt or (not args.txt and not args.json):
                generate_txt_report(d, output_dir=args.output)
            if args.json:
                generate_json_report(d, output_dir=args.output)
        print(f"\n{Colors.BRIGHT_GREEN}[+] Batch processing complete. Reports saved to '{args.output}/'{Colors.RESET}")
        return

    # Interactive Menu Mode
    clear_screen()
    interactive_menu()


if __name__ == "__main__":
    cli_entrypoint()
