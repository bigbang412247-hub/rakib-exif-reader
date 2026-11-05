# RAKIB EXIF METADATA READER
### Digital Forensics & Image Geolocation Intelligence Toolkit

**Developer:** **RAKIB HOSSEN**  
**Role:** Senior Python Developer & Digital Forensics Software Engineer  
**Version:** 1.0.0  
**License:** MIT Open Source (Educational & Authorized Digital Forensics)  

---

## 1. Main Objective

**RAKIB EXIF METADATA READER** is a digital image forensic analysis and geolocation intelligence tool engineered for cybersecurity researchers, digital forensics investigators, OSINT specialists, and privacy advocates. 

It safely parses exchangeable image file format (EXIF) metadata from photographs, extracts hardware telemetry, calculates cryptographic checksums (SHA-256, SHA-1, MD5), converts raw GPS coordinates into decimal degrees and standardized navigation links, and highlights critical privacy vulnerabilities — **all 100% locally and offline**.

---

## 2. Platform Compatibility

The application is engineered and tested across multi-architecture environments:

* 🐉 **Kali Linux** (Native x86_64 / aarch64)
* 📱 **Kali NetHunter Rootless** (Android PRoot / Chroot)
* ⚡ **Termux** (Android OS without root)
* 🪟 **Microsoft Windows** (Windows 10/11 with PowerShell or CMD)
* 🐧 **Linux Distributions** (Ubuntu, Debian, Fedora, Arch, CentOS)

---

## 3. Main Features

### 1. Image File Information
* File name and absolute canonical path
* Exact file size in human-readable notation (KB, MB) and raw bytes
* Image encoding format (`JPEG`, `PNG`, `WEBP`, `TIFF`, etc.)
* Image dimensions (`Width x Height` in pixels)
* Aspect ratio calculation (`16:9`, `4:3`, etc.)
* Color space / mode (`RGB`, `RGBA`, `CMYK`, `L`)
* IANA MIME type detection

### 2. EXIF Camera Metadata
* Camera manufacturer (`Make`)
* Camera model (`Model`)
* Software and firmware version
* Date & Time Original (shutter press)
* Date & Time Digitized
* Date & Time Modified
* Exposure Time (formatted e.g. `1/250s`)
* ISO Speed Rating (`ISOSpeedRatings`)
* Aperture / F-Stop (formatted e.g. `f/2.8`)
* Focal Length (formatted e.g. `50.0 mm`) and 35mm equivalent
* Lens make and lens model
* Metering mode, flash status, white balance, orientation
* Artist and copyright attributions

### 3. GPS Geolocation & Navigation
* Converts Degrees, Minutes, Seconds (DMS) rational tuples to standard **Decimal Degrees (DD)**
* Cardinal direction handling: automatically accounts for North/South and East/West references
* Formats human-readable DMS strings (e.g. `23° 48' 49.32" N`)
* Altitude calculation in both meters and feet, with above/below sea level indicator
* Auto-generated **Google Maps** direct navigation URL
* Auto-generated **OpenStreetMap (OSM)** verification link
* Embedded GPS timestamp and date stamp in UTC

### 4. Forensic Cryptographic Integrity
* **SHA-256 Hash**: High-assurance cryptographic signature
* **SHA-1 Hash**: Forensic legacy verification
* **MD5 Hash**: Rapid collision detection
* Streamed in 64 KB chunks to process large images without memory exhaustion

### 5. Automated Reporting System
* **Export TXT Report**: Clean, structured ASCII forensic report with dividers and confidentiality notice
* **Export JSON Report**: Machine-readable JSON output suitable for automated SIEM or OSINT ingestion
* Automatic naming convention: `reports/report_{filename}_{timestamp}.{txt|json}`
* Auto-created `reports/` directory

### 6. Batch Processing Engine
* Scan an entire folder containing hundreds of images
* Identifies supported formats (`.jpg`, `.jpeg`, `.png`, `.webp`, `.tiff`, `.bmp`)
* Summary statistics table showing total files, EXIF presence, and GPS presence
* Bulk automatic report generation (TXT, JSON, or Both)

### 7. Privacy Awareness & Ethics
* **CRITICAL PRIVACY WARNING**: Triggers an alert whenever GPS metadata is detected in an image
* **Zero Remote Requests**: Never connects to the Internet. 100% of calculations execute locally
* **Read-Only Evidence Preservation**: Never alters, writes, or touches original evidence files
* **Truthful Reporting**: Clearly marks missing or unsupported tags as `"Not Available"` — never fabricates synthetic data

---

## 4. Project Directory Structure

```text
rakib-exif-reader/
├── main.py                 # Main CLI application & interactive terminal UI
├── exif_reader.py          # Core EXIF extraction engine & Pillow wrapper
├── gps_parser.py           # Geolocation rational math & decimal degrees converter
├── hash_utils.py           # Chunked SHA-256, SHA-1, and MD5 cryptographic engine
├── report_generator.py     # Forensic TXT and JSON report generation
├── requirements.txt        # Python package dependencies (Pillow)
├── generate_test_samples.py# Script to generate sample images with simulated EXIF/GPS
├── test_suite.py           # Automated unit tests for math, hashes, and reports
├── README.md               # English & Bengali documentation
├── reports/                # Output directory for exported reports (.gitkeep)
└── samples/                # Sample image directory for testing
```

---

## 5. Installation Instructions

### Prerequisites
* Python 3.8 or higher
* `pip` package manager

### Cross-Platform Setup

#### Option A: Kali Linux / Ubuntu / Debian
```bash
# Update repositories and install Python 3 & Pillow
sudo apt update
sudo apt install -y python3 python3-pip python3-pil

# Clone or navigate to the project directory
cd rakib-exif-reader

# Install requirements
pip3 install -r requirements.txt
```

#### Option B: Kali NetHunter Rootless (Android)
```bash
# Inside NetHunter terminal
sudo apt update
sudo apt install -y python3 python3-pip python3-pil
cd rakib-exif-reader
pip3 install -r requirements.txt
```

#### Option C: Termux (Android)
```bash
# Update Termux packages
pkg update && pkg upgrade -y
pkg install -y python python-pip libjpeg-turbo libpng

# Install Pillow using Termux package manager or pip
pkg install -y python-pillow
# OR
pip install -r requirements.txt

# Grant storage permission to read camera images
termux-setup-storage
cd /sdcard/Download/rakib-exif-reader
```

#### Option D: Microsoft Windows (PowerShell or CMD)
```powershell
# Verify Python is installed
python --version

# Navigate to project folder
cd rakib-exif-reader

# Install dependencies
pip install -r requirements.txt
```

---

## 6. Execution & Usage

### 1. Interactive Menu Mode (Recommended)
Run the main script without arguments to open the terminal interface:

```bash
python3 main.py
```

#### Main Menu Options:
```text
  [1] Analyze Single Image
  [2] Analyze Image Folder (Batch Mode)
  [3] View EXIF Metadata (Raw Tags)
  [4] Generate SHA256 Hash
  [5] Export TXT Report
  [6] Export JSON Report
  [7] About Developer
  [0] Exit
```

### 2. Command-Line Arguments (Pipeline Mode)

For automated scripts, forensics pipelines, or quick queries:

```bash
# Analyze a single image with terminal output
python3 main.py -i photo.jpg

# Analyze and automatically export both TXT and JSON reports
python3 main.py -i photo.jpg --txt --json

# Calculate only cryptographic integrity hashes
python3 main.py -i photo.jpg --hash

# Batch process an entire directory and save reports to custom folder
python3 main.py -d /path/to/images/ -o /path/to/custom_reports/

# Display help and version
python3 main.py --help
python3 main.py --version
```

### 3. Running Unit Tests
Verify math and cryptographic integrity:

```bash
python3 -m unittest test_suite.py
```

### 4. Creating Sample Test Images
Synthesize sample photos with camera and GPS data:

```bash
python3 generate_test_samples.py
```

---

## 7. Example Terminal Output

```text
  ██████╗  █████╗ ██╗  ██╗██╗██████╗     ███████╗██╗   ██╗██╗███████╗
  ██╔══██╗██╔══██╗██║ ██╔╝██║██╔══██╗    ██╔════╝██║   ██║██║██╔════╝
  ██████╔╝███████║█████╔╝ ██║██████╔╝    █████╗  ██║   ██║██║█████╗  
  ██╔══██╗██╔══██║██╔═██╗ ██║██╔══██╗    ██╔══╝  ╚██╗ ██╔╝██║██╔══╝  
  ██║  ██║██║  ██║██║  ██╗██║██████╔╝    ███████╗ ╚████╔╝ ██║██║     
  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═════╝     ╚══════╝  ╚═══╝  ╚═╝╚═╝     
            E X I F   M E T A D A T A   R E A D E R
       Digital Forensics & Geolocation Analysis Toolkit v1.0.0
------------------------------------------------------------------------
  Developer: RAKIB HOSSEN | Platform: Kali • NetHunter • Termux • Win • Linux
  Privacy  : 100% Offline Analysis • Zero Data Transmission • Read-Only
------------------------------------------------------------------------

┌── [ 1. FILE & FORMAT INFORMATION ]
│ File Name        : evidence_sample.jpg
│ File Path        : /workspace/samples/evidence_sample.jpg
│ File Size        : 2.45 MB (2,569,012 bytes)
│ Image Format     : JPEG
│ Dimensions       : 6000 x 4000 pixels (3:2 (1.50:1))
│ Color Mode       : RGB
│ MIME Type        : image/jpeg
├── [ 2. CRYPTOGRAPHIC CHECKSUMS (INTEGRITY) ]
│ SHA-256          : b83c16260ab50f316260b949bc52bb4a806c9a296dff836cf930438128fb17a4
│ SHA-1            : 4b68e984d72bc4685ff8619bc947bfb174a974b2
│ MD5              : 1f387920ab4685bf927b1409ab410294
├── [ 3. CAMERA & DEVICE METADATA ]
│ Manufacturer     : Canon
│ Model            : Canon EOS R5
│ Software         : Firmware 1.5.0
│ Date/Time (Orig) : 2026:11:02 14:32:00
│ Date/Time (Digit): 2026:11:02 14:32:00
│ Date/Time (Mod)  : 2026:11:02 14:32:00
├── [ 4. SHOOTING & EXPOSURE PARAMETERS ]
│ Exposure Time    : 1/250s (1/250s)
│ Aperture (F-Stop): f/2.8
│ ISO Speed        : 400
│ Focal Length     : 50.0 mm (35mm equiv: 50)
│ Lens Model       : RF 50mm F1.2 L USM
│ Metering Mode    : Pattern
│ Flash            : Off, Did not fire
│ White Balance    : Auto
└── [ 5. GPS GEOLOCATION DATA ]

 [!] CRITICAL PRIVACY ALERT: GPS METADATA DETECTED! 
  Exact geographic coordinates were recovered from this image.
  Sharing this raw image exposes physical residence, workplace, or route.
  Forensic recommendation: Strip EXIF tags before public release.

  Latitude (DD)    : 23.813700
  Longitude (DD)   : 90.412500
  Latitude (DMS)   : 23° 48' 49.32" N
  Longitude (DMS)  : 90° 24' 45.00" E
  Altitude         : 14.50 m (47.57 ft) [Above Sea Level]
  GPS Timestamp    : 2026:11:02 08:32:00 UTC
  Google Maps Link : https://www.google.com/maps?q=23.813700,90.412500
  OpenStreetMap    : https://www.openstreetmap.org/?mlat=23.813700&mlon=90.412500#map=16/23.813700/90.412500
```

---

## 8. গুরুত্বপূর্ণ বাংলা ডকুমেন্টেশন (Bengali Documentation)

### পরিচিতি
**রাকিব এক্সিফ মেটাডাটা রিডার (RAKIB EXIF METADATA READER)** একটি আধুনিক ও প্রফেশনাল ডিজিটাল ফরেনসিক সফটওয়্যার। সফটওয়্যারটি তৈরি করেছেন ডিজিটাল ফরেনসিক গবেষক **রাকিব হোসেন (RAKIB HOSSEN)**। 

মোবাইল, ক্যামেরা বা ড্রোন দিয়ে তোলা ডিজিটাল ছবির ভেতরে লুকানো গুরুত্বপূর্ণ তথ্য যেমন ক্যামেরার নাম, ছবি তোলার সঠিক সময়, এক্সপোজার সেটিংস, এবং বিশেষ করে জিপিএস (GPS) লোকেশন নিখুঁতভাবে বের করে আনাই এই টুলের মূল উদ্দেশ্য।

---

### প্রধান বৈশিষ্ট্যসমূহ

1. **ছবির সাধারণ তথ্য:** ছবির নাম, ফাইল সাইজ, ফরম্যাট (JPEG, PNG, WEBP ইত্যাদি), ডাইমেনশন (Width x Height), কালার মোড এবং MIME টাইপ।
2. **ক্যামেরা ও ডিভাইসের তথ্য:** ক্যামেরা প্রস্তুতকারক (যেমন: Canon, Nikon, Apple, Samsung), মডেল, সফটওয়্যার ভার্সন, এবং ছবি তোলার আসল তারিখ ও সময়।
3. **ফটোগ্রাফিক সেটিংস:** শাটার স্পিড (Exposure time), অ্যাপারচার (F-Stop), আইএসও (ISO), ফোকাল লেন্থ এবং লেন্স মডেল।
4. **জিপিএস ও লোকেশন ট্র্যাকিং:** জিপিএস স্থানাঙ্ক স্বয়ংক্রিয়ভাবে ডেসিমেল ডিগ্রিতে (Decimal Degrees) রূপান্তর, উচ্চতা (Altitude) এবং গুগল ম্যাপস (Google Maps) ও ওপেন-স্ট্রিট-ম্যাপের সরাসরি ক্লিকযোগ্য লিংক তৈরি।
5. **ফরেনসিক হ্যাশ ইন্টিগ্রিটি:** ছবির আসল অবস্থা প্রমাণে SHA-256, SHA-1 এবং MD5 হ্যাশ স্বয়ংক্রিয়ভাবে গণনা করা।
6. **রিপোর্ট তৈরি:** সংগৃহীত তথ্যাদি সুন্দর টেক্সট (TXT) এবং জেএসন (JSON) ফরম্যাটে এক্সপোর্ট করা।
7. **ফোল্ডার ভিত্তিক বিশ্লেষণ (Batch Mode):** একটি ফোল্ডারে থাকা শত শত ছবি একসাথে এনালাইসিস করে একক রিপোর্ট তৈরি।
8. **নিরাপত্তা ও প্রাইভেসি সচেতনতা:** ছবিতে জিপিএস পাওয়া গেলে স্বয়ংক্রিয় লাল সতর্কবার্তা প্রদান যাতে সোশ্যাল মিডিয়ায় ছবি শেয়ার করার আগে লোকেশন মুছে ফেলা যায়।

---

### ব্যবহারের নিয়মাবলী

#### ১. টার্মিনালে রান করা
```bash
python3 main.py
```

#### ২. মেনু অপশনসমূহ:
* **[1] Analyze Single Image:** একটি নির্দিষ্ট ছবির মেটাডাটা ও হ্যাশ দেখতে।
* **[2] Analyze Image Folder:** সম্পূর্ণ ফোল্ডারের সব ছবি একসাথে এনালাইসিস করতে।
* **[3] View EXIF Metadata:** সব র' (Raw) এক্সিফ ট্যাগ দেখতে।
* **[4] Generate SHA256 Hash:** ছবির ক্রিপ্টোগ্রাফিক হ্যাশ যাচাই করতে।
* **[5] Export TXT Report:** টেক্সট রিপোর্ট সেভ করতে (`reports/` ফোল্ডারে সংরক্ষিত হবে)।
* **[6] Export JSON Report:** জেএসন রিপোর্ট সেভ করতে।
* **[7] About Developer:** ডেভলপার পরিচিতি ও ফরেনসিক নীতি দেখতে।
* **[0] Exit:** সফটওয়্যার থেকে প্রস্থান করতে।

---

### ইনস্টলেশন নির্দেশিকা (বাংলা)

#### টারমাক্স (Termux - Android মোবাইল)
```bash
pkg update
pkg install -y python python-pillow
pip install -r requirements.txt
python main.py
```

#### কালি লিনাক্স / উবুন্টু (Kali Linux / Ubuntu)
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-pil
pip3 install -r requirements.txt
python3 main.py
```

#### উইন্ডোজ (Windows 10/11)
```powershell
pip install -r requirements.txt
python main.py
```

---

### গোপনীয়তা ও ফরেনসিক নীতিমালা (Privacy & Ethics)
* **১০০% লোকাল প্রসেসিং:** এটি একটি অফলাইন সফটওয়্যার। কোনো ছবি বা তথ্য ইন্টারনেটে বা কোনো সার্ভারে আপলোড করা হয় না।
* **মূল ছবির নিরাপত্তা:** সফটওয়্যারটি কোনো মূল ছবির ভেতর কোনো কিছু পরিবর্তন বা মুছে ফেলে না (Read-Only Mode)।
* **সত্যনিষ্ঠ ফরেনসিক:** কোনো তথ্য না থাকলে বানোয়াট তথ্য তৈরি না করে স্পষ্টভাবে `"Not Available"` প্রদর্শন করা হয়।

---

**Developer:** RAKIB HOSSEN  
*Dedicated to Ethical Digital Forensics, Cyber Safety, and OSINT Research.*
