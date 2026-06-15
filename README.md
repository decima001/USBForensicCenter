# USBForensicCenter
A USB Foensic App for scanning devices for logs and vulnerabilities.


USB Forensic Center
The USB Forensic Center is an automated, Celery-backed forensic analysis suite designed to perform rapid filesystem inspection, credential harvesting, and anti-forensic evasion detection on mounted removable media.

🛠️ System Overview
The system utilizes a Django web interface for case management and device orchestration, while leveraging Celery with Redis to execute hardware-level forensic scans in the background.

Core Features
Filesystem Crawling: Automated traversal using os.walk with system-level exclusion logic.

MIME Masquerade Detection: Identifies files with misleading extensions (e.g., .txt files that are actually binary executables).

Credential Leak Detection: Uses regex-based pattern matching to identify potential secrets (API keys, passwords) in configuration and log files.

Automated Reporting: Generates HTML-based forensic reports upon scan completion.

🚀 Installation Process
Prerequisites
Python 3.14+

Redis Server (required as the message broker)

Libmagic (ensure the development binaries are installed on your OS)

Setup Steps
Clone the repository:

Bash
git clone https://github.com/your-repo/usb-forensic-center.git
cd USBForensicCenter
Install dependencies:

Bash
pip install -r requirements.txt
Run database migrations:

Bash
python manage.py makemigrations forensics
python manage.py migrate
Start the infrastructure:

Start Redis Server (refer to your OS-specific installation).

Start the Celery Worker:

Bash
python -m celery -A core worker --loglevel=info --pool=solo
Start the Django Development Server:

Bash
python manage.py runserver
🤝 Contribution Requests
We welcome contributions to strengthen the forensic capabilities of the suite. We are specifically looking for help in the following areas:

1. New Pattern Signatures
We are looking to expand the SECRET_PATTERNS dictionary in tasks.py. If you have experience with regex for identifying sensitive data structures (SSH keys, cloud provider tokens, etc.), please submit a pull request.

2. Forensic Logic
Hashing Optimization: Help integrate multi-threaded hashing for large files.

Carving Logic: Support for raw file carving from unallocated space.

Android/Mobile Modules: Enhancing the execute_android_vulnerability_scan module to support broader device compatibility.

How to Contribute
Fork the repository.

Create a Feature Branch (git checkout -b feature/amazing-module).

Commit your changes.

Push to the branch.

Open a Pull Request detailing your changes and how they improve the forensic pipeline.

[!NOTE]
This software is intended for legitimate forensic research and security audit purposes. Always ensure you have appropriate authorization before performing any analysis on hardware.

For technical documentation on the architecture, refer to the following guide:
