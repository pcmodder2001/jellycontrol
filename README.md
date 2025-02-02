<div align="center">

# 🎮 Jellyfin Control

<img src="https://github.com/pcmodder2001/jellycontrol/blob/1.03/jellyfin_control/static/assets/custom_logo.png" alt="Project Logo" width="200"/>

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org)
[![Django](https://img.shields.io/badge/Django-5.0+-green.svg?style=for-the-badge&logo=django&logoColor=white)](https://www.djangoproject.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com)

*A powerful Django-based web application for managing Jellyfin media server users and permissions.*

[Features](#-features) •
[Quick Start](#-quick-start) •
[Documentation](#-documentation) •
[Contributing](#-contributing) •
[Support](#-support)

</div>

---

## ✨ Features

<div align="center">

| 🔐 User Management | 📨 Invitation System | 🛡️ Security | 🔌 Integration |
|-------------------|---------------------|-------------|----------------|
| Create & Manage Users | Generate Invite Codes | Role-based Access | Jellyfin API |
| Bulk Operations | Track Usage | Activity Logging | Email Notifications |
| Activity Monitoring | Set Expiration | IP Restrictions | Custom Branding |
| Custom Permissions | Usage Limits | Secure Auth | Mobile-responsive |

</div>

## 🚀 Quick Start

### 🐳 Docker Installation (Recommended)

Clone the repository
git clone https://github.com/pcmodder2001/jellycontrol.git
Navigate to project directory
cd jellycontrol
Build and run with Docker
docker build -t jellycontrol .
docker run -p 8056:8056 jellycontrol


### 💻 Manual Installation

<details>
<summary>Click to expand</summary>

1. **Prerequisites**
   ```bash
   # Install Python 3.10 or higher
   python -m pip install --upgrade pip
   ```

2. **Setup**
   ```bash
   # Clone and setup
   git clone https://github.com/pcmodder2001/jellycontrol.git
   cd jellycontrol
   
   # Virtual environment (recommended)
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   
   # Dependencies
   pip install -r requirements.txt
   ```

3. **Run**
   ```bash
   python run.py
   ```
</details>

## 📚 Documentation

<div align="center">

| Section | Description |
|---------|-------------|
| [📖 Wiki](wiki) | Complete documentation |
| [🔧 Setup Guide](wiki/setup) | Detailed setup instructions |
| [👥 User Guide](wiki/users) | User management guide |
| [⚡ API Reference](wiki/api) | API documentation |

</div>

## 🛡️ Security Features

- 🔒 Built with security best practices
- 🔄 Regular security updates
- 🛑 Protected against common vulnerabilities
- 🔐 Secure session handling

## 🤝 Contributing

We welcome contributions! Here's how you can help:

1. 🍴 Fork the repository
2. 🌿 Create your feature branch (`git checkout -b feature/Amazing`)
3. 💾 Commit changes (`git commit -m 'Add Amazing Feature'`)
4. 📤 Push to branch (`git push origin feature/Amazing`)
5. 🔍 Open a Pull Request

## 📦 Tech Stack

<div align="center">

| Technology | Purpose |
|------------|---------|
| ![Django](https://img.shields.io/badge/Django-092E20?style=for-the-badge&logo=django&logoColor=white) | Backend Framework |
| ![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white) | Programming Language |
| ![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white) | Containerization |
| ![UIkit](https://img.shields.io/badge/UIkit-2396F3?style=for-the-badge&logo=uikit&logoColor=white) | Frontend Framework |

</div>

## 📧 Support

<div align="center">

</div>

---

<div align="center">

Made with ❤️ by [Brad Crampton](https://github.com/pcmodder2001)

</div>