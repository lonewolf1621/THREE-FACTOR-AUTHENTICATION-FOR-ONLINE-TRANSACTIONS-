# 🔐 Three Factor Authentication for Online Transactions

This repository is based on my B.Tech group project on **Three Factor Authentication for Online Transactions**,
combining:

* \*A secure multi-layer identity verification system combining password, OTP, and fingerprint authentication.\*
* 
* ---
* 
* \## 📌 \*\*Project Overview\*\*
* 
* This project implements a \*\*Three-Factor Authentication (3FA)\*\* system designed to make online transactions significantly more secure. Traditional authentication methods rely mainly on a username and password, which can be vulnerable to phishing, brute-force attacks, and credential theft.
* 
* This system enhances security by validating the user through \*\*three independent authentication factors\*\*:
* 
* 1\. \*\*Knowledge Factor:\*\* Username + Password
* 2\. \*\*Possession Factor:\*\* One-Time Password (OTP) sent to the user’s registered mobile number
* 3\. \*\*Inherence Factor:\*\* Fingerprint authentication on an Android device
* 
* Only when all three layers are successfully completed does the system authorize access, making it resistant to most common cyberattacks including SIM swap attempts, password leaks, and unauthorized access.
* 
* ---
* 
* \## 🎯 \*\*Key Features\*\*
* 
* \### \*\*1️⃣ Password-Based Login (PHP + MySQL)\*\*
* 
* \* User registers with name, email, password, and mobile number
* \* Login page verifies credentials against the database
* \* Prevents unauthorized login attempts
* 
* \### \*\*2️⃣ SMS-Based OTP Verification\*\*
* 
* \* Upon successful password login, a \*\*random 6-digit OTP\*\* is generated
* \* OTP is sent to the user’s registered mobile number
* \* Login proceeds only if OTP matches
* \* Protects against credential theft \& session hijacking
* 
* \### \*\*3️⃣ Fingerprint Authentication (Android)\*\*
* 
* \* Uses Android’s fingerprint APIs
* \* Performs permission, hardware, and enrollment checks
* \* User must confirm identity using their fingerprint
* \* Adds a biometric layer for maximum security
* 
* ---
* 
* \## 🏗️ \*\*System Architecture (Text Diagram)\*\*
* 
* ```
* ┌────────────┐        ┌────────────────────┐        ┌──────────────────────┐
* │ USER LOGIN │  --->  │ PASSWORD VERIFIED  │  --->  │ OTP SENT TO MOBILE   │
* └────────────┘        └────────────────────┘        └──────────────────────┘
* &nbsp;                                                              │
* &nbsp;                                                              ▼
* &nbsp;                                               ┌────────────────────────┐
* &nbsp;                                               │ OTP VERIFIED BY SERVER │
* &nbsp;                                               └────────────────────────┘
* &nbsp;                                                              │
* &nbsp;                                                              ▼
* &nbsp;                                             ┌────────────────────────────┐
* &nbsp;                                             │ FINGERPRINT AUTH (ANDROID) │
* &nbsp;                                             └────────────────────────────┘
* &nbsp;                                                              │
* &nbsp;                                                              ▼
* &nbsp;                                              ┌──────────────────────────┐
* &nbsp;                                              │ ACCESS SUCCESSFUL        │
* &nbsp;                                              └──────────────────────────┘
* ```
* 
* ---
* 
* \## 📂 \*\*Repository Structure\*\*
* 
* ```
* three-factor-authentication/
* │── README.md
* │── requirements.txt
* │── .gitignore
* │── code/
* │   ├── php/
* │   │   ├── signup\_sample.php
* │   │   └── login\_otp\_sample.php
* │   ├── android/
* │   │   └── MainActivity\_fingerprint\_demo.java
* │   └── technical\_notes.md
* │── screenshots/
* │── data/
* │── models/
* └── results/
* ```
* 
* ---
* 
* \## ⚙️ \*\*Technologies Used\*\*
* 
* \### \*\*Backend \& Web\*\*
* 
* \* PHP
* \* MySQL
* \* XAMPP Server
* 
* \### \*\*Mobile (Android)\*\*
* 
* \* Android Studio (Java)
* \* FingerprintManager API
* \* BiometricPrompt-compatible logic
* 
* \### \*\*Security \& Testing Tools\*\*
* 
* \* Randomized OTP generation
* \* HTTPS-ready logic
* \* Secure session handling
* 
* ---
* 
* \## 🚀 \*\*How It Works (Process Flow)\*\*
* 
* \### \*\*Step 1: User Registration (PHP)\*\*
* 
* User enters:
* 
* \* Name
* \* Email
* \* Password
* \* Phone number
* 
* Stored in MySQL using `signup\_sample.php`.
* 
* ---
* 
* \### \*\*Step 2: Login with Username + Password\*\*
* 
* \* User enters credentials
* \* System checks MySQL
* \* If valid → OTP screen appears
* \* If invalid → access denied
* 
* ---
* 
* \### \*\*Step 3: OTP Generation \& Delivery\*\*
* 
* \* Server generates a `6-digit numeric OTP`
* \* Stores OTP in PHP session
* \* Sends via SMS API (placeholder in sample code)
* 
* User enters OTP → server validates.
* 
* ---
* 
* \### \*\*Step 4: Fingerprint Authentication (Android App)\*\*
* 
* Android app checks:
* 
* \* Is fingerprint sensor available?
* \* Does the user have fingerprints enrolled?
* \* Are permissions granted?
* 
* If all checks pass → user verifies fingerprint → authentication completes.
* 
* ---
* 
* \## 🧪 \*\*Security Advantages\*\*
* 
* ✔ Resistant to phishing
* ✔ Prevents unauthorized access
* ✔ Protects against stolen passwords
* ✔ Protects even if SIM is cloned
* ✔ Fingerprint ensures user presence
* ✔ Strong defense against credential stuffing
* 
* ---
* 
* \## 💡 \*\*Future Enhancements\*\*
* 
* \* Replace SMS OTP with TOTP (Google Authenticator)
* \* Implement face unlock
* \* Add backend APIs using Node.js or Flask
* \* JWT-based secure session management
* \* AES encryption for database storage
* 
* ---
* 
