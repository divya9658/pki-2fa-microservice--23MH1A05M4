# PKI-Based 2FA Microservice

Secure authentication microservice using RSA (PKI), TOTP 2FA, Docker, and cron.
# 🔐 PKI-Based 2FA Microservice with Docker

## Overview
This project implements a secure, containerized authentication microservice using **Public Key Infrastructure (PKI)** and **Time-based One-Time Password (TOTP)** two-factor authentication. It demonstrates enterprise-grade security practices including RSA encryption, secure key handling, Docker containerization, persistent storage, and automated cron jobs.

This project was developed as part of the **Partnr Mandatory Task**.

---

## Objective
To build a production-ready microservice that:
- Decrypts a securely encrypted seed using RSA/OAEP
- Generates and verifies TOTP-based 2FA codes
- Persists sensitive data across container restarts
- Logs TOTP codes every minute using cron
- Runs reliably inside a Docker container

---

## Tech Stack
- **Language:** Python 3.11  
- **Framework:** FastAPI  
- **Cryptography:** cryptography (RSA, OAEP, PSS)  
- **2FA:** pyotp (TOTP)  
- **Containerization:** Docker, Docker Compose  
- **Scheduler:** cron  

---

## Security Features
- RSA 4096-bit key pair
- RSA/OAEP (SHA-256) for seed decryption
- RSA-PSS (SHA-256) for commit proof signing
- TOTP (SHA-1, 30-second window, 6-digit codes)
- Time window tolerance (±1 period)
- UTC timezone enforced

---

## API Endpoints

### POST `/decrypt-seed`
Decrypts the encrypted seed and stores it persistently.
```json
{ "encrypted_seed": "BASE64_STRING" }

