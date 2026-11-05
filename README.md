# 🛡️ XCSA-1100-MC1: Automated Network Reconnaissance & OS Fingerprinter

> **Course**: XCSA-1100-MC1 - Network Programming for Security Analysts  
> **Instructor**: Hamid Talebi  
> **Date**: November 5th, 2026
> **Author**: Alex Terziyski (alexterziyski@gmail.com)  
> **Core Topics**: Python Fundamentals | Socket Programming | Subprocess Management | Regular Expressions | File Operations | Try-Except Handling | REST API Integration  

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Reconnaissance-red.svg)](https://csrc.nist.gov/)
[![Course](https://img.shields.io/badge/Course-XCSA--1100--MC1-purple.svg)](#course-modules-and-curriculum-alignment)

---

## 📋 Executive Overview

In computer network defense and ethical hacking, active and passive reconnaissance constitutes the essential first phase of any security assessment. Security analysts must rapidly discover active hosts, map exposed network services, identify underlying operating systems, and enrich targets with threat and geographic intelligence.

`network_scanner.py` is an end-to-end Python network reconnaissance tool engineered without heavy external dependencies. By harnessing Python's native standard libraries—`socket`, `subprocess`, `re`, `urllib.request`, `json`, and `datetime`—this project demonstrates deep mastery of core network programming primitives.

---

## 🎯 Key Features & Capabilities

- 🔍 **Smart Target Resolution**: Resolves hostnames, fully qualified domain names (FQDNs), and IPv4 addresses via `socket.gethostbyname()`.
- 🐧 **Passive OS Fingerprinting via ICMP TTL Heuristics**: Spawns platform-aware ICMP ping processes via `subprocess.run()`, extracting Time-to-Live (`TTL`) fields using Regular Expressions (`re.search()`).
- ⚡ **Fast TCP Port Scanner**: Executes rapid 3-way TCP handshake scans using non-blocking socket timeouts (`socket.connect_ex()`) across 22 high-priority security ports.
- 🌐 **Threat & Geolocation REST API Integration**: Queries the `ip-api.com` REST service using `urllib.request` to enrich public IPs with ISP, Autonomous System (ASN), Geographic Coordinates, City, and Country data.
- 📝 **Automated Audit Report Generation**: Generates clean, timestamped security audit log files (`scan_report_<IP>_<timestamp>.txt`) using context-managed File Operations (`with open()`).
- 🛡️ **Defensive Error Handling**: Comprehensive nested `try-except-finally` blocks that cleanly trap `socket.gaierror`, `socket.timeout`, `urllib.error.URLError`, `subprocess.TimeoutExpired`, `IOError`, and `KeyboardInterrupt`.
