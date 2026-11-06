# NetScaler ADC Disaster Recovery Sync Automation
Python-based NetScaler ADC configuration synchronization between Primary and Disaster Recovery sites using NITRO REST API.
Python-based configuration synchronization automation for Citrix NetScaler ADC environments using the NITRO REST API.

Overview

This project was developed to help maintain configuration consistency between geographically separated NetScaler ADC HA environments.

The automation discovers active Primary nodes, retrieves supported configuration resources, compares Main and DR environments, and performs synchronization operations.

Key Features

Automatic HA Primary Node Discovery

NITRO REST API Integration

Main-to-DR Configuration Comparison

Missing Resource Creation

Supported Configuration Updates

Orphan Resource Detection and Cleanup

Responder and Rewrite Policy Synchronization

Content Switching and Load Balancing Configuration Synchronization

Dataset Value Binding Synchronization

Logging and Scheduled Execution

Configuration Save Operations

Architecture

Main Data Center (HA Pair)

↓

Python Synchronization Engine

↓

Disaster Recovery Data Center (HA Pair)

Technologies

Python 3

Citrix NetScaler ADC

NITRO REST API

Requests

Linux Cron

Scheduling

Example daily execution at 19:00:

0 19 * * * /usr/bin/python3 /opt/netscaler-sync/netscaler_sync.py >> /var/log/netscaler_sync.log 2>&1

Important Notes

This project is intended for controlled NetScaler environments.

Before production deployment, review the supported resource types, configuration dependencies, update restrictions, and deletion behavior.

Some advanced resource dependencies and dataset index operations require additional handling and validation.

Never commit production credentials, management IP addresses, or customer-specific information to a public repository.

Author

Network Security Engineering | ADC Automation | Python | Disaster Recovery
