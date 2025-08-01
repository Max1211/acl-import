# ACL Import Tool for Pensando Systems Manager (PSM)

A Python script that converts Cisco Nexus ACL rules into Pensando Systems Manager (PSM) network security policies via REST API.

## Overview

This tool parses Cisco Nexus-style ACL entries and transforms them into PSM-compatible network security policies. It includes optimization capabilities to merge similar rules and provides comprehensive reporting on the conversion process.

## Features

- **Cisco Nexus ACL Support**: Parses standard Nexus ACL format with CIDR notation
- **IPv4/IPv6 Support**: Automatically detects address family from ACL and creates appropriate policy
- **Rule Optimization**: Merges similar ACL entries to reduce policy complexity
- **Comprehensive Reporting**: Detailed summary of processed, merged, and dropped rules
- **Service Name Translation**: Converts well-known service names to port numbers
- **IP Range Validation**: Automatically corrects improperly specified subnets
- **Interactive Workflow**: User confirmation at each critical step
- **Address Family Detection**: Identifies ACL type from first IP address entry

## Prerequisites

- Python 3.6+
- Access to Pensando Systems Manager (PSM) API
- Required Python packages (see `requirements.txt`)

## Installation

1. Clone or download the script to your desired location
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Create a `.env` file with your PSM credentials:
   ```env
   USERNAME=your_username
   PASSWORD=your_password
   APIGWURL=https://your-psm-url
   DISPLAY_NAME=ACL-Import
   RULE_NAME_PREFIX=ACE-rule
   ```
   Note: The script automatically appends a timestamp to DISPLAY_NAME to ensure uniqueness.

## File Structure

```
acl_import/
├── acl_import.py              # Main script with IPv6 support
├── acl.txt                    # Input ACL rules (Nexus format)
├── service_translation.txt    # Service name to port mappings
├── protocol_translation.txt   # Protocol name translations
├── requirements.txt           # Python dependencies
└── README.md                  # This file
```

## Input File Formats

### acl.txt
Cisco Nexus ACL format:
```
9000 permit tcp any 192.168.1.0/24 eq 22
9001 deny udp 10.0.0.0/8 any eq 53
9002 permit tcp 172.16.0.0/16 192.168.100.0/24 range 80 443
```

### service_translation.txt
Service name to port number mappings:
```
www = 80
https = 443
ssh = 22
telnet = 23
```

### protocol_translation.txt
Protocol name translations:
```
ahp = ah
```

## Usage

1. Prepare your ACL rules in `acl.txt`
2. Run the script:
   ```bash
   python acl_import.py
   ```
3. Follow the interactive prompts:
   - Accept the disclaimer
   - Review parsed ACL entries
   - Choose whether to optimize rules
   - Confirm policy creation
   - Approve sending to PSM

## Output Files

- **optimized_rules.txt**: Human-readable list of optimized rules
- **sqn_merge_table.csv**: Mapping of original ACL sequence numbers to merged rules
- **rules_export.csv**: PSM-compatible rule format for review
- **acl_processing_report.txt**: Detailed conversion report with statistics

## Limitations

- **Source Port Filtering**: Not supported by PSM (rules are adapted)
- **Established Keyword**: Not supported (rules are dropped)
- **Address Family Consistency**: ACLs must be either IPv4 or IPv6; inconsistent entries are dropped
- **Advanced Options**: No support for precedence, DSCP, logging, or fragments
- **IP Collections**: The script does not generate IP Collection objects from source/destination addresses
- **Apps**: No application-level filtering is created (L3/L4 rules only)

## Processing Summary

The script provides a comprehensive summary including:
- Total ACL entries processed vs successfully parsed
- Compression ratio achieved through optimization
- Detailed breakdown of dropped rules by reason
- IP range corrections made
- Address family detection results

## Troubleshooting

- **Logs**: Check `acl_to_api.log` in the script directory for detailed logging
- **SSL Warnings**: The script disables SSL warnings for self-signed certificates
- **Failed Login**: Verify credentials in `.env` file
- **Parse Errors**: Ensure ACL format matches Cisco Nexus syntax

## Security Notes

- Credentials are loaded from environment variables (`.env` file)
- Never commit `.env` files to version control
- The script includes a disclaimer that must be accepted before execution
- All operations are logged for audit purposes

## License

This script is provided "as is" without warranty. Use at your own risk.