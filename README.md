# tif-FeedIndicatorConverter
Converts IOCs between different formats (e.g., STIX, MISP, plain text) and normalizes them for consistent processing across various threat feeds. Supports multiple input/output formats and validation. - Focused on Aggregates data from multiple threat intelligence feeds (e.g., open-source malware databases, vulnerability reports, IP reputation lists) and provides a consolidated view.  Allows users to search, filter, and correlate threat data to identify potential risks in their environment. Includes basic geoip capabilities to help associate threats with locations, but avoids anything too computationally expensive for a simple tool.

## Install
`git clone https://github.com/ShadowStrikeHQ/tif-feedindicatorconverter`

## Usage
`./tif-feedindicatorconverter [params]`

## Parameters
- `-h`: Show help message and exit
- `-u`: No description provided
- `-f`: No description provided
- `-o`: Output file to save the converted IOCs. If not specified, prints to stdout.
- `-g`: Enable GeoIP lookup for IP addresses.
- `--geoip_db`: No description provided
- `-i`: Filter IOCs by type.
- `-r`: Filter IOCs by a regular expression.

## License
Copyright (c) ShadowStrikeHQ
