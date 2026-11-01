# tif-FeedIndicatorConverter
Converts IOCs between formats and normalizes them for consistent processing across threat feeds. Input is a feed URL or a local file path in JSON, RSS or Atom, or plain text form, and local text feeds are parsed line by line for indicators. Output formats are text, json, STIX, and MISP: STIX output is a STIX 2.1 bundle of indicator objects with a pattern for each indicator, and MISP output is a MISP event JSON object with an attributes array. A run with no feed, an unreadable feed, or an input with no data exits non-zero and produces no conversion output. Includes basic GeoIP lookup for IP addresses.

GeoIP is operator controlled. Supply an existing database with --geoip_db, or supply an archive URL with --geoip-url, for example a MaxMind GeoLite2 archive the operator is licensed to download from MaxMind. No download happens when --geoip-url is not supplied. Downloads use a 30 second timeout, and every archive member path is validated before extraction; an archive with a member outside the target directory is refused.

## Install
`git clone https://github.com/ShadowGuard-AI/tif-feedindicatorconverter`

## Usage
`./tif-feedindicatorconverter [params]`

## Parameters
- `-h`: Show help message and exit
- `-u`: URL of the threat intelligence feed, or a local file path
- `-f`: Output format: stix, misp, text, or json
- `-o`: Output file to save the converted IOCs. If not specified, prints to stdout.
- `-g`: Enable GeoIP lookup for IP addresses.
- `--geoip_db`: Path to the GeoIP database
- `--geoip-url`: Operator supplied URL of a GeoIP database archive, used only when the database file is missing
- `-i`: Filter IOCs by type.
- `-r`: Filter IOCs by a regular expression.

## License
Copyright (c) ShadowStrikeHQ
