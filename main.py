import argparse
import logging
import requests
import feedparser
import geoip2.database
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
DEFAULT_GEOIP_DB = 'GeoLite2-City.mmdb'

def _validate_tar_members(tar, target_dir):
    base = os.path.abspath(target_dir)
    for member in tar.getmembers():
        dest = os.path.abspath(os.path.join(base, member.name))
        if dest != base and not dest.startswith(base + os.sep):
            raise ValueError(f"Refusing archive member outside the target directory: {member.name}")
        if member.issym() or member.islnk():
            link_dest = os.path.abspath(os.path.join(base, os.path.dirname(member.name), member.linkname))
            if not link_dest.startswith(base + os.sep):
                raise ValueError(f"Refusing archive link member outside the target directory: {member.name}")

def extract_geoip_archive(archive_path, target_dir):
    """Extracts an archive only after every member path is validated."""
    import tarfile
    with tarfile.open(archive_path, "r:gz") as tar:
        _validate_tar_members(tar, target_dir)
        try:
            tar.extractall(path=target_dir, filter="data")
        except TypeError:
            tar.extractall(path=target_dir)

def download_geoip_db(db_path, url):
    """Downloads and extracts a GeoIP database from an operator supplied URL."""
    logging.info(f"Downloading GeoIP database from operator supplied URL: {url}")
    try:
        import tarfile
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        archive_path = "GeoLite2-City.tar.gz"
        with open(archive_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        logging.info("Extracting GeoIP database...")
        extract_dir = "geoip_extract"
        os.makedirs(extract_dir, exist_ok=True)
        extract_geoip_archive(archive_path, extract_dir)
        found = None
        for root, _dirs, files in os.walk(extract_dir):
            for name in files:
                if name.endswith(".mmdb"):
                    found = os.path.join(root, name)
                    break
            if found:
                break
        if not found:
            raise Exception("No .mmdb file found in the GeoIP archive.")
        os.rename(found, db_path)
        os.remove(archive_path)
        import shutil
        shutil.rmtree(extract_dir, ignore_errors=True)
        logging.info("GeoIP database downloaded and extracted successfully.")
    except Exception as e:
        logging.error(f"Error downloading or extracting GeoIP database: {e}")
        raise

def is_valid_url(url):
    """
    Validates if a given string is a valid URL.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def setup_argparse():
    """Sets up the command-line argument parser."""
    parser = argparse.ArgumentParser(description="tif-FeedIndicatorConverter: Aggregates threat intelligence feeds, converts IOCs, and normalizes them.")
    parser.add_argument("-u", "--url", help="URL of the threat intelligence feed (e.g., RSS, JSON). Can also be a local file path.", required=False)
    parser.add_argument("-f", "--format", choices=["stix", "misp", "text", "json"], default="text", help="Output format for the IOCs (default: text)")
    parser.add_argument("-o", "--output", help="Output file to save the converted IOCs. If not specified, prints to stdout.", required=False)
    parser.add_argument("-g", "--geoip", action="store_true", help="Enable GeoIP lookup for IP addresses.")
    parser.add_argument("--geoip_db", default=DEFAULT_GEOIP_DB, help=f"Path to the GeoIP database. Defaults to '{DEFAULT_GEOIP_DB}'. No download happens unless --geoip-url is also supplied.")
    parser.add_argument("--geoip-url", dest="geoip_url", default=None, help="Operator supplied URL of a GeoIP database archive (for example a MaxMind GeoLite2 archive the operator is licensed to download). Used only when the database file is missing.")
    parser.add_argument("-i", "--ioc_type", choices=["ip", "domain", "url", "hash"], help="Filter IOCs by type.")
    parser.add_argument("-r", "--regex", help="Filter IOCs by a regular expression.", required=False)


    return parser

def fetch_feed(url):
    """Fetches the threat intelligence feed from the given URL."""
    try:
        if is_valid_url(url):
             response = requests.get(url, timeout=10)
             response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

             try:
                 # Attempt to parse as JSON
                 return response.json()
             except json.JSONDecodeError:
                 # If JSON parsing fails, assume it's a feed
                 return feedparser.parse(response.content)
        else:
            # Treat as a local file
            try:
                with open(url, 'r') as f:
                    content = f.read()
                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    parsed = feedparser.parse(content)
                    if getattr(parsed, "entries", None):
                        return parsed
                    # Plain text feed: return the raw text so its lines
                    # are parsed for indicators instead of dropped.
                    return content
            except FileNotFoundError:
                logging.error(f"File not found: {url}")
                return None
            except Exception as e:
                logging.error(f"Error reading local file: {e}")
                return None

    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching feed from {url}: {e}")
        return None
    except feedparser.CharacterEncodingOverride as e:
        logging.warning(f"Character encoding issue with feed {url}: {e}")
        return feedparser.parse(response.content) #Attempt again to parse but maybe not handle encoding override properly
    except Exception as e:
        logging.error(f"An unexpected error occurred while fetching the feed: {e}")
        return None


def extract_iocs(feed_data):
    """Extracts IOCs (IP addresses, domains, URLs, hashes) from the feed data."""
    iocs = {"ip": [], "domain": [], "url": [], "hash": []}

    if isinstance(feed_data, dict):  # JSON format
        # Attempt to parse a dictionary with IOC's
        def extract_from_dict(data):
          if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, str):
                  # Simple heuristic to identify IOCs
                  if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", value):  #IP address
                      iocs["ip"].append(value)
                  elif re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value): #Domain
                      iocs["domain"].append(value)
                  elif "http" in value: #URL
                      iocs["url"].append(value)
                  elif re.match(r"^[a-fA-F0-9]{32,128}$", value): #Hash
                      iocs["hash"].append(value) #very broad range of hashes

                elif isinstance(value, (dict, list)):
                   extract_from_dict(value)
          elif isinstance(data, list):
              for item in data:
                  extract_from_dict(item)
        extract_from_dict(feed_data) # run the extraction

    elif isinstance(feed_data, str):  # Plain text feed
        iocs["ip"] = re.findall(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", feed_data)
        iocs["domain"] = re.findall(r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", feed_data)
        iocs["url"] = re.findall(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", feed_data)
        iocs["hash"] = re.findall(r"\b[a-fA-F0-9]{32,128}\b", feed_data)

    elif hasattr(feed_data, 'entries'):  # RSS/Atom feed
        for entry in feed_data.entries:
            description = entry.get("description", "")
            content = entry.get("content", [])
            if content:
                description += " ".join([c.get("value", "") for c in content])

            # Extract IOCs from the description
            ip_addresses = re.findall(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", description)
            domains = re.findall(r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", description)
            urls = re.findall(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", description)
            hashes = re.findall(r"[a-fA-F0-9]{32,128}", description) # match for multiple hash values

            iocs["ip"].extend(ip_addresses)
            iocs["domain"].extend(domains)
            iocs["url"].extend(urls)
            iocs["hash"].extend(hashes)

    #Remove Duplicates
    # Sets also throw away the feed's own ordering and any count of
    # how often an indicator appeared, which in a feed is often the
    # only signal of how widely it was reported.
    for key in iocs:
        iocs[key] = list(set(iocs[key]))

    return iocs

def filter_iocs(iocs, ioc_type=None, regex=None):
    """Filters IOCs based on type and regular expression."""
    filtered_iocs = {}
    if ioc_type:
        if ioc_type in iocs:
            filtered_iocs[ioc_type] = iocs[ioc_type]
        else:
            logging.warning(f"IOC type '{ioc_type}' not found in extracted IOCs.")
            return {}
    else:
        filtered_iocs = iocs  # all IOC's

    if regex:
      try:
          compiled_regex = re.compile(regex)
          for ioc_type, ioc_list in filtered_iocs.items():
              filtered_iocs[ioc_type] = [ioc for ioc in ioc_list if compiled_regex.search(ioc)]
      except re.error as e:
          logging.error(f"Invalid regular expression: {e}")
          return {}

    return filtered_iocs

def geolocate_ip(ip_address, geoip_db_path):
    """
    Geolocates an IP address using the GeoLite2 database.
    Returns a dictionary containing geolocation information or None if not found.
    """
    try:
        with geoip2.database.Reader(geoip_db_path) as reader:
            try:
                response = reader.city(ip_address)
                return {
                    "country": response.country.name,
                    "city": response.city.name,
                    "latitude": response.location.latitude,
                    "longitude": response.location.longitude
                }
            except geoip2.errors.AddressNotFoundError:
                logging.warning(f"No geolocation data found for IP address: {ip_address}")
                return None
            except Exception as e:
                logging.error(f"Error during GeoIP lookup for {ip_address}: {e}")
                return None
    except FileNotFoundError:
        logging.error(f"GeoIP database not found at {geoip_db_path}. Please specify the correct path or download the database.")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred during GeoIP database operations: {e}")
        return None

def convert_to_format(iocs, output_format, geoip_enabled, geoip_db_path):
    """Converts IOCs to the specified format."""
    output = ""

    if output_format == "text":
        for ioc_type, ioc_list in iocs.items():
            output += f"[{ioc_type.upper()}]\n"
            for ioc in ioc_list:
                output += f"{ioc}\n"
                if geoip_enabled and ioc_type == "ip":
                    location_data = geolocate_ip(ioc, geoip_db_path)
                    if location_data:
                        output += f"  - Location: {location_data}\n"
            output += "\n"
    elif output_format == "json":
        if geoip_enabled:
            for ioc_type, ioc_list in iocs.items():
                if ioc_type == "ip":
                    for i in range(len(ioc_list)):
                        location_data = geolocate_ip(ioc_list[i], geoip_db_path)
                        if location_data:
                            iocs[ioc_type][i] = {"ip": ioc_list[i], "location": location_data}
        output = json.dumps(iocs, indent=4)
    elif output_format == "stix":
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        patterns = {"ip": ("ipv4-addr", "value"), "domain": ("domain-name", "value"), "url": ("url", "value")}
        hash_names = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
        objects = []
        for ioc_type, ioc_list in iocs.items():
            for value in ioc_list:
                if isinstance(value, dict):
                    value = value.get("ip", "")
                if not value:
                    continue
                if ioc_type == "hash":
                    algo = hash_names.get(len(value), "SHA-256")
                    pattern = f"[file:hashes.'{algo}' = '{value}']"
                else:
                    stix_type = patterns.get(ioc_type, ("artifact", "url"))[0]
                    pattern = f"[{stix_type}:value = '{value}']"
                objects.append({"type": "indicator", "spec_version": "2.1", "id": f"indicator--{uuid.uuid4()}", "created": now, "modified": now, "name": str(value), "pattern": pattern, "pattern_type": "stix", "valid_from": now})
        bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
        output = json.dumps(bundle, indent=4)
    elif output_format == "misp":
        type_map = {"ip": ("Network activity", "ip-dst"), "domain": ("Network activity", "domain"), "url": ("Network activity", "url")}
        hash_types = {32: "md5", 40: "sha1", 64: "sha256"}
        attributes = []
        for ioc_type, ioc_list in iocs.items():
            for value in ioc_list:
                if isinstance(value, dict):
                    value = value.get("ip", "")
                if not value:
                    continue
                if ioc_type == "hash":
                    category, attr_type = "Payload delivery", hash_types.get(len(value), "sha256")
                else:
                    category, attr_type = type_map.get(ioc_type, ("Network activity", "text"))
                attributes.append({"category": category, "type": attr_type, "value": str(value)})
        event = {"Event": {"info": "Converted feed indicators", "distribution": "0", "threat_level_id": "2", "analysis": "0", "Attribute": attributes}}
        output = json.dumps(event, indent=4)
    else:
        logging.error(f"Unsupported output format: {output_format}")
        return None

    return output

def main():
    """Main function to process threat intelligence feeds and convert IOCs."""
    parser = setup_argparse()
    args = parser.parse_args()

    if not args.url:
      parser.print_help()
      sys.exit(2)

    feed_data = fetch_feed(args.url)

    if not feed_data:
        logging.error("Failed to fetch or parse the threat intelligence feed.")
        sys.exit(1)

    iocs = extract_iocs(feed_data)
    filtered_iocs = filter_iocs(iocs, args.ioc_type, args.regex)

    if args.geoip and not os.path.exists(args.geoip_db):
        if args.geoip_url:
            try:
                download_geoip_db(args.geoip_db, args.geoip_url)
            except Exception:
                sys.exit(1)
        else:
            logging.error(f"GeoIP database not found at {args.geoip_db} and no --geoip-url was supplied. No download was attempted. Supply --geoip-db with an existing database or --geoip-url with an archive URL.")
            sys.exit(1)

    output = convert_to_format(filtered_iocs, args.format, args.geoip, args.geoip_db)

    if not output:
        logging.error("No output generated.")
        sys.exit(1)

    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write(output)
            logging.info(f"IOCs saved to {args.output}")
        except Exception as e:
            logging.error(f"Error writing to output file: {e}")
            sys.exit(1)
    else:
        print(output)

if __name__ == "__main__":
    main()


# Usage Examples:
# 1. Fetch IOCs from a URL and print to stdout in text format:
#    python tif-FeedIndicatorConverter.py -u http://example.com/threatfeed.rss
#
# 2. Fetch IOCs from a local file (JSON) and save to output.txt in JSON format:
#    python tif-FeedIndicatorConverter.py -u /path/to/threatfeed.json -f json -o output.txt
#
# 3. Fetch IP addresses from a URL, enable GeoIP lookup, and save to output.txt in text format:
#    python tif-FeedIndicatorConverter.py -u http://example.com/threatfeed.rss -i ip -g -o output.txt
#
# 4. Fetch IOCs from a URL and filter based on a regex:
#    python tif-FeedIndicatorConverter.py -u http://example.com/threatfeed.rss -r "maliciousdomain\.com"
#
# 5. Download GeoIP database if it doesn't exist and perform GeoIP lookups
#   python tif-FeedIndicatorConverter.py -u http://example.com/threatfeed.rss -i ip -g --geoip_db ./custom_geoip.mmdb -o output.txt