#!/usr/bin/python

'''
# Author: Michael Stott
# Date: 10/19/19
#
# Command line tool for scanning URLs for CRLF injection.
'''

from scanner.scanner import CrlfScanner  # Corrected import statement
import click
import validators
import json

@click.group()
def main():
    pass  # Removed initial echo for cleaner terminal output

@main.command("scan")
@click.option("-u", "--urls", help="Comma delimited URLs.")
@click.option("-i", "--ifile", help="File of URLs to scan, separated by newlines")
@click.option("-o", "--ofile", help="Output scan results to file.")
def scan(urls, ifile, ofile):
    """ Performs CRLF injection on the specified URLs. """
    scanner = CrlfScanner()
    target_urls = _parse_urls(urls, ifile)
    vuln_results = []  # Store results with vulnerability status

    if not target_urls:
        click.echo("No input found! Terminating.")
        return
    
    click.echo("Beginning scan...")
    
    for url in target_urls:
        crlf_urls = scanner.generate_vuln_urls(url.strip())
        for crlf_url in crlf_urls:
            is_vulnerable = scanner.scan(crlf_url)
            vuln_results.append({"url": crlf_url, "vulnerable": is_vulnerable})
    
    click.echo("Finished scan!")

    # Save results to specified output files
    save_results_to_json(vuln_results)
    save_results_to_text(vuln_results)

    if ofile:
        with open(ofile, 'w') as out:
            for result in vuln_results:
                out.write(f"{result['url']}, Vulnerable: {result['vulnerable']}\n")
        click.echo(f"Results saved to {ofile}")

def _parse_urls(urls, ifile):
    """ Parses URLs from CLI args and input file. """
    target_urls = []
    
    # Parse the URLs.
    if urls:
        target_urls.extend([_clean(url) for url in urls.split(",")])
    if ifile:
        with open(ifile) as fp:
            for line in fp:
                target_urls.append(_clean(line))
    
    # Remove all nonvalid URLs.
    for target_url in target_urls[:]:  # Use a copy of the list to avoid modifying while iterating
        if not validators.domain(target_url):
            target_urls.remove(target_url)
    
    return target_urls

def _clean(url):
    for protocol in CrlfScanner.PROTOCOL_LIST:
        if protocol + "://" in url:
            url = url.replace(protocol + "://", "")
    return url.strip()

def save_results_to_json(results):
    """ Save scan results to a JSON file. """
    with open('crlf_scan_results.json', 'w') as json_file:
        json.dump(results, json_file, indent=2)

def save_results_to_text(results):
    """ Save scan results to a text file. """
    with open('crlf_scan_results.txt', 'w') as text_file:
        for entry in results:
            text_file.write(f"URL: {entry['url']}, Vulnerable: {entry['vulnerable']}\n")

if __name__ == "__main__":
    main()
