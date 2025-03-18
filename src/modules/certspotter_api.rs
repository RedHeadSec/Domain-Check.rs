use reqwest::blocking::Client;
use serde::Deserialize;
use std::error::Error;

/// CertSpotter API endpoint (No API key required)
const CERTSPOTTER_API_URL: &str = "https://api.certspotter.com/v1/issuances";

/// Structure for certificate response
#[derive(Debug, Deserialize)]
struct CertSpotterResponse {
    dns_names: Vec<String>,
}

/// Fetch historical TXT-related subdomains from CertSpotter
pub fn fetch_historical_txt_records(domain: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let url = format!("{}?domain={}&include_subdomains=true&expand=dns_names", CERTSPOTTER_API_URL, domain);
    let client = Client::new();

    let response = client.get(&url).send()?.json::<Vec<CertSpotterResponse>>()?;

    // Extract all DNS names (may include TXT-related records)
    let mut txt_records = Vec::new();
    for entry in response {
        for dns_name in entry.dns_names {
            // Filter out non-TXT related entries
            if dns_name.contains(domain) {
                txt_records.push(dns_name);
            }
        }
    }

    // Remove duplicates
    txt_records.sort();
    txt_records.dedup();

    Ok(txt_records)
}