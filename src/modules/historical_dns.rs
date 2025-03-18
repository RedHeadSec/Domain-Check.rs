use reqwest::blocking::Client;
use serde::Deserialize;
use std::collections::HashSet;

/// AlienVault API endpoint
const ALIENVAULT_API_URL: &str = "https://otx.alienvault.com/api/v1/indicators/domain";

/// Data structure for deserializing JSON responses
#[derive(Debug, Deserialize)]
struct PassiveDNSRecord {
    hostname: String,
}

/// Structure to handle full API response
#[derive(Debug, Deserialize)]
struct PassiveDNSResponse {
    passive_dns: Vec<PassiveDNSRecord>,
}

/// Fetches historical subdomains from AlienVault OTX
pub fn fetch_historical_subdomains(domain: &str, api_key: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let url = format!("{}/{}/passive_dns", ALIENVAULT_API_URL, domain);
    let client = Client::new();
    
    let response = client
        .get(&url)
        .header("X-OTX-API-KEY", api_key)
        .send()?
        .json::<PassiveDNSResponse>()?;

    // Remove duplicates
    let subdomains: HashSet<String> = response.passive_dns
        .into_iter()
        .map(|record| record.hostname)
        .collect();

    // Convert back to Vec<String>
    Ok(subdomains.into_iter().collect())
}
