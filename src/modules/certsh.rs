use reqwest::blocking::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::error::Error;

#[derive(Debug, Deserialize)]
struct CrtShEntry {
    name_value: String,
}

/// Fetch subdomains from crt.sh
pub fn fetch_subdomains_from_crtsh(domain: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let url = format!("https://crt.sh/?q=%.{}&output=json", domain);
    let client = Client::new();

    let response = client.get(&url).send()?.json::<Vec<CrtShEntry>>()?;

    let mut subdomains = HashSet::new();

    for entry in response {
        for name in entry.name_value.split('\n') {
            if name.contains(domain) {
                subdomains.insert(name.trim().to_string());
            }
        }
    }

    // Return unique subdomains
    let mut subdomain_list: Vec<String> = subdomains.into_iter().collect();
    subdomain_list.sort();
    Ok(subdomain_list)
}