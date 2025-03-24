use serde::Deserialize;
use std::collections::HashSet;
use std::error::Error;
use reqwest::blocking::Client;
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct CrtShEntry {
    name_value: String,
}

pub fn fetch_subdomains_from_crtsh(domain: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let url = format!("https://crt.sh/?q=%.{}&output=json", domain);
    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;

    let response = client.get(&url).send();

    match response {
        Ok(resp) => {
            // Ensure status is 200 OK
            if !resp.status().is_success() {
                return Err(format!("crt.sh returned non-200: {}", resp.status()).into());
            }

            let entries: Vec<CrtShEntry> = match resp.json() {
                Ok(json) => json,
                Err(e) => return Err(format!("Failed to parse crt.sh response: {}", e).into()),
            };

            let mut subdomains = HashSet::new();
            for entry in entries {
                for name in entry.name_value.split('\n') {
                    if name.contains(domain) {
                        subdomains.insert(name.trim().to_string());
                    }
                }
            }

            let mut subdomain_list: Vec<String> = subdomains.into_iter().collect();
            subdomain_list.sort();
            Ok(subdomain_list)
        }
        Err(e) => Err(format!("Failed to fetch crt.sh data: {}", e).into()),
    }
}