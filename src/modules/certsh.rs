use serde::Deserialize;
use std::collections::HashSet;
use std::error::Error;
use reqwest::blocking::Client;
use std::{thread, time::Duration};

#[derive(Debug, Deserialize)]
struct CrtShEntry {
    name_value: String,
}

pub fn fetch_subdomains_from_crtsh(domain: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let url = format!("https://crt.sh/?q=%.{}&output=json", domain);
    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;

    let mut last_err = None;
    for attempt in 1..=3 {
        match client.get(&url).send() {
            Ok(resp) => {
                if !resp.status().is_success() {
                    return Err(format!("crt.sh returned non-200: {}", resp.status()).into());
                }

                let entries: Vec<CrtShEntry> = resp.json()?;
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
                return Ok(subdomain_list);
            }
            Err(e) => {
                last_err = Some(e);
                println!("⚠️ Attempt {}/3 to fetch crt.sh failed, retrying... ", attempt);
                thread::sleep(Duration::from_secs(2 * attempt)); // Exponential backoff
            }
        }
    }

    Err(format!(
        "Failed to fetch crt.sh data after retries: {}",
        last_err.unwrap()
    )
    .into())
}