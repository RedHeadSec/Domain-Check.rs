use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashSet;

const ALIENVAULT_API_URL: &str = "https://otx.alienvault.com/api/v1/indicators/domain";

#[derive(Debug, Deserialize)]
struct PassiveDNSRecord {
    hostname: String,
}

#[derive(Debug, Deserialize)]
struct PassiveDNSResponse {
    #[serde(default)]
    passive_dns: Vec<PassiveDNSRecord>,
}

#[derive(Debug, Deserialize)]
struct UrlRecord {
    url: String,
}

#[derive(Debug, Deserialize)]
struct UrlListResponse {
    #[serde(default)]
    url_list: Vec<UrlRecord>,
}

#[derive(Debug, Deserialize)]
struct HttpScanRecord {
    key: String,
    name: String,
    value: Value,
}

#[derive(Debug, Deserialize)]
struct HttpScansResponse {
    #[serde(default)]
    data: Vec<HttpScanRecord>,
}

#[derive(Debug, Deserialize)]
struct WhoisResponse {
    #[serde(default)]
    registrar: String,
    #[serde(default)]
    creation_date: String,
    #[serde(default)]
    expiration_date: String,
    #[serde(default)]
    name_servers: Vec<String>,
}

pub fn fetch_historical_subdomains(domain: &str, api_key: Option<&str>) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let url = format!("{}/{}/passive_dns", ALIENVAULT_API_URL, domain);
    let client = Client::new();
    
    let mut request = client.get(&url);
    
    if let Some(key) = api_key {
        if !key.is_empty() && !key.contains("No AV key") {
            request = request.header("X-OTX-API-KEY", key);
        }
    }
    
    let response = request.send()?;

    let status = response.status();
    if !status.is_success() {
        return Err(format!("API returned status code: {}", status).into());
    }

    let json_response = response.json::<PassiveDNSResponse>()?;

    let subdomains: HashSet<String> = json_response.passive_dns
        .into_iter()
        .map(|record| record.hostname)
        .collect();

    Ok(subdomains.into_iter().collect())
}

pub fn fetch_url_list(domain: &str, api_key: Option<&str>) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let url = format!("{}/{}/url_list", ALIENVAULT_API_URL, domain);
    let client = Client::new();
    
    let mut request = client.get(&url);
    
    if let Some(key) = api_key {
        if !key.is_empty() && !key.contains("No AV key") {
            request = request.header("X-OTX-API-KEY", key);
        }
    }
    
    let response = request.send()?;

    let status = response.status();
    if !status.is_success() {
        return Err(format!("API returned status code: {}", status).into());
    }

    let json_response = response.json::<UrlListResponse>()?;

    let urls: HashSet<String> = json_response.url_list
        .into_iter()
        .map(|record| record.url)
        .collect();

    Ok(urls.into_iter().collect())
}

pub fn fetch_http_scans(domain: &str, api_key: Option<&str>) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let url = format!("{}/{}/http_scans", ALIENVAULT_API_URL, domain);
    let client = Client::new();
    
    let mut request = client.get(&url);
    
    if let Some(key) = api_key {
        if !key.is_empty() && !key.contains("No AV key") {
            request = request.header("X-OTX-API-KEY", key);
        }
    }
    
    let response = request.send()?;

    let status = response.status();
    if !status.is_success() {
        return Err(format!("API returned status code: {}", status).into());
    }

    let json_response = response.json::<HttpScansResponse>()?;

    let scans: Vec<String> = json_response.data
        .into_iter()
        .map(|scan| {
            let value_str = match &scan.value {
                Value::String(s) => {
                    if s.len() > 100 {
                        format!("{}...", &s[..100])
                    } else {
                        s.clone()
                    }
                },
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                _ => scan.value.to_string(),
            };
            format!("{}: {}", scan.name, value_str)
        })
        .collect();

    Ok(scans)
}

pub fn fetch_whois(domain: &str, api_key: Option<&str>) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let url = format!("{}/{}/whois", ALIENVAULT_API_URL, domain);
    let client = Client::new();
    
    let mut request = client.get(&url);
    
    if let Some(key) = api_key {
        if !key.is_empty() && !key.contains("No AV key") {
            request = request.header("X-OTX-API-KEY", key);
        }
    }
    
    let response = request.send()?;

    let status = response.status();
    if !status.is_success() {
        return Err(format!("API returned status code: {}", status).into());
    }

    let json_response = response.json::<WhoisResponse>()?;

    let mut whois_data = Vec::new();
    
    if !json_response.registrar.is_empty() {
        whois_data.push(format!("Registrar: {}", json_response.registrar));
    }
    if !json_response.creation_date.is_empty() {
        whois_data.push(format!("Created: {}", json_response.creation_date));
    }
    if !json_response.expiration_date.is_empty() {
        whois_data.push(format!("Expires: {}", json_response.expiration_date));
    }
    if !json_response.name_servers.is_empty() {
        whois_data.push(format!("Name Servers: {}", json_response.name_servers.join(", ")));
    }

    Ok(whois_data)
}
