use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;
use trust_dns_resolver::error::ResolveError;
use std::net::IpAddr;

/// Function to resolve A records (IPv4) and AAAA records (IPv6)
pub fn resolve_a_record(domain: &str) -> Result<(Vec<IpAddr>, bool), ResolveError> {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())?;
    let response = resolver.lookup_ip(domain)?;
    let ips: Vec<IpAddr> = response.iter().collect();

    // Heuristic: Check if any IP is potentially a known proxy (Cloudflare ranges example)
    let is_cloudflare = ips.iter().any(|ip| match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            (octets[0] == 104) || (octets[0] == 172 && (octets[1] >= 64 && octets[1] <= 127)) || (octets[0] == 131)
        }
        IpAddr::V6(_) => false, // IPv6 check could be added with known ranges
    });

    Ok((ips, is_cloudflare))
}

/// Function to resolve TXT records
pub fn resolve_txt_record(domain: &str) -> Result<Vec<String>, ResolveError> {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())?;
    let response = resolver.txt_lookup(domain)?;
    
    let txt_records: Vec<String> = response
        .iter()
        .flat_map(|r| r.iter().map(|txt| String::from_utf8_lossy(txt).to_string()))
        .collect();

    Ok(txt_records)
}

/// Function to resolve CNAME record
pub fn resolve_cname_chain(domain: &str) -> Result<Vec<String>, ResolveError> {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())?;
    let mut current = domain.to_string();
    let mut chain = Vec::new();

    loop {
        let response = resolver.lookup(&current, trust_dns_resolver::proto::rr::RecordType::CNAME)?;
        if let Some(cname) = response.iter().next() {
            let cname_str = cname.to_string();
            chain.push(format!("{} -> {}", current, cname_str));
            current = cname_str.trim_end_matches('.').to_string(); // remove trailing dot if present
        } else {
            // No more CNAMEs, stop chasing
            break;
        }
    }

    if chain.is_empty() {
        Err(ResolveError::from(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No CNAME chain found",
        )))
    } else {
        Ok(chain)
    }
}

/// Resolves MX (Mail Exchange) record - returns first found or error
pub fn resolve_mx_record(domain: &str) -> Result<String, ResolveError> {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())?;
    let response = resolver.mx_lookup(domain)?;

    let mx_records: Vec<String> = response
        .iter()
        .map(|r| format!("{} -> {}", r.preference(), r.exchange()))
        .collect();

    if mx_records.is_empty() {
        return Err(ResolveError::from(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No MX records found",
        )));
    }

    Ok(mx_records.join("\n  - "))
}

/// Resolves NS (Name Server) record - returns first found or error
pub fn resolve_ns_record(domain: &str) -> Result<String, ResolveError> {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())?;
    let response = resolver.ns_lookup(domain)?;
    
    if let Some(ns) = response.iter().next() {
        Ok(ns.to_string())
    } else {
        Err(ResolveError::from(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No NS record found",
        )))
    }
}