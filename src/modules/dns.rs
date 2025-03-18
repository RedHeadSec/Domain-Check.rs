use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;
use trust_dns_resolver::error::ResolveError;
use std::net::IpAddr;

/// Function to resolve A records (IPv4) and AAAA records (IPv6)
pub fn resolve_a_record(domain: &str) -> Result<Vec<IpAddr>, ResolveError> {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())?;
    
    let response = resolver.lookup_ip(domain)?;
    
    let ips: Vec<IpAddr> = response.iter().collect();
    Ok(ips)
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
pub fn resolve_cname(domain: &str) -> Result<String, ResolveError> {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())?;
    
    let response = resolver.lookup(domain, trust_dns_resolver::proto::rr::RecordType::CNAME)?;
    
    if let Some(cname) = response.iter().next() {
        Ok(cname.to_string())
    } else {
        Err(ResolveError::from(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No CNAME record found",
        )))
    }
}

/// Resolves MX (Mail Exchange) record - returns first found or error
pub fn resolve_mx_record(domain: &str) -> Result<String, ResolveError> {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())?;
    let response = resolver.mx_lookup(domain)?;
    
    if let Some(mx) = response.iter().next() {
        Ok(format!("{} -> {}", mx.preference(), mx.exchange()))
    } else {
        Err(ResolveError::from(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No MX record found",
        )))
    }
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