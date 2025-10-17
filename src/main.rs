mod args;
mod modules;
mod utils;

use args::CliArgs;
use clap::Parser;
use modules::{historical_dns,dns,certspotter_api,certsh};

fn main() {
    let args = CliArgs::parse(); 
    let domain = &args.domain;
    let av_api_key = args.av_api_key.as_deref();
    let st_api_key = args.st_api_key.as_deref();
    let mut output = format!("🔍 DNS Report for: {}\n\n", domain);

    println!("🔍 Checking DNS records for: {}", domain);

    match dns::resolve_a_record(domain) {
        Ok((ips, is_cloudflare)) => {
            println!("📌 A/AAAA Records:");
            for ip in ips {
                println!("  - {}", ip);
            }
            if is_cloudflare {
                println!("⚠️  Potential Proxy Detected (e.g., Cloudflare in front of this domain)");
            }
        }
        Err(_) => eprintln!("❌ Failed to resolve A/AAAA records"),
    }

    match dns::resolve_txt_record(domain) {
        Ok(txts) => {
            let txt_results = format!(
                "\n📜 TXT Records:\n{}\n",
                txts.iter()
                    .map(|txt| format!("  - {}", txt))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
            output.push_str(&txt_results);
            println!("{}", txt_results);
        }
        Err(_) => eprintln!("❌ No TXT records found"),
    }

    match dns::resolve_cname_chain(domain) {
        Ok(chain) => {
            println!("\n🔄 CNAME Chain:");
            for entry in chain {
                println!("  - {}", entry);
            }
        }
        Err(_) => eprintln!("❌ No CNAME records found"),
    }

    match dns::resolve_mx_record(domain) {
        Ok(mail) => {
            let mail_result = format!("\n📧 MX Records:\n  - {}\n", mail);
            output.push_str(&mail_result);
            println!("{}", mail_result);
        }
        Err(_) => eprintln!("❌ No MX records found"),
    }

    match dns::resolve_ns_record(domain) {
        Ok(ns) => {
            let ns_result = format!("\n🌐 Nameservers Record:\n  - {}\n", ns);
            output.push_str(&ns_result);
            println!("{}", ns_result);
        }
        Err(_) => eprintln!("❌ Failed to resolve NS record"),
    }

    match historical_dns::fetch_whois(domain, av_api_key) {
        Ok(whois_data) => {
            if !whois_data.is_empty() {
                let whois_results = format!(
                    "\n📋 WHOIS Information (AlienVault):\n{}\n",
                    whois_data
                        .iter()
                        .map(|w| format!("  - {}", w))
                        .collect::<Vec<_>>()
                        .join("\n")
                );
                output.push_str(&whois_results);
                println!("{}", whois_results);
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to fetch WHOIS: {}", e);
        }
    }

    match historical_dns::fetch_historical_subdomains(domain, av_api_key) {
        Ok(subdomains) => {
            if !subdomains.is_empty() {
                let subdomain_results = format!(
                    "\n📜 Historical Subdomains (AlienVault):\n{}\n",
                    subdomains
                        .iter()
                        .map(|s| format!("  - {}", s))
                        .collect::<Vec<_>>()
                        .join("\n")
                );
                output.push_str(&subdomain_results);
                println!("{}", subdomain_results);
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to fetch historical subdomains: {}", e);
        }
    }

    match historical_dns::fetch_url_list(domain, av_api_key) {
        Ok(urls) => {
            if !urls.is_empty() {
                let url_results = format!(
                    "\n🔗 URL List (AlienVault):\n{}\n",
                    urls.iter()
                        .map(|u| format!("  - {}", u))
                        .collect::<Vec<_>>()
                        .join("\n")
                );
                output.push_str(&url_results);
                println!("{}", url_results);
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to fetch URL list: {}", e);
        }
    }

    match historical_dns::fetch_http_scans(domain, av_api_key) {
        Ok(scans) => {
            if !scans.is_empty() {
                let scan_results = format!(
                    "\n🔍 HTTP Scans (AlienVault):\n{}\n",
                    scans.iter()
                        .map(|s| format!("  - {}", s))
                        .collect::<Vec<_>>()
                        .join("\n")
                );
                output.push_str(&scan_results);
                println!("{}", scan_results);
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to fetch HTTP scans: {}", e);
        }
    }

    match certspotter_api::fetch_historical_txt_records(domain) {
        Ok(txt_history) => {
            if !txt_history.is_empty() {
                let txt_history_results = format!("\n📜 Historical TXT Records (CertSpotter):\n{}\n", 
                    txt_history.iter().map(|txt| format!("  - {}", txt)).collect::<Vec<_>>().join("\n"));
                output.push_str(&txt_history_results);
                println!("{}", txt_history_results);
            }
        }
        Err(_) => eprintln!("❌ Failed to fetch historical TXT records from CertSpotter"),
    }

    match certsh::fetch_subdomains_from_crtsh(domain) {
        Ok(crtsh_subs) => {
            if !crtsh_subs.is_empty() {
                let crtsh_results = format!("\n📜 Subdomains from crt.sh (Active & Expired Certificates):\n{}\n", 
                    crtsh_subs.iter().map(|s| format!("  - {}", s)).collect::<Vec<_>>().join("\n"));
                output.push_str(&crtsh_results);
                println!("{}", crtsh_results);
            }
        }
        Err(e) => {
            let error_msg = e.to_string();
            if error_msg.contains("502") || error_msg.contains("Bad Gateway") {
                eprintln!("❌ crt.sh service temporarily unavailable");
            } else {
                eprintln!("❌ Failed to fetch subdomains from crt.sh");
            }
        }
    }

    if args.save {
        if let Err(e) = utils::save_to_file(&args.file_name, &output) {
            eprintln!("❌ Failed to save results: {}", e);
        }
    }
}
