mod args;
mod modules;
mod utils;

use args::CliArgs;
use clap::Parser;
use modules::{historical_dns,dns,certspotter_api,certsh};

fn main() {
    let args = CliArgs::parse(); 
    let domain = &args.domain;
    let av_api_key = args.av_api_key.as_deref().unwrap_or("No AV key provided!");
    let st_api_key = args.st_api_key.as_deref().unwrap_or("No ST key provided!");
    let mut output = format!("🔍 DNS Report for: {}\n\n", domain);

    println!("🔍 Checking DNS records for: {}", domain);

    // Live DNS Queries
    if let Ok(ips) = dns::resolve_a_record(domain) {
        let ip_results = format!("📌 A/AAAA Records:\n{}\n", ips.iter().map(|ip| format!("  - {}", ip)).collect::<Vec<_>>().join("\n"));
        output.push_str(&ip_results);
        println!("{}", ip_results);
    }

    if let Ok(txts) = dns::resolve_txt_record(domain) {
        let txt_results = format!("\n📜 TXT Records:\n{}\n", txts.iter().map(|txt| format!("  - {}", txt)).collect::<Vec<_>>().join("\n"));
        output.push_str(&txt_results);
        println!("{}", txt_results);
    }

    if let Ok(cname) = dns::resolve_cname(domain) {
        let cname_result = format!("\n🔄 CNAME Record:\n  - {}\n", cname);
        output.push_str(&cname_result);
        println!("{}", cname_result);
    }

    // Historical Subdomains Lookup
    if let Ok(subdomains) = historical_dns::fetch_historical_subdomains(domain, av_api_key) {
        let subdomain_results = format!("\n📜 Historical Subdomains:\n{}\n", subdomains.iter().map(|s| format!("  - {}", s)).collect::<Vec<_>>().join("\n"));
        output.push_str(&subdomain_results);
        println!("{}", subdomain_results);
    }

    // Fetch Historical TXT Records from CertSpotter
    match certspotter_api::fetch_historical_txt_records(domain) {
        Ok(txt_history) => {
            let txt_history_results = format!("\n📜 Historical TXT Records (CertSpotter):\n{}\n", txt_history.iter().map(|txt| format!("  - {}", txt)).collect::<Vec<_>>().join("\n"));
            output.push_str(&txt_history_results);
            println!("{}", txt_history_results);
        }
        Err(e) => eprintln!("❌ Failed to fetch historical TXT records: {}", e),
    }

    match certsh::fetch_subdomains_from_crtsh(domain) {
        Ok(crtsh_subs) => {
            let crtsh_results = format!("\n📜 Subdomains from crt.sh (Active & Expired Certificates):\n{}\n", 
                crtsh_subs.iter().map(|s| format!("  - {}", s)).collect::<Vec<_>>().join("\n"));
            output.push_str(&crtsh_results);
            println!("{}", crtsh_results);
        }
        Err(e) => eprintln!("❌ Failed to fetch subdomains from crt.sh: {}", e),
    }

    // Save results if --save is set
    if args.save {
        if let Err(e) = utils::save_to_file(&args.file_name, &output) {
            eprintln!("❌ Failed to save results: {}", e);
        }
    }

}
