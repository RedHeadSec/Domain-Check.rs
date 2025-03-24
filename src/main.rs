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
        Err(e) => eprintln!("❌ Failed to resolve A/AAAA records: {}", e),
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
    Err(e) => eprintln!("❌ Failed to resolve TXT records: {}", e),
}

match dns::resolve_cname_chain(domain) {
    Ok(chain) => {
        println!("\n🔄 CNAME Chain:");
        for entry in chain {
            println!("  - {}", entry);
        }
    }
    Err(e) => eprintln!("❌ Failed to resolve CNAME chain: {}", e),
}

match dns::resolve_mx_record(domain) {
    Ok(mail) => {
        let mail_result = format!("\n📧 MX Records:\n  - {}\n", mail);
        output.push_str(&mail_result);
        println!("{}", mail_result);
    }
    Err(e) => eprintln!("❌ Failed to resolve MX records: {}", e),
}

match dns::resolve_ns_record(domain) {
    Ok(ns) => {
        let ns_result = format!("\n🌐 Nameservers Record:\n  - {}\n", ns);
        output.push_str(&ns_result);
        println!("{}", ns_result);
    }
    Err(e) => eprintln!("❌ Failed to resolve NS record: {}", e),
}

match historical_dns::fetch_historical_subdomains(domain, av_api_key) {
    Ok(subdomains) => {
        let subdomain_results = format!(
            "\n📜 Historical Subdomains:\n{}\n",
            subdomains
                .iter()
                .map(|s| format!("  - {}", s))
                .collect::<Vec<_>>()
                .join("\n")
        );
        output.push_str(&subdomain_results);
        println!("{}", subdomain_results);
    }
    Err(e) => eprintln!("❌ Failed to fetch historical subdomains: {}", e),
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
