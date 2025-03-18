# DNS-Check
A small tool for performing active and historical DNS checks on a domain. This can be used for both reconissance or for infrastructure domains to check for potentially IOC'd or sensitive records that could jeapordize an engagement or expose past client operations. 

## ✨ Features

    - Fetch A, AAAA, TXT, and CNAME records for a given domain
    - Retrieve historical subdomains using AlienVault OTX API
    - Save results to a .txt file using the --save flag
    - Easy-to-use CLI with clap argument parsing

## 🚀 Installation
Prerequisites
- Rust & Cargo (Install via rustup)
- An AlienVault OTX API Key (Sign up at otx.alienvault.com) - Not a hard requirement as the endpoint is avaliable without a valid API key. 

Clone & Build
```
git clone https://github.com/RedHeadSec/Domain-Check.rs.git
cd dns-lookup-tool
cargo build --release
```
## 🛠 Usage
Basic DNS Lookup

`cargo run -- --domain example.com --api-key YOUR_API_KEY`

Note: The API key does not appear to be needed to pull from the passive records endpoint, so it can be omitted unless you run into permission issues. 

Save Results to a File

`cargo run -- --domain example.com --api-key YOUR_API_KEY --save --file my_results`

- 🔹 Saves the output to my_results.txt.
- 🔹 If no file name is provided, defaults to results.txt.


## 📄 License
MIT License - Use freely, but give credit please. 
