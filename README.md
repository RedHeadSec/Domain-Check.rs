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

`target/release/Domain-Check -d redheadsec.tech -A OTX_KEY`

Note: An API key is now required to hit the passive_dns endpoint, else you will see 429 response codes.

<img width="1359" height="1099" alt="image" src="https://github.com/user-attachments/assets/0753eaef-e289-461d-9d66-5ff60c74d432" />


Save Results to a File

`DNS-Check --domain example.com  --save --file my_results`

- 🔹 Saves the output to my_results.txt.
- 🔹 If no file name is provided, defaults to results.txt.

## To-do
Implement SecurityTrails Records

## 📄 License
MIT License - Use freely, but give credit please. 
