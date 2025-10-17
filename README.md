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

`DNS-Check --domain example.com`

Note: An API key is now required to hit the passive_dns endpoint, else you will see 429 response codes.

![image](https://github.com/user-attachments/assets/0f0cfb41-919f-41c2-972e-e25ef360af95)

Save Results to a File

`DNS-Check --domain example.com  --save --file my_results`

- 🔹 Saves the output to my_results.txt.
- 🔹 If no file name is provided, defaults to results.txt.

## To-do
Implement SecurityTrails Records

## 📄 License
MIT License - Use freely, but give credit please. 
