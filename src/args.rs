use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "DNS_Check")]
#[command(about = "A tool to perform quick live and historical DNS checks prior to engagements or during!", long_about = None)]
pub struct CliArgs {
    #[arg(short = 'A',long = "av-api_key",help = "Your OTX AlienVault API Key found here: https://otx.alienvault.com/settings. (May want to include this if you are having issues getting historical records.)")]
    pub av_api_key: Option<String>,

    #[arg(short = 'S', long = "st-api-key", help = "API key for SecurityTrails (Optional for historical TXT records)")]
    pub st_api_key: Option<String>,

    #[arg(short = 'd',long = "domian",help = "Domain to perform the search on!")]
    pub domain: String, 

    #[arg(short = 's', long = "save", help = "Flag to set saving to file")]
    pub save: bool,

    #[arg(short = 'f', long = "file_name", help = "File name to save as", default_value = "Results")]
    pub file_name: String,
}