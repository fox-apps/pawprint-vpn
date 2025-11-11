use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::PathBuf;
use std::{collections::HashMap, fs};
use url::Url;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    // Start default config.
    // #[arg(short, long)]
    // vpn_start: bool,

    // Config key to parse it
    #[arg(short, long)]
    config: String,

    // Path to output json
    #[arg(short, long)]
    output: PathBuf,

    // Replace existing config
    #[arg(short, long)]
    force: bool,
}

#[derive(Debug, Clone)]
struct VlessConfig {
    uuid: String,
    address: String,
    port: u16,
    params: HashMap<String, String>,
    tag: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct XrayConfig {
    inbounds: Vec<serde_json::Value>,
    outbounds: Vec<serde_json::Value>,
}

fn parse_config(config: &str) -> Result<VlessConfig, Box<dyn std::error::Error>> {
    if !config.starts_with("vless://") {
        return Err("URL must start with vless://".into());
    }
    let url = Url::parse(config)?;

    let uuid = url.username().to_string();
    if uuid.is_empty() {
        return Err("UUID not found in URL".into());
    }

    let address = url.host_str().ok_or("Host not found in URL")?.to_string();
    let port = url.port().ok_or("Port not found in URL")?;

    let mut params = HashMap::new();
    for (key, value) in url.query_pairs() {
        params.insert(key.to_string(), value.to_string());
    }

    let tag = url.fragment().unwrap_or("VLESS-Config").to_string();

    Ok(VlessConfig {
        uuid,
        address,
        port,
        params,
        tag,
    })
}

fn build_config(vless_config: &VlessConfig) -> XrayConfig {
    let network_type = vless_config
        .params
        .get("type")
        .cloned()
        .unwrap_or_else(|| "tcp".to_string());

    let security = vless_config
        .params
        .get("security")
        .cloned()
        .unwrap_or_else(|| "tls".to_string());

    let mut stream_settings = json!({
        "network": network_type,
        "security": security,
    });

    if security == "reality" {
        let pbk = vless_config.params.get("pbk").cloned().unwrap_or_default();
        let sni = vless_config.params.get("sni").cloned().unwrap_or_default();
        let fp = vless_config
            .params
            .get("fp")
            .cloned()
            .unwrap_or_else(|| "chrome".to_string());
        let sid = vless_config.params.get("sid").cloned().unwrap_or_default();

        stream_settings["realitySettings"] = json!({
            "publicKey": pbk,
            "password": pbk,
            "fingerprint": fp,
            "serverName": sni,
            "shortId": sid,
            "spiderX": "/"
        });
    } else if security == "tls" {
        let sni = vless_config
            .params
            .get("sni")
            .cloned()
            .unwrap_or_else(|| vless_config.address.clone());

        stream_settings["tlsSettings"] = json!({
            "serverName": sni,
            "allowInsecure": false
        });
    }

    let mut user = json!({
        "id": vless_config.uuid,
        "encryption": "none",
        "level": 0
    });

    let flow = vless_config.params.get("flow").cloned();

    if let Some(flow_val) = flow {
        user["flow"] = json!(flow_val);
    }

    let outbound = json!({
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": vless_config.address,
                "port": vless_config.port,
                "users": [user]
            }]
        },
        "streamSettings": stream_settings,
        "tag": vless_config.tag
    });

    let inbound = json!({
        "port": 10808,
        "protocol": "socks",
        "settings": {
            "auth": "noauth",
            "udp": true
        },
        "tag": "socks-in"
    });

    XrayConfig {
        inbounds: vec![inbound],
        outbounds: vec![outbound],
    }
}

fn save_config(
    config: &XrayConfig,
    output_path: &PathBuf,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if output_path.exists() && !force {
        return Err(format!(
            "File already exists: {}. Use --force to overwrite.",
            output_path.display()
        )
        .into());
    }

    let json_content = serde_json::to_string_pretty(config)?;

    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let temp_path = PathBuf::from(format!("{}.tmp", output_path.display()));
    fs::write(&temp_path, &json_content)?;
    fs::rename(&temp_path, output_path)?;

    println!("✓ Config saved to: {}", output_path.display());
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("Parsing VLESS URL...");
    let vless_config = parse_config(&args.config)?;
    println!("UUID: {}", vless_config.uuid);
    println!("Server: {}:{}", vless_config.address, vless_config.port);
    println!("Tag: {}", vless_config.tag);

    println!("\n🔨 Building Xray configuration...");
    let xray_config = build_config(&vless_config);

    let output_path = args.output;
    println!("\nSaving configuration...");
    save_config(&xray_config, &output_path, args.force)?;

    Ok(())
}
