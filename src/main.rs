use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    vpn_start: bool,
    config: String,
}

fn main() {
    let args = Args::parse();
    println!("Is it config {}??", args.config);
}
