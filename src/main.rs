mod dns_header;
mod dns_message;
mod dns_question_and_answer;
mod forwarder;
mod local;
mod server;

use clap::Parser;
use server::DnsServer;

#[derive(Parser, Debug)]
#[command(name = "dns-server")]
struct Args {
    /// Upstream DNS resolver address (e.g., 8.8.8.8:53)
    #[arg(long)]
    resolver: Option<String>,
}

fn main() {
    println!("Logs from your program will appear here!");

    let args = Args::parse();

    if let Some(ref addr) = args.resolver {
        println!("Using resolver: {}", addr);
    }

    let server =
        DnsServer::new("127.0.0.1:2053", args.resolver).expect("Failed to create DNS server");

    server.run();
}
