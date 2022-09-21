mod auth;
mod socks;

use crate::auth::Authentication;
use anyhow::{Context as _, Result};
use clap::Parser;
use std::{
    io::{self, BufReader},
    net::{SocketAddr, TcpListener, TcpStream},
    thread,
};

#[derive(Debug, Parser)]
struct Args {
    /// The socket address of the remote proxy.
    #[clap(short, long, env)]
    proxy: SocketAddr,

    /// The authentication for the remote proxy.
    #[clap(short, long, env)]
    auth: Authentication,

    /// The local bind address for the Socks5 proxy.
    #[clap(short, long, env, default_value = "127.0.0.1:5005")]
    bind: SocketAddr,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    tracing::debug!("starting with {args:#?}");

    let listener = TcpListener::bind(args.bind)?;
    for client in listener.incoming() {
        let proxy = args.proxy;
        let auth = args.auth.clone();

        let client = client?;
        thread::spawn(move || {
            if let Err(err) = connection(client, proxy, auth) {
                tracing::warn!(?err, "connection error");
            }
        });
    }

    Ok(())
}

fn connection(mut client: TcpStream, proxy: SocketAddr, auth: Authentication) -> Result<()> {
    let peer = client.peer_addr()?;
    tracing::info!(%peer, "opened client connection");

    let mut client_reader = BufReader::new(client.try_clone()?);

    tracing::debug!(%proxy, "connecting to remote");
    let mut proxy = TcpStream::connect(proxy)?;
    let mut proxy_reader = BufReader::new(proxy.try_clone()?);

    tracing::debug!("performing client handshake");
    socks::client_handshake(&mut client_reader, &mut client)
        .context("inbound client handshake failed")?;

    tracing::debug!("performing remote handshake");
    socks::proxy_handshake(&mut proxy_reader, &mut proxy, auth)
        .context("outbound proxy handshake failed")?;

    let c2p = thread::spawn(move || io::copy(&mut client_reader, &mut proxy));
    let p2c = thread::spawn(move || io::copy(&mut proxy_reader, &mut client));

    c2p.join().unwrap()?;
    p2c.join().unwrap()?;

    tracing::info!(%peer, "closing client connection");
    Ok(())
}
