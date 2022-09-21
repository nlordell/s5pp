mod auth;

use self::auth::Authentication;
use anyhow::{bail, ensure, Context as _, Result};
use clap::Parser;
use std::{
    io::{self, BufReader, BufWriter, Read, Write},
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
    tracing::info!(%peer, "received client connection");

    let mut client_reader = BufReader::new(client.try_clone()?);

    tracing::debug!(%proxy, "connecting to remote");
    let mut proxy = TcpStream::connect(proxy)?;
    let mut proxy_reader = BufReader::new(proxy.try_clone()?);

    tracing::debug!("performing client handshake");
    client_handshake(&mut client_reader, &mut client).context("client handshake failed")?;

    tracing::debug!("performing remote handshake");
    proxy_handshake(&mut proxy_reader, &mut proxy, auth).context("proxy handshake failed")?;

    let c2p = thread::spawn(move || io::copy(&mut client_reader, &mut proxy));
    let p2c = thread::spawn(move || io::copy(&mut proxy_reader, &mut client));

    c2p.join().unwrap()?;
    p2c.join().unwrap()?;

    tracing::info!(%peer, "closing client connection");
    Ok(())
}

fn client_handshake<R, W>(input: &mut R, output: &mut W) -> Result<()>
where
    R: Read,
    W: Write,
{
    let version = input.byte()?;
    ensure!(version == 5, "unsupported socks version {version:#x}");

    let nauths = input.byte()?;
    let auths = input
        .take(nauths as _)
        .bytes()
        .collect::<Result<Vec<_>, _>>()?;
    if !auths.contains(&0) {
        output.write_all(b"\x05\xff")?;
        bail!("unsupported auth {auths:?}");
    }
    output.write_all(b"\x05\x00")?;

    Ok(())
}

fn proxy_handshake<R, W>(input: &mut R, output: &mut W, auth: Authentication) -> Result<()>
where
    R: Read,
    W: Write,
{
    output.write_all(b"\x05\x01\x02")?;

    let version = input.byte()?;
    ensure!(version == 5, "unsupported socks version {version:#x}");

    let cauth = input.byte()?;
    ensure!(cauth == 2, "unsupported auth");

    {
        let mut writer = BufWriter::new(output);
        writer.write_all(&[0x01, auth.username.len().try_into()?])?;
        writer.write_all(auth.username.as_bytes())?;
        writer.write_all(&[auth.password.len().try_into()?])?;
        writer.write_all(auth.password.as_bytes())?;
        writer.flush()?;
    }

    let vauth = input.byte()?;
    ensure!(vauth == 1, "unsupported auth version {vauth:#x}");

    let status = input.byte()?;
    ensure!(status == 0, "authentication failed");

    Ok(())
}

trait ByteExt {
    fn byte(&mut self) -> io::Result<u8>;
}

impl<R> ByteExt for R
where
    R: Read,
{
    fn byte(&mut self) -> io::Result<u8> {
        self.bytes().next().ok_or(io::ErrorKind::UnexpectedEof)?
    }
}
