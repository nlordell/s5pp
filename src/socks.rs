use crate::auth::Authentication;
use anyhow::{bail, ensure, Result};
use std::io::{self, BufWriter, Read, Write};

const VER: u8 = 0x05;

const AUTH_NONE: u8 = 0x00;
const AUTH_LOGIN: u8 = 0x02;
const AUTH_UNSUPPORTED: u8 = 0xff;

const LOGIN_VER: u8 = 0x01;
const LOGIN_SUCCESS: u8 = 0x00;

pub fn client_handshake<R, W>(input: &mut R, output: &mut W) -> Result<()>
where
    R: Read,
    W: Write,
{
    let version = input.byte()?;
    ensure!(version == VER, "unsupported socks version {version:#x}");

    let nauths = input.byte()?;
    let auths = input
        .take(nauths as _)
        .bytes()
        .collect::<Result<Vec<_>, _>>()?;
    if !auths.contains(&AUTH_NONE) {
        output.write_all(&[VER, AUTH_UNSUPPORTED])?;
        bail!("unsupported auth {auths:?}");
    }
    output.write_all(&[VER, AUTH_NONE])?;

    Ok(())
}

pub fn proxy_handshake<R, W>(input: &mut R, output: &mut W, auth: Authentication) -> Result<()>
where
    R: Read,
    W: Write,
{
    let nauths = 1;
    output.write_all(&[VER, nauths, AUTH_LOGIN])?;

    let version = input.byte()?;
    ensure!(version == VER, "unsupported socks version {version:#x}");

    let cauth = input.byte()?;
    ensure!(cauth == AUTH_LOGIN, "unsupported auth");

    {
        let mut writer = BufWriter::new(output);
        writer.write_all(&[LOGIN_VER, auth.username.len().try_into()?])?;
        writer.write_all(auth.username.as_bytes())?;
        writer.write_all(&[auth.password.len().try_into()?])?;
        writer.write_all(auth.password.as_bytes())?;
        writer.flush()?;
    }

    let vauth = input.byte()?;
    ensure!(vauth == LOGIN_VER, "unsupported login version {vauth:#x}");

    let status = input.byte()?;
    ensure!(status == LOGIN_SUCCESS, "authentication failed");

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
