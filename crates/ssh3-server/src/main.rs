use std::net::SocketAddr;
use std::process::ExitCode;

use ssh3_server::{ServerConfig, run_with_self_signed};

fn usage(program: &str) -> String {
    format!(
        "Usage: {program} [--bind ADDR] [--hostname NAME] [--server-header TEXT] [--user NAME] [--shell PATH] [--require-auth] [--authorized-identity PATH] [--enable-password-login]\n\
         \n\
         Starts a minimal Rust SSH3 server with a self-signed certificate."
    )
}

fn parse_args() -> Result<Option<ServerConfig>, String> {
    let mut config = ServerConfig::default();
    let mut args = std::env::args();
    let program = args.next().unwrap_or_else(|| "ssh3-server".to_string());
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bind" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value for --bind".to_string())?;
                config.bind_addr = value
                    .parse::<SocketAddr>()
                    .map_err(|err| format!("invalid --bind value: {err}"))?;
            }
            "--hostname" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value for --hostname".to_string())?;
                config.cert_subject_alt_names = vec![value];
            }
            "--server-header" => {
                config.server_header = args
                    .next()
                    .ok_or_else(|| "missing value for --server-header".to_string())?;
            }
            "--require-auth" => {
                config.require_authentication = true;
            }
            "--enable-password-login" => {
                config.enable_password_login = true;
            }
            "--authorized-identity" => {
                config.authorized_identity_paths.push(
                    args.next()
                        .ok_or_else(|| "missing value for --authorized-identity".to_string())?
                        .into(),
                );
            }
            "--user" => {
                config.default_user = Some(
                    args.next()
                        .ok_or_else(|| "missing value for --user".to_string())?,
                );
            }
            "--shell" => {
                config.shell = Some(
                    args.next()
                        .ok_or_else(|| "missing value for --shell".to_string())?,
                );
            }
            "--help" | "-h" => {
                println!("{}", usage(&program));
                return Ok(None);
            }
            other => {
                return Err(format!(
                    "unrecognized argument: {other}\n\n{}",
                    usage(&program)
                ));
            }
        }
    }

    Ok(Some(config))
}

#[tokio::main]
async fn main() -> ExitCode {
    let config = match parse_args() {
        Ok(Some(config)) => config,
        Ok(None) => return ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::FAILURE;
        }
    };

    match run_with_self_signed(config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("ssh3-server failed: {err}");
            ExitCode::FAILURE
        }
    }
}
