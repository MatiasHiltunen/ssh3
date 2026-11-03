use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueHint, error::ErrorKind};
use ssh3_server::{ServerConfig, run_with_self_signed};

#[derive(Debug, Parser)]
#[command(
    name = "ssh3-server",
    version,
    about = "Starts a minimal Rust SSH3 server with a self-signed certificate."
)]
struct Cli {
    #[arg(long, value_name = "ADDR")]
    bind: Option<SocketAddr>,

    #[arg(long, value_name = "NAME", action = clap::ArgAction::Append)]
    hostname: Vec<String>,

    #[arg(long = "server-header", value_name = "TEXT")]
    server_header: Option<String>,

    #[arg(long)]
    require_auth: bool,

    #[arg(
        long,
        help = "Allow unauthenticated non-loopback access. UNSAFE: development use only."
    )]
    allow_insecure_unauthenticated_remote: bool,

    #[arg(long)]
    enable_password_login: bool,

    #[arg(
        long = "authorized-identity",
        value_name = "PATH",
        value_hint = ValueHint::FilePath,
        action = clap::ArgAction::Append
    )]
    authorized_identity: Vec<PathBuf>,

    #[arg(long, value_name = "NAME")]
    user: Option<String>,

    #[arg(long, value_name = "PATH", value_hint = ValueHint::FilePath)]
    shell: Option<String>,
}

fn parse_args() -> Result<ServerConfig, clap::Error> {
    let cli = Cli::try_parse()?;
    Ok(config_from_cli(cli))
}

fn config_from_cli(cli: Cli) -> ServerConfig {
    let mut config = ServerConfig::default();
    if let Some(bind_addr) = cli.bind {
        config.bind_addr = bind_addr;
    }
    if !cli.hostname.is_empty() {
        config.cert_subject_alt_names = cli.hostname;
    }
    if let Some(server_header) = cli.server_header {
        config.server_header = server_header;
    }
    config.require_authentication = cli.require_auth;
    config.allow_insecure_unauthenticated_remote = cli.allow_insecure_unauthenticated_remote;
    config.enable_password_login = cli.enable_password_login;
    if !cli.authorized_identity.is_empty() {
        config.authorized_identity_paths = cli.authorized_identity;
    }
    if let Some(user) = cli.user {
        config.default_user = Some(user);
    }
    if let Some(shell) = cli.shell {
        config.shell = Some(shell);
    }
    config
}

#[tokio::main]
async fn main() -> ExitCode {
    let config = match parse_args() {
        Ok(config) => config,
        Err(err) => {
            let status = match err.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => ExitCode::SUCCESS,
                _ => ExitCode::FAILURE,
            };
            err.print().ok();
            return status;
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn default_and_external_bind_do_not_implicitly_enable_the_insecure_override() {
        let defaults = config_from_cli(Cli::try_parse_from(["ssh3-server"]).unwrap());
        assert!(defaults.bind_addr.ip().is_loopback());
        assert!(!defaults.allow_insecure_unauthenticated_remote);
        for address in ["0.0.0.0:4433", "[::]:4433"] {
            let config =
                config_from_cli(Cli::try_parse_from(["ssh3-server", "--bind", address]).unwrap());
            assert!(!config.allow_insecure_unauthenticated_remote);
            assert!(!config.require_authentication);
        }
    }

    #[test]
    fn insecure_override_is_explicit_and_preserves_authentication_options() {
        let config = config_from_cli(
            Cli::try_parse_from([
                "ssh3-server",
                "--bind",
                "[::]:4433",
                "--allow-insecure-unauthenticated-remote",
                "--require-auth",
                "--authorized-identity",
                "authorized_keys",
                "--enable-password-login",
            ])
            .unwrap(),
        );
        assert!(config.allow_insecure_unauthenticated_remote);
        assert!(config.require_authentication);
        assert!(config.enable_password_login);
        assert_eq!(
            config.authorized_identity_paths,
            vec![PathBuf::from("authorized_keys")]
        );
    }

    #[test]
    fn insecure_override_help_explains_the_development_risk() {
        let help = Cli::command().render_long_help().to_string();
        assert!(help.contains("--allow-insecure-unauthenticated-remote"));
        assert!(help.contains("UNSAFE: development use only"));
    }
}
