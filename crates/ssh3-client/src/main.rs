use std::path::PathBuf;
use std::process::ExitCode;

use http::Uri;
use ssh3_client::{
    AgentSelection, ClientConfig, OidcConfig, SessionRequest, TrustStrategy, load_certificates,
    run_session_stdio,
};

fn usage(program: &str) -> String {
    format!(
        "Usage: {program} [--server-name NAME] [--user NAME] [--identity PATH | --agent [--agent-socket PATH] | --agent-key PATH [--agent-socket PATH] | --password PASS | --password-file PATH | --bearer-token TOKEN | --bearer-token-file PATH | --use-oidc ISSUER --oidc-client-id ID [--oidc-client-secret SECRET] [--no-pkce]] [--forward-agent [--agent-socket PATH]] [--ca-cert PATH] [--insecure] URL [COMMAND...]\n\
         \n\
         Connects to an SSH3 server over QUIC/HTTP3. If COMMAND is omitted, requests a shell."
    )
}

fn parse_args() -> Result<Option<(ClientConfig, SessionRequest)>, String> {
    let mut args = std::env::args();
    let program = args.next().unwrap_or_else(|| "ssh3-client".to_string());
    let mut args = args.peekable();

    let mut server_name: Option<String> = None;
    let mut username: Option<String> = None;
    let mut identity_file: Option<PathBuf> = None;
    let mut agent: Option<AgentSelection> = None;
    let mut agent_socket: Option<PathBuf> = None;
    let mut forward_agent = false;
    let mut password: Option<String> = None;
    let mut bearer_token: Option<String> = None;
    let mut oidc_issuer_url: Option<String> = None;
    let mut oidc_client_id: Option<String> = None;
    let mut oidc_client_secret: Option<String> = None;
    let mut oidc_use_pkce = true;
    let mut ca_cert: Option<PathBuf> = None;
    let mut insecure = false;
    let mut url: Option<Uri> = None;
    let mut command = Vec::new();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--server-name" => {
                server_name = Some(
                    args.next()
                        .ok_or_else(|| "missing value for --server-name".to_string())?,
                );
            }
            "--user" => {
                username = Some(
                    args.next()
                        .ok_or_else(|| "missing value for --user".to_string())?,
                );
            }
            "--identity" => {
                identity_file = Some(PathBuf::from(
                    args.next()
                        .ok_or_else(|| "missing value for --identity".to_string())?,
                ));
            }
            "--agent" => {
                if agent.is_some() {
                    return Err("use either --agent or --agent-key, not both".to_string());
                }
                agent = Some(AgentSelection::First);
            }
            "--agent-key" => {
                if agent.is_some() {
                    return Err("use either --agent or --agent-key, not both".to_string());
                }
                agent = Some(AgentSelection::PublicKey(PathBuf::from(
                    args.next()
                        .ok_or_else(|| "missing value for --agent-key".to_string())?,
                )));
            }
            "--agent-socket" => {
                agent_socket =
                    Some(PathBuf::from(args.next().ok_or_else(|| {
                        "missing value for --agent-socket".to_string()
                    })?));
            }
            "--forward-agent" => forward_agent = true,
            "--password" => {
                password = Some(
                    args.next()
                        .ok_or_else(|| "missing value for --password".to_string())?,
                );
            }
            "--password-file" => {
                let path = PathBuf::from(
                    args.next()
                        .ok_or_else(|| "missing value for --password-file".to_string())?,
                );
                password = Some(
                    std::fs::read_to_string(&path)
                        .map_err(|err| format!("failed to read password file: {err}"))?
                        .trim_end_matches(['\r', '\n'])
                        .to_string(),
                );
            }
            "--bearer-token" => {
                bearer_token = Some(
                    args.next()
                        .ok_or_else(|| "missing value for --bearer-token".to_string())?,
                );
            }
            "--bearer-token-file" => {
                let path = PathBuf::from(
                    args.next()
                        .ok_or_else(|| "missing value for --bearer-token-file".to_string())?,
                );
                bearer_token = Some(
                    std::fs::read_to_string(&path)
                        .map_err(|err| format!("failed to read bearer token file: {err}"))?,
                );
            }
            "--use-oidc" => {
                oidc_issuer_url = Some(
                    args.next()
                        .ok_or_else(|| "missing value for --use-oidc".to_string())?,
                );
            }
            "--oidc-client-id" => {
                oidc_client_id = Some(
                    args.next()
                        .ok_or_else(|| "missing value for --oidc-client-id".to_string())?,
                );
            }
            "--oidc-client-secret" => {
                oidc_client_secret = Some(
                    args.next()
                        .ok_or_else(|| "missing value for --oidc-client-secret".to_string())?,
                );
            }
            "--no-pkce" => oidc_use_pkce = false,
            "--ca-cert" => {
                ca_cert = Some(PathBuf::from(
                    args.next()
                        .ok_or_else(|| "missing value for --ca-cert".to_string())?,
                ));
            }
            "--insecure" => insecure = true,
            "--help" | "-h" => {
                println!("{}", usage(&program));
                return Ok(None);
            }
            "--" => {
                command.extend(args);
                break;
            }
            value if value.starts_with('-') && url.is_none() => {
                return Err(format!(
                    "unrecognized argument: {value}\n\n{}",
                    usage(&program)
                ));
            }
            value if url.is_none() => {
                url = Some(
                    value
                        .parse::<Uri>()
                        .map_err(|err| format!("invalid URL: {err}"))?,
                );
            }
            value => command.push(value.to_string()),
        }
    }

    let Some(url) = url else {
        return Err(usage(&program));
    };
    if insecure && ca_cert.is_some() {
        return Err("use either --ca-cert or --insecure, not both".to_string());
    }
    let has_oidc_client_secret = oidc_client_secret.is_some();
    let oidc = match (oidc_issuer_url, oidc_client_id) {
        (Some(issuer_url), Some(client_id)) => Some(OidcConfig {
            issuer_url,
            client_id,
            client_secret: oidc_client_secret,
            use_pkce: oidc_use_pkce,
        }),
        (None, None) => None,
        (Some(_), None) => {
            return Err("--use-oidc requires --oidc-client-id".to_string());
        }
        (None, Some(_)) => {
            return Err("--oidc-client-id requires --use-oidc".to_string());
        }
    };
    if oidc.is_none() && has_oidc_client_secret {
        return Err("--oidc-client-secret requires --use-oidc".to_string());
    }

    let auth_methods = usize::from(identity_file.is_some())
        + usize::from(agent.is_some())
        + usize::from(password.is_some())
        + usize::from(bearer_token.is_some())
        + usize::from(oidc.is_some());
    if auth_methods > 1 {
        return Err(
            "use either --identity, --agent/--agent-key, --password/--password-file, --bearer-token/--bearer-token-file, or --use-oidc".to_string(),
        );
    }
    if agent.is_some() && username.is_none() {
        return Err("--agent/--agent-key requires --user".to_string());
    }
    if password.is_some() && username.is_none() {
        return Err("--password/--password-file requires --user".to_string());
    }

    let mut config = ClientConfig::new(url);
    config.server_name = server_name;
    config.username = username;
    config.identity_file = identity_file;
    config.agent = agent;
    config.agent_socket = agent_socket;
    config.forward_agent = forward_agent;
    config.password = password;
    config.bearer_token = bearer_token.map(|token| token.trim().to_string());
    config.oidc = oidc;
    config.trust = if insecure {
        TrustStrategy::Insecure
    } else if let Some(path) = ca_cert {
        TrustStrategy::Certificates(
            load_certificates(&path)
                .map_err(|err| format!("failed to load CA certificate: {err}"))?,
        )
    } else {
        TrustStrategy::WebPkiRoots
    };

    let request = if command.is_empty() {
        SessionRequest::Shell
    } else {
        SessionRequest::Exec(command.join(" "))
    };
    Ok(Some((config, request)))
}

#[tokio::main]
async fn main() -> ExitCode {
    let (config, request) = match parse_args() {
        Ok(Some(parsed)) => parsed,
        Ok(None) => return ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::FAILURE;
        }
    };

    match run_session_stdio(&config, request).await {
        Ok(status) => ExitCode::from(status as u8),
        Err(err) => {
            eprintln!("ssh3-client failed: {err}");
            ExitCode::FAILURE
        }
    }
}
