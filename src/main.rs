use clap::Parser;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenUrl,
};
use std::borrow::Cow;
use std::convert::Infallible;
use std::sync::mpsc;
use url::Url;

#[derive(Parser, Debug)]
pub struct Args {
    #[clap(long)]
    client_id: String,
    #[clap(long)]
    client_secret: Option<String>,
    #[clap(long)]
    auth_url: Url,
    #[clap(long)]
    token_url: Url,
    #[clap(long)]
    redirect_url: Url,
    #[clap(long)]
    implicit_flow: bool,
    #[clap(long, short)]
    scopes: Vec<String>,
}

pub struct ChallengeRequest {}

fn oauth_clent(args: &Args) -> BasicClient {
    BasicClient::new(
        ClientId::new(args.client_id.clone()),
        args.client_secret.clone().map(ClientSecret::new),
        AuthUrl::from_url(args.auth_url.clone()),
        Some(TokenUrl::from_url(args.token_url.clone())),
    )
    .set_redirect_uri(RedirectUrl::from_url(args.redirect_url.clone()))
}

fn oauth_url(args: &Args, oauth_client: &BasicClient) -> (Url, CsrfToken, PkceCodeVerifier) {
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let mut auth_url = oauth_client
        .authorize_url(CsrfToken::new_random)
        .set_pkce_challenge(pkce_challenge);

    if args.implicit_flow {
        auth_url = auth_url.use_implicit_flow();
    }

    for scope in args.scopes.iter() {
        auth_url = auth_url.add_scope(Scope::new(scope.to_string()))
    }

    let (auth_url, csrf_token) = auth_url.url();

    (auth_url, csrf_token, pkce_verifier)
}

fn get_query_param<'a>(req: &'a Request<Body>, key: &str) -> Option<Cow<'a, str>> {
    req.uri().query().and_then(|query| {
        form_urlencoded::parse(query.as_bytes()).find_map(|(query_key, value)| {
            if query_key == key {
                Some(value)
            } else {
                None
            }
        })
    })
}

async fn handle_redirect(
    req: Request<Body>,
    sender: mpsc::Sender<(CsrfToken, AuthorizationCode)>,
) -> Result<Response<Body>, Infallible> {
    match (
        get_query_param(&req, "state"),
        get_query_param(&req, "code"),
    ) {
        (Some(state), Some(code)) => {
            sender
                .send((
                    CsrfToken::new(state.to_string()),
                    AuthorizationCode::new(code.to_string()),
                ))
                .expect("Could not send authorization code");
            Ok(Response::new(Body::from("Success! Return to console (:")))
        }
        _ => Ok(Response::new(Body::from("Server sent invalid redirect :/"))),
    }
}

fn wait_for_redirect(args: &Args) -> (CsrfToken, AuthorizationCode) {
    let (sender, receiver) = mpsc::channel();

    let make_service = make_service_fn(move |_| {
        let sender = sender.clone();
        let service = service_fn(move |req| handle_redirect(req, sender.clone()));
        async move { Ok::<_, Infallible>(service) }
    });

    let server = Server::bind(
        &args
            .redirect_url
            .socket_addrs(|| None)
            .expect("redirect url should be a bindable address")[0],
    )
    .serve(make_service);

    tokio::spawn(async move {
        if let Err(e) = server.await {
            eprintln!("server error: {}", e);
        }
    });

    receiver
        .recv()
        .expect("Could not receive authorization code")
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let oauth_client = oauth_clent(&args);
    let (auth_url, csrf_token, pkce_verifier) = oauth_url(&args, &oauth_client);

    if opener::open(auth_url.to_string()).is_err() {
        eprintln!("Open url in browser: {}", auth_url);
    }

    let (server_token, authorization_code) = wait_for_redirect(&args);
    if server_token.secret() != csrf_token.secret() {
        panic!("Server state mismatch")
    }
    let token_response = oauth_client
        .exchange_code(authorization_code)
        .set_pkce_verifier(pkce_verifier)
        .request_async(oauth2::reqwest::async_http_client)
        .await
        .expect("Unable to get token response");

    println!(
        "{}",
        serde_json::to_string_pretty(&token_response)
            .expect("token response can't be serialized to json")
    )
}
