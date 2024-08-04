//! Redirect all HTTP requests to HTTPs.

use std::net::SocketAddr;

use rocket::http::Status;
use rocket::tracing::Level;
use rocket::{route, Error, Request, Data, Route, Orbit, Rocket, Ignite};
use rocket::fairing::{Fairing, Info, Kind};
use rocket::response::Redirect;
use rocket::listener::tcp::TcpListener;
use rocket::trace::Trace;

#[derive(Debug, Clone, Copy, Default)]
pub struct Redirector(u16);

#[derive(Debug, Clone)]
pub struct Config {
    server: rocket::Config,
    tls_addr: SocketAddr,
}

impl Redirector {
    pub fn on(port: u16) -> Self {
        Redirector(port)
    }

    // Route function that gets called on every single request.
    fn redirect<'r>(req: &'r Request, _: Data<'r>) -> route::BoxFuture<'r> {
        // FIXME: Check the host against a whitelist!
        let config = req.rocket().state::<Config>().expect("managed Self");
        if let Some(host) = req.host() {
            let domain = host.domain();
            let https_uri = match config.tls_addr.port() {
                443 => format!("https://{domain}{}", req.uri()),
                port => format!("https://{domain}:{port}{}", req.uri()),
            };

            route::Outcome::from(req, Redirect::permanent(https_uri)).pin()
        } else {
            route::Outcome::from(req, Status::BadRequest).pin()
        }
    }

    // Launch an instance of Rocket than handles redirection on `self.port`.
    pub async fn try_launch(self, config: Config) -> Result<Rocket<Ignite>, Error> {
        use rocket::http::Method::*;

        rocket::span_info!("HTTP -> HTTPS Redirector" => {
            info!(from =  self.0, to = config.tls_addr.port(),  "redirecting");
        });

        // Build a vector of routes to `redirect` on `<path..>` for each method.
        let redirects = [Get, Put, Post, Delete, Options, Head, Trace, Connect, Patch]
            .into_iter()
            .map(|m| Route::new(m, "/<path..>", Self::redirect))
            .collect::<Vec<_>>();

        let addr = SocketAddr::new(config.tls_addr.ip(), self.0);
        rocket::custom(&config.server)
            .manage(config)
            .mount("/", redirects)
            .try_launch_on(TcpListener::bind(addr))
            .await
    }
}

#[rocket::async_trait]
impl Fairing for Redirector {
    fn info(&self) -> Info {
        Info {
            name: "HTTP -> HTTPS Redirector",
            kind: Kind::Liftoff | Kind::Singleton
        }
    }

    async fn on_liftoff(&self, rocket: &Rocket<Orbit>) {
        let Some(tls_addr) = rocket.endpoints().find_map(|e| e.tls()?.tcp()) else {
            rocket::span_warn!("HTTP -> HTTPS Redirector" => {
                warn!("Main instance is not being served over TLS/TCP.\n\
                    Redirector refusing to start.");
            });

            return;
        };

        let config = Config {
            tls_addr,
            server: rocket::Config {
                log_level: Some(Level::ERROR),
                ..rocket.config().clone()
            },
        };

        let this = *self;
        let shutdown = rocket.shutdown();
        rocket::tokio::spawn(async move {
            if let Err(e) = this.try_launch(config).await {
                span_error!("HTTP -> HTTPS Redirector", "failed to start" => {
                    e.trace_error();
                    info!("shutting down main instance");
                });

                shutdown.notify();
            }
        });
    }
}
