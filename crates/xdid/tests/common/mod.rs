use std::{
    convert::Infallible,
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
};

use hyper::{
    Response,
    StatusCode,
    header::{
        HeaderValue,
        LOCATION,
    },
    server::conn::http1::Builder,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use xdid::{
    core::{
        Method,
        did::Did,
        document::Document,
    },
    methods::web::{
        Config,
        MethodDidWeb,
        target::TargetPolicy,
    },
    resolver::DidResolver,
};

/// The one response a served DID answers with.
pub struct Reply {
    status:   StatusCode,
    location: Option<&'static str>,
    body:     String,
}

impl Reply {
    pub const fn ok(body: String) -> Self {
        Self {
            status: StatusCode::OK,
            location: None,
            body,
        }
    }

    pub const fn redirect(to: &'static str) -> Self {
        Self {
            status:   StatusCode::FOUND,
            location: Some(to),
            body:     String::new(),
        }
    }
}

pub fn resolver_with(config: Config) -> DidResolver {
    let method = MethodDidWeb::with_config(config).expect("resolver construction");
    DidResolver::with_methods([Box::new(method) as Box<dyn Method>])
}

/// Permits the loopback target the test server runs on.
pub fn local_config() -> Config {
    Config {
        target: TargetPolicy::AllowLocal,
        ..Config::default()
    }
}

pub fn document_body(did: &Did) -> String {
    serde_json::to_string(&Document::new(did.clone())).expect("serialization should succeed")
}

/// Serves one reply at a fresh `did:web:localhost%3A<port>`, and returns that
/// DID.
pub async fn serve(make: impl FnOnce(&Did) -> Reply) -> Did {
    let port = port_check::free_local_port().expect("free port should be available");
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(addr).await.expect("listener should bind");

    let did = Did::from_str(&format!("did:web:localhost%3A{port}")).expect("valid DID");
    let reply = Arc::new(make(&did));

    let handler = move |_| {
        let reply = reply.clone();
        async move {
            let mut res = Response::new(reply.body.clone());
            *res.status_mut() = reply.status;

            if let Some(to) = reply.location {
                res.headers_mut()
                    .insert(LOCATION, HeaderValue::from_static(to));
            }

            Ok::<_, Infallible>(res)
        }
    };

    tokio::spawn(async move {
        loop {
            let (stream, _) = listener
                .accept()
                .await
                .expect("listener should accept connections");

            // Logged rather than asserted on. A server fault reaches the test
            // as whatever the client concluded, which is what each test checks.
            if let Err(e) = Builder::new()
                .serve_connection(TokioIo::new(stream), service_fn(&handler))
                .await
            {
                eprintln!("test server connection error: {e}");
            }
        }
    });

    did
}
