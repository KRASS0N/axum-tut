use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use axum::{
    extract::{ConnectInfo, Multipart, State},
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Form, Router,
};
use sailfish::TemplateSimple;
use serde::{Deserialize, Serialize};
use sqlx::{
    postgres::{PgPool, PgPoolOptions},
    query,
};
use std::{env, net::SocketAddr, process::Command};
use time::Duration;
use tokio::{
    net::TcpListener,
    signal,
    task::{self, AbortHandle},
};
use tower_http::services::ServeDir;
use tower_sessions::{session_store::ExpiredDeletion, Expiry, Session, SessionManagerLayer};
use tower_sessions_sqlx_store::PostgresStore;

#[derive(Clone)]
struct SiteState {
    pool: PgPool,
}

#[derive(TemplateSimple)]
#[template(path = "../templates/hello.stpl")]
struct HelloTemplate {
    username: String,
    addr: String,
}

#[derive(TemplateSimple)]
#[template(path = "../templates/login.stpl")]
struct LoginTemplate<'a> {
    msg: &'a str,
}

#[derive(TemplateSimple)]
#[template(path = "../templates/signup.stpl")]
struct SignUpTemplate<'a> {
    msg: &'a str,
}

#[derive(TemplateSimple)]
#[template(path = "../templates/signup_success.stpl")]
struct SignUpSuccessTemplate {}

#[derive(TemplateSimple)]
#[template(path = "../templates/avatar.stpl")]
struct AvatarTemplate<'a> {
    msg: &'a str,
}

#[derive(TemplateSimple)]
#[template(path = "../templates/devlog1.stpl")]
struct Devlog1Template {}

#[derive(Deserialize)]
struct Login {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct SignUp {
    username: String,
    password: String,
    password2: String,
}

#[derive(Serialize, Deserialize, Default)]
struct User(String);
const USER_KEY: &str = "username";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    Command::new("python3")
        .args(["init_db.py"])
        .output()
        .expect("Failed to initialize database!");

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = TcpListener::bind(addr).await?;
    println!("Listening on address {}", addr.to_string());

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL unset!");
    let state_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;
    let state = SiteState { pool: state_pool };

    let session_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;
    let session_store = PostgresStore::new(session_pool);
    session_store.migrate().await?;

    let deletion_task = tokio::task::spawn(
        session_store
            .clone()
            .continuously_delete_expired(tokio::time::Duration::from_secs(1 * 60 * 60)), //1 hour
    );

    let session_layer = SessionManagerLayer::new(session_store)
        .with_expiry(Expiry::OnInactivity(Duration::hours(1)));

    let site = Router::new()
        .route("/", get(index))
        .route("/login", get(login))
        .route("/login", post(verify_login))
        .route("/signup", get(signup))
        .route("/signup", post(verify_signup))
        .route("/logout", get(logout_get))
        .route("/logout", post(logout))
        .route("/avatar", get(avatar))
        .route("/avatar", post(change_avatar))
        .route("/devlog1", get(devlog1))
        .nest_service("/static", ServeDir::new("static"))
        .with_state(state)
        .layer(session_layer);

    axum::serve(
        listener,
        site.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal(deletion_task.abort_handle()))
    .await?;

    Ok(())
}

async fn shutdown_signal(deletion_task_abort_handle: AbortHandle) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => { deletion_task_abort_handle.abort() },
        _ = terminate => { deletion_task_abort_handle.abort() },
    }
}

async fn index(session: Session, ConnectInfo(addr): ConnectInfo<SocketAddr>) -> impl IntoResponse {
    let user: User = session.get(USER_KEY).await.unwrap().unwrap_or_default();
    let ctx = HelloTemplate {
        username: user.0,
        addr: addr.to_string(),
    };

    Html(ctx.render_once().unwrap())
}

async fn login() -> impl IntoResponse {
    let ctx = LoginTemplate { msg: "" };

    Html(ctx.render_once().unwrap())
}

async fn verify_login(
    session: Session,
    State(state): State<SiteState>,
    Form(login): Form<Login>,
) -> impl IntoResponse {
    let loginfail = LoginTemplate {
        msg: "Login Failed!",
    };

    let result = query!(
        r#"SELECT Password FROM Users
        WHERE Username = $1"#,
        login.username
    )
    .fetch_one(&state.pool)
    .await;

    let Ok(user) = result else {
        return Html(loginfail.render_once().unwrap()).into_response();
    };

    let verifier = Argon2::default();
    let verify_result = task::spawn_blocking(move || {
        let password_hash = PasswordHash::new(&user.password).expect("Invalid password hash");
        verifier.verify_password(login.password.as_bytes(), &password_hash)
    })
    .await
    .unwrap();

    let Ok(_) = verify_result else {
        return Html(loginfail.render_once().unwrap()).into_response();
    };

    session.insert(USER_KEY, &login.username).await.unwrap();

    Redirect::to("/").into_response()
}

async fn logout(session: Session) -> impl IntoResponse {
    session.remove::<String>(USER_KEY).await.unwrap();
    Redirect::to("/")
}

// stops people from using links to log people out
async fn logout_get() -> impl IntoResponse {
    Redirect::to("/")
}

async fn signup() -> impl IntoResponse {
    let ctx = SignUpTemplate { msg: "" };

    Html(ctx.render_once().unwrap())
}

async fn verify_signup(
    State(state): State<SiteState>,
    Form(signup): Form<SignUp>,
) -> impl IntoResponse {
    if signup.password != signup.password2 {
        let ctx = SignUpTemplate {
            msg: "Passwords must match!",
        };
        Html(ctx.render_once().unwrap())
    } else {
        let salt = SaltString::generate(&mut OsRng);
        let hasher = Argon2::default();
        let hash = task::spawn_blocking(move || {
            hasher
                .hash_password(signup.password.as_bytes(), &salt)
                .expect("Password hash failed!")
                .to_string()
        })
        .await
        .unwrap();

        let result = query!(
            r#"INSERT INTO Users (Username, Password)
            VALUES ($1, $2)"#,
            signup.username,
            hash
        )
        .execute(&state.pool)
        .await;

        let Ok(_) = result else {
            let ctx = SignUpTemplate {
                msg: "Username in use!",
            };
            return Html(ctx.render_once().unwrap());
        };

        let ctx = SignUpSuccessTemplate {};
        Html(ctx.render_once().unwrap())
    }
}

async fn avatar() -> impl IntoResponse {
    let ctx = AvatarTemplate { msg: "" };

    Html(ctx.render_once().unwrap())
}

async fn change_avatar(
    State(state): State<SiteState>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    if let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap().to_string();
        let data_try = field.bytes().await;
        let Ok(data) = data_try else {
            let ctx = AvatarTemplate {
                msg: "File is too large!",
            };
            return Html(ctx.render_once().unwrap());
        };

        let ctx = AvatarTemplate {
            msg: &format!("Length of {} is {} bytes\n", name, data.len()),
        };
        Html(ctx.render_once().unwrap())
    } else {
        let ctx = AvatarTemplate {
            msg: "Empty request!",
        };
        Html(ctx.render_once().unwrap())
    }
}

async fn devlog1() -> impl IntoResponse {
    let ctx = Devlog1Template {};
    Html(ctx.render_once().unwrap())
}
