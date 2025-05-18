use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use axum::{
    extract::ConnectInfo,
    extract::State,
    response::Html,
    routing::{get, post},
    Form, Router,
};
use sailfish::TemplateSimple;
use serde::Deserialize;
use sqlx::{
    postgres::{PgPool, PgPoolOptions},
    query,
};
use std::{env, net::SocketAddr, process::Command};
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
    addr: String,
}

#[derive(TemplateSimple)]
#[template(path = "../templates/login.stpl")]
struct LoginTemplate<'a> {
    msg: &'a str,
}

#[derive(TemplateSimple)]
#[template(path = "../templates/login_success.stpl")]
struct LoginSuccessTemplate {
    username: String,
}

#[derive(TemplateSimple)]
#[template(path = "../templates/signup.stpl")]
struct SignUpTemplate<'a> {
    msg: &'a str,
}

#[derive(TemplateSimple)]
#[template(path = "../templates/signup_success.stpl")]
struct SignUpSuccessTemplate {}

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
            .continuously_delete_expired(tokio::time::Duration::from_secs(60)),
    );

    let site = Router::new()
        .route("/", get(index))
        .route("/login", get(login))
        .route("/login", post(verify_login))
        .route("/signup", get(signup))
        .route("/signup", post(verify_signup))
        .nest_service("/static", ServeDir::new("static"))
        .with_state(state);

    axum::serve(
        listener,
        site.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

async fn index(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> Html<String> {
    let ctx = HelloTemplate {
        addr: addr.to_string(),
    };

    Html(ctx.render_once().unwrap())
}

async fn login() -> Html<String> {
    let ctx = LoginTemplate { msg: "" };

    Html(ctx.render_once().unwrap())
}

async fn verify_login(State(state): State<SiteState>, Form(login): Form<Login>) -> Html<String> {
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
        return Html(loginfail.render_once().unwrap());
    };

    let verifier = Argon2::default();
    let verify_result = task::spawn_blocking(move || {
        let password_hash = PasswordHash::new(&user.password).expect("Invalid password hash");
        verifier.verify_password(login.password.as_bytes(), &password_hash)
    })
    .await
    .unwrap();

    let Ok(_) = verify_result else {
        return Html(loginfail.render_once().unwrap());
    };

    let ctx = LoginSuccessTemplate {
        username: login.username,
    };
    Html(ctx.render_once().unwrap())
}

async fn signup() -> Html<String> {
    let ctx = SignUpTemplate { msg: "" };

    Html(ctx.render_once().unwrap())
}

async fn verify_signup(State(state): State<SiteState>, Form(signup): Form<SignUp>) -> Html<String> {
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
