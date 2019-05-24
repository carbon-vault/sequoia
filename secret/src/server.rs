extern crate sequoia_core;
extern crate sequoia_ipc;
extern crate sequoia_secret;

use sequoia_ipc::Server;

fn main() {
    let ctx = Server::context()
        .expect("Failed to create context");
    Server::new(sequoia_secret::descriptor(&ctx))
        .expect("Failed to create server")
        .serve()
        .expect("Failed to start server");
}
