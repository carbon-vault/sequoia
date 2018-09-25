use clap::{App, Arg, SubCommand, AppSettings};

pub fn build() -> App<'static, 'static> {
    App::new("sq")
        .version("0.1.0")
        .about("Sequoia is an implementation of OpenPGP.  This is a command-line frontend.")
        .setting(AppSettings::ArgRequiredElseHelp)
        .arg(Arg::with_name("home").value_name("DIRECTORY")
             .long("home")
             .help("Sets the home directory to use"))
        .arg(Arg::with_name("domain").value_name("DOMAIN")
             .long("domain")
             .short("d")
             .help("Sets the domain to use"))
        .arg(Arg::with_name("store").value_name("STORE")
             .long("store")
             .short("s")
             .help("Sets the store to use (default: 'default')"))
        .arg(Arg::with_name("policy").value_name("NETWORK-POLICY")
             .long("policy")
             .short("p")
             .help("Sets the network policy to use"))
        .subcommand(SubCommand::with_name("decrypt")
                    .display_order(10)
                    .about("Decrypts an OpenPGP message")
                    .arg(Arg::with_name("input").value_name("FILE")
                         .help("Sets the input file to use"))
                    .arg(Arg::with_name("output").value_name("FILE")
                         .long("output")
                         .short("o")
                         .help("Sets the output file to use"))
                    .arg(Arg::with_name("secret-key-file")
                         .long("secret-key-file")
                         .multiple(true)
                         .takes_value(true)
                         .value_name("TSK-FILE")
                         .number_of_values(1)
                         .help("Secret key to decrypt with, given as a file \
                                (can be given multiple times)"))
                    .arg(Arg::with_name("dump")
                         .long("dump")
                         .help("Print a packet dump to stderr"))
                    .arg(Arg::with_name("hex")
                         .long("hex")
                         .short("x")
                         .help("Print a hexdump (implies --dump)")))
        .subcommand(SubCommand::with_name("encrypt")
                    .display_order(20)
                    .about("Encrypts a message")
                    .arg(Arg::with_name("input").value_name("FILE")
                         .help("Sets the input file to use"))
                    .arg(Arg::with_name("output").value_name("FILE")
                         .long("output")
                         .short("o")
                         .help("Sets the output file to use"))
                    .arg(Arg::with_name("binary")
                         .long("binary")
                         .short("B")
                         .help("Don't ASCII-armor encode the OpenPGP data"))
                    .arg(Arg::with_name("recipient")
                         .long("recipient")
                         .short("r")
                         .multiple(true)
                         .takes_value(true)
                         .value_name("LABEL")
                         .number_of_values(1)
                         .help("Recipient to encrypt for \
                                (can be given multiple times)"))
                    .arg(Arg::with_name("recipient-key-file")
                         .long("recipient-key-file")
                         .multiple(true)
                         .takes_value(true)
                         .value_name("TPK-FILE")
                         .number_of_values(1)
                         .help("Recipient to encrypt for, given as a file \
                                (can be given multiple times)"))
                    .arg(Arg::with_name("symmetric")
                         .long("symmetric")
                         .short("s")
                         .multiple(true)
                         .help("Encrypt with a password \
                                (can be given multiple times)")))
        .subcommand(SubCommand::with_name("sign")
                    .display_order(25)
                    .about("Signs a message")
                    .arg(Arg::with_name("input").value_name("FILE")
                         .help("Sets the input file to use"))
                    .arg(Arg::with_name("output").value_name("FILE")
                         .long("output")
                         .short("o")
                         .help("Sets the output file to use"))
                    .arg(Arg::with_name("binary")
                         .long("binary")
                         .short("B")
                         .help("Don't ASCII-armor encode the OpenPGP data"))
                    .arg(Arg::with_name("detached")
                         .long("detached")
                         .help("Create a detached signature"))
                    .arg(Arg::with_name("append")
                         .long("append")
                         .short("a")
                         .conflicts_with("notarize")
                         .help("Append signature to existing signature"))
                    .arg(Arg::with_name("notarize")
                         .long("notarize")
                         .short("n")
                         .conflicts_with("append")
                         .help("Signs a message and all existing signatures"))
                    .arg(Arg::with_name("secret-key-file")
                         .long("secret-key-file")
                         .multiple(true)
                         .takes_value(true)
                         .value_name("TSK-FILE")
                         .number_of_values(1)
                         .help("Secret key to sign with, given as a file \
                                (can be given multiple times)")))
        .subcommand(SubCommand::with_name("verify")
                    .display_order(26)
                    .about("Verifies a message")
                    .arg(Arg::with_name("input").value_name("FILE")
                         .help("Sets the input file to use"))
                    .arg(Arg::with_name("output").value_name("FILE")
                         .long("output")
                         .short("o")
                         .help("Sets the output file to use"))
/* Not yet....
                    .arg(Arg::with_name("detached")
                         .long("detached")
                         .takes_value(true)
                         .value_name("SIG-FILE")
                         .help("Verifies a detached signature"))
*/
                    .arg(Arg::with_name("signatures").value_name("N")
                         .help("The number of valid signatures required.  \
                                Default: 1")
                         .long("signatures")
                         .short("n")
                         .takes_value(true))
                    .arg(Arg::with_name("public-key-file")
                         .long("public-key-file")
                         .multiple(true)
                         .takes_value(true)
                         .value_name("TPK-FILE")
                         .number_of_values(1)
                         .help("Public key to verify with, given as a file \
                                (can be given multiple times)")))
        .subcommand(SubCommand::with_name("enarmor")
                    .about("Applies ASCII Armor to a file")
                    .arg(Arg::with_name("input").value_name("FILE")
                         .help("Sets the input file to use"))
                    .arg(Arg::with_name("output").value_name("FILE")
                         .long("output")
                         .short("o")
                         .help("Sets the output file to use")))
        .subcommand(SubCommand::with_name("dearmor")
                    .about("Removes ASCII Armor from a file")
                    .arg(Arg::with_name("input").value_name("FILE")
                         .help("Sets the input file to use"))
                    .arg(Arg::with_name("output").value_name("FILE")
                         .long("output")
                         .short("o")
                         .help("Sets the output file to use")))
        .subcommand(SubCommand::with_name("autocrypt")
                    .about("Autocrypt support")
                    .setting(AppSettings::ArgRequiredElseHelp)
                    .subcommand(SubCommand::with_name("decode")
                                .about("Converts Autocrypt-encoded keys to OpenPGP TPKs")
                                .arg(Arg::with_name("input").value_name("FILE")
                                     .help("Sets the input file to use"))
                                .arg(Arg::with_name("output").value_name("FILE")
                                     .long("output")
                                     .short("o")
                                     .help("Sets the output file to use"))))
        .subcommand(SubCommand::with_name("dump")
                    .about("Lists OpenPGP packets")
                    .arg(Arg::with_name("input").value_name("FILE")
                         .help("Sets the input file to use"))
                    .arg(Arg::with_name("output").value_name("FILE")
                         .long("output")
                         .short("o")
                         .help("Sets the output file to use"))
                    .arg(Arg::with_name("mpis")
                         .long("mpis")
                         .help("Print MPIs"))
                    .arg(Arg::with_name("hex")
                         .long("hex")
                         .short("x")
                         .help("Print a hexdump")))
        .subcommand(SubCommand::with_name("split")
                    .about("Splits a message into OpenPGP packets")
                    .arg(Arg::with_name("input").value_name("FILE")
                         .help("Sets the input file to use"))
                    .arg(Arg::with_name("prefix").value_name("FILE")
                         .long("prefix")
                         .short("p")
                         .help("Sets the prefix to use for output files \
                                (defaults to the input filename with a dash, \
                                or 'output')")))
        .subcommand(SubCommand::with_name("keyserver")
                    .display_order(40)
                    .about("Interacts with keyservers")
                    .setting(AppSettings::ArgRequiredElseHelp)
                    .arg(Arg::with_name("server").value_name("URI")
                         .long("server")
                         .short("s")
                         .help("Sets the keyserver to use"))
                    .subcommand(SubCommand::with_name("get")
                                .about("Retrieves a key")
                                .arg(Arg::with_name("output").value_name("FILE")
                                     .long("output")
                                     .short("o")
                                     .help("Sets the output file to use"))
                                .arg(Arg::with_name("binary")
                                     .long("binary")
                                     .short("B")
                                     .help("Don't ASCII-armor encode the OpenPGP data"))
                                .arg(Arg::with_name("keyid").value_name("KEYID")
                                     .required(true)
                                     .help("ID of the key to retrieve")))
                    .subcommand(SubCommand::with_name("send")
                                .about("Sends a key")
                                .arg(Arg::with_name("input").value_name("FILE")
                                     .help("Sets the input file to use"))))
        .subcommand(SubCommand::with_name("store")
                    .display_order(30)
                    .about("Interacts with key stores")
                    .setting(AppSettings::ArgRequiredElseHelp)
                    .subcommand(SubCommand::with_name("list")
                                .about("Lists keys in the store"))
                    .subcommand(SubCommand::with_name("add")
                                .about("Add a key identified by fingerprint")
                                .arg(Arg::with_name("label").value_name("LABEL")
                                     .required(true)
                                     .help("Label to use"))
                                .arg(Arg::with_name("fingerprint").value_name("FINGERPRINT")
                                     .required(true)
                                     .help("Key to add")))
                    .subcommand(SubCommand::with_name("import")
                                .about("Imports a key")
                                .arg(Arg::with_name("label").value_name("LABEL")
                                     .required(true)
                                     .help("Label to use"))
                                .arg(Arg::with_name("input").value_name("FILE")
                                     .help("Sets the input file to use")))
                    .subcommand(SubCommand::with_name("export")
                                .about("Exports a key")
                                .arg(Arg::with_name("label").value_name("LABEL")
                                     .required(true)
                                     .help("Label to use"))
                                .arg(Arg::with_name("output").value_name("FILE")
                                     .long("output")
                                     .short("o")
                                     .help("Sets the output file to use"))
                                .arg(Arg::with_name("binary")
                                     .long("binary")
                                     .short("B")
                                     .help("Don't ASCII-armor encode the OpenPGP data")))
                    .subcommand(SubCommand::with_name("delete")
                                .about("Deletes bindings or stores")
                                .arg(Arg::with_name("the-store")
                                     .long("the-store")
                                     .help("Delete the selected store (change with --store)"))
                                .arg(Arg::with_name("label")
                                     .value_name("LABEL")
                                     .help("Delete binding with this label")))
                    .subcommand(SubCommand::with_name("stats")
                                .about("Get stats for the given label")
                                .arg(Arg::with_name("label").value_name("LABEL")
                                     .required(true)
                                     .help("Label to use")))
                    .subcommand(SubCommand::with_name("log")
                                .about("Lists the keystore log")
                                .arg(Arg::with_name("label")
                                     .value_name("LABEL")
                                     .help("List messages related to this label"))))
        .subcommand(SubCommand::with_name("list")
                    .about("Lists key stores and known keys")
                    .setting(AppSettings::ArgRequiredElseHelp)
                    .subcommand(SubCommand::with_name("stores")
                                .about("Lists key stores")
                                .arg(Arg::with_name("prefix").value_name("PREFIX")
                                     .help("List only stores with the given domain prefix")))
                    .subcommand(SubCommand::with_name("bindings")
                                .about("Lists all bindings in all key stores")
                                .arg(Arg::with_name("prefix").value_name("PREFIX")
                                     .help("List only bindings from stores with the given domain prefix")))
                    .subcommand(SubCommand::with_name("keys")
                                .about("Lists all keys in the common key pool"))
                    .subcommand(SubCommand::with_name("log")
                                .about("Lists the server log")))
}
