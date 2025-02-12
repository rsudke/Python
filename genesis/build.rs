use std::{env, fmt::Write, fs, path::Path};

use nimiq_database::mdbx::{DatabaseConfig, MdbxDatabase};
use nimiq_genesis_builder::GenesisBuilder;
use nimiq_hash::Blake2bHash;

fn write_genesis_rs(directory: &Path, name: &str, genesis_hash: &Blake2bHash, have_accounts: bool) {
    let hash = {
        let mut hash = String::new();
        write!(&mut hash, "0x{:02x}", genesis_hash.0[0]).unwrap();
        for &byte in &genesis_hash.0[1..] {
            write!(&mut hash, ", 0x{:02x}", byte).unwrap();
        }
        hash
    };

    let accounts_expr = if have_accounts {
        format!(r#"Some(include_bytes!(concat!(env!("OUT_DIR"), "/genesis/{name}/accounts.dat")))"#)
    } else {
        String::from("None")
    };

    let genesis_rs = format!(
        r#"GenesisData {{
            block: include_bytes!(concat!(env!("OUT_DIR"), "/genesis/{name}/block.dat")),
            decompressed_keys: include_bytes!(concat!(env!("OUT_DIR"), "/genesis/{name}/decompressed_keys.dat")),
            hash: Blake2bHash([{hash}]),
            accounts: {accounts_expr},
    }}"#,
    );
    log::debug!("Writing genesis source code: {}", &genesis_rs);
    fs::write(directory.join("genesis.rs"), genesis_rs.as_bytes()).unwrap();
}

fn generate_albatross(name: &str, out_dir: &Path, src_dir: &Path) {
    log::info!("Generating Albatross genesis config: {}", name);

    let directory = out_dir.join(name);
    fs::create_dir_all(&directory).unwrap();

    let genesis_config = src_dir.join(format!("{name}.toml"));
    log::info!("genesis source file: {}", genesis_config.display());

    let db = MdbxDatabase::new_volatile(DatabaseConfig {
        // Limit the database to 100GB to support platforms with a lower supported maximum
        size: Some(0..(100 * 1024 * 1024 * 1024)),
        ..Default::default()
    })
    .expect("Could not open a volatile database");
    let builder = GenesisBuilder::from_config_file(genesis_config).unwrap();
    let (genesis_hash, have_accounts) = builder.write_to_files(db, &directory).unwrap();
    write_genesis_rs(&directory, name, &genesis_hash, have_accounts);
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let out_dir = Path::new(&env::var("OUT_DIR").unwrap()).join("genesis");
    let src_dir = Path::new("src").join("genesis");

    println!("Taking genesis config files from: {}", src_dir.display());
    println!("Writing genesis data to: {}", out_dir.display());
    generate_albatross("dev-albatross", &out_dir, &src_dir);
    generate_albatross("test-albatross", &out_dir, &src_dir);
    generate_albatross("unit-albatross", &out_dir, &src_dir);
    generate_albatross("main-albatross", &out_dir, &src_dir);
}
