---
title: "Just CTF: Baby Otter"
tags: solana
style: border
color: danger
comments: true
description: Solution to Just CTF Solana challenge, Baby Otter.
---

# Baby Otter

A while ago I participated in Just CTF, I remembered I should post at least once every month in this blog, so here we go.

The CTF had a Solana challenge, which I enjoy solving since they are normally very puzzle-like.

A quick summary of the challenge is to crack an internal encryption and call ```request_ownership``` method with the cracked code as a parameter.

## Analysis

Solana challenges usually provide two folders: ```framework``` and ```framework-solve```.

Our solution goes into ```framework-solve``` (surprise).

### Challenge Code

Inside framework folder, there are two Rust codes to observe: ```main.rs``` and ```baby_otter_challenge.rs```. ```main``` is the driver code and ```baby_otter_challenge``` is a method that the main uses and the one that we are going to exploit.

```main.rs``` looks like:
```rust
use std::env;
use std::fmt;
use std::thread;
use std::mem::drop;
use std::path::Path;
use std::error::Error;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use sui_ctf_framework::NumericalAddress;
use sui_transactional_test_runner::args::SuiValue;
use sui_transactional_test_runner::test_adapter::FakeID;

fn handle_client(mut stream: TcpStream) -> Result<(), Box<dyn Error>> {

    // Initialize SuiTestAdapter
    let chall = "baby_otter_challenge";
    let named_addresses = vec![
        ("challenge".to_string(), NumericalAddress::parse_str("0x8107417ed30fcc2d0b0dfd680f12f6ead218cb971cb989afc8d28ad37da89467")?),
        ("solution".to_string(), NumericalAddress::parse_str("0x42f5c1c42496636b461f1cb4f8d62aac8ebac3ca7766c154b63942671bc86836")?),
    ];
    
    let precompiled = sui_ctf_framework::get_precompiled(Path::new(&format!(
        "./chall/build/{}/sources/dependencies",
        chall
    )));

    let mut adapter = sui_ctf_framework::initialize(
        named_addresses,
        &precompiled,
        Some(vec!["challenger".to_string(), "solver".to_string()]),
    );
    
    let mut solution_data = [0 as u8; 1000]; 
    let _solution_size = stream.read(&mut solution_data)?;

    // Publish Challenge Module
    let mod_bytes: Vec<u8> = std::fs::read(format!(
        "./chall/build/{}/bytecode_modules/{}.mv",
        chall, chall
    ))?;
    let chall_dependencies: Vec<String> = Vec::new();
    let chall_addr = sui_ctf_framework::publish_compiled_module(&mut adapter, mod_bytes, chall_dependencies, Some(String::from("challenger")));
    println!("[SERVER] Challenge published at: {:?}", chall_addr);

    // Publish Solution Module
    let mut sol_dependencies: Vec<String> = Vec::new();
    sol_dependencies.push(String::from("challenge"));
    let sol_addr = sui_ctf_framework::publish_compiled_module(&mut adapter, solution_data.to_vec(), sol_dependencies, Some(String::from("solver")));
    println!("[SERVER] Solution published at: {:?}", sol_addr);

    let mut output = String::new();
    fmt::write(
        &mut output,
        format_args!(
            "[SERVER] Challenge published at {}. Solution published at {}",
            chall_addr.to_string().as_str(),
            sol_addr.to_string().as_str()
        ),
    ).unwrap();
    stream.write(output.as_bytes()).unwrap();

    // Prepare Function Call Arguments
    let mut args_sol : Vec<SuiValue> = Vec::new();
    let arg_ob = SuiValue::Object(FakeID::Enumerated(1, 1));
    args_sol.push(arg_ob);

    // Call solve Function
    let ret_val = sui_ctf_framework::call_function(
        &mut adapter,
        sol_addr,
        "baby_otter_solution",
        "solve",
        args_sol,
        Some("solver".to_string())
    );
    println!("[SERVER] Return value {:#?}", ret_val);
    println!("");

    // Check Solution
    let mut args2: Vec<SuiValue> = Vec::new();
    let arg_ob2 = SuiValue::Object(FakeID::Enumerated(1, 1));
    args2.push(arg_ob2);

    let ret_val = sui_ctf_framework::call_function(
        &mut adapter,
        chall_addr,
        chall,
        "is_owner",
        args2,
        Some("challenger".to_string()),
    );
    println!("[SERVER] Return value {:#?}", ret_val);
    println!("");

    // Validate Solution
    match ret_val {
        Ok(()) => {
            println!("[SERVER] Correct Solution!");
            println!("");
            if let Ok(flag) = env::var("FLAG") {
                let message = format!("[SERVER] Congrats, flag: {}", flag);
                stream.write(message.as_bytes()).unwrap();
            } else {
                stream.write("[SERVER] Flag not found, please contact admin".as_bytes()).unwrap();
            }
        }
        Err(_error) => {
            println!("[SERVER] Invalid Solution!");
            println!("");
            stream.write("[SERVER] Invalid Solution!".as_bytes()).unwrap();
        }
    };

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {

    // Create Socket - Port 31337
    let listener = TcpListener::bind("0.0.0.0:31337")?;
    println!("[SERVER] Starting server at port 31337!");

    // Wait For Incoming Solution
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("[SERVER] New connection: {}", stream.peer_addr().unwrap());
                thread::spawn(move|| handle_client(stream).unwrap());
            }
            Err(e) => {
                println!("[SERVER] Error: {}", e);
            }
        }        
    }

    // Close Socket Server
    drop(listener);
    Ok(())
}
```

Nothing too significant, we can see that the driver code will try to verify whether the client is "owner" and print flag if yes.

```baby_otter_challenge.rs``` looks like:
```rust
module challenge::baby_otter_challenge {
    
    // [*] Import dependencies
    use std::vector;

    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{TxContext};

    // [*] Error Codes
    const ERR_INVALID_CODE : u64 = 31337;
 
    // [*] Structs
    struct Status has key, store {
        id : UID,
        solved : bool,
    }

    // [*] Module initializer
    fun init(ctx: &mut TxContext) {
        transfer::public_share_object(Status {
            id: object::new(ctx),
            solved: false
        });
    }

    // [*] Local functions
    fun gt() : vector<u64> {

        let table : vector<u64> = vector::empty<u64>();
        let i = 0;

        while( i < 256 ) {
            let tmp = i;
            let j = 0;

            while( j < 8 ) {
                if( tmp & 1 != 0 ) {
                    tmp = tmp >> 1;
                    tmp = tmp ^ 0xedb88320;
                } else {
                    tmp = tmp >> 1;
                };

                j = j+1;
            };

            vector::push_back(&mut table, tmp);
            i = i+1;
        };

        table
    }

    fun hh(input : vector<u8>) : u64 {

        let table : vector<u64> = gt();
        let tmp : u64 = 0xffffffff;
        let input_length = vector::length(&input);
        let i = 0;

        while ( i < input_length ) {
            let byte : u64 = (*vector::borrow(&mut input, i) as u64);

            let index = tmp ^ byte;
            index = index & 0xff;

            tmp = tmp >> 8;
            tmp = tmp ^ *vector::borrow(&mut table, index);

            i = i+1;
        };

        tmp ^ 0xffffffff
    }
 
    // [*] Public functions
    public entry fun request_ownership(status: &mut Status, ownership_code : vector<u8>, _ctx: &mut TxContext) {

        let ownership_code_hash : u64 = hh(ownership_code);
        assert!(ownership_code_hash == 1725720156, ERR_INVALID_CODE);
        status.solved = true;

    }

    public entry fun is_owner(status: &mut Status) {
        assert!(status.solved == true, 0);
    }

}
```

Here we can see a few interesting methods: gt(), hh(), and request_ownership().

We want to trigger ```request_ownership``` with the correct ownership_code_hash value (specifically, 1725720156), so the state of ```status.solved``` will be true.

## Exploit

Function hh() and gt() is essentially a Rust implementation of CRC32 (this took 6 hours to figure it out amongst my team, but the grind was worth it).

We simply ran crc32 decryptor to reverse 1725720156 (0x66dc665c in hex):
```bash
python2 crc32.py reverse 0x66dc665c 
4 bytes: H4CK {0x48, 0x34, 0x43, 0x4b}
verification checksum: 0x66dc665c (OK)
6 bytes: 6g9CPP (OK)
6 bytes: 7gxrKI (OK)
6 bytes: 9hgBwG (OK)
6 bytes: DgMXYM (OK)
6 bytes: JhRheC (OK)
6 bytes: MqUVOh (OK)
6 bytes: Qok67t (OK)
6 bytes: ZY9zyX (OK)
6 bytes: bmw2Rn (OK)
6 bytes: bq8nSz (OK)
6 bytes: cqy_Hc (OK)
6 bytes: uYTBeJ (OK)
```

The key turns out to be H4CK.

We finally supply the above key as hex string: x"4834434b" and call ```request_ownership``` with it to get flag.

Finalized solve script ```solve.rs```:
```rust
module solution::baby_otter_solution {
    use sui::tx_context::TxContext;
    use challenge::baby_otter_challenge;

    public entry fun solve(status: &mut baby_otter_challenge::Status, ctx: &mut TxContext) {

    let str = x"4834434b";
        baby_otter_challenge::request_ownership(status,str,ctx);        
    }
}
```

We lastly run the given script to execute client code to get flag:
```sh
set -eux

cd framework-solve/solve && sui move build
cd ..
cargo r --release
```

The build took a while (2hr) but we got the flag!

```bash
Connection Output: '[SERVER] Challenge published at 8107417ed30fcc2d0b0dfd680f12f6ead218cb971cb989afc8d28ad37da89467. Solution published at 42f5c1c42496636b461f1cb4f8d62aac8ebac3ca7766c154b63942671bc86836'
Connection Output: '[SERVER] Congrats, flag: '
```

Thanks!

079
