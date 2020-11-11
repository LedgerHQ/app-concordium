use ed25519_dalek::{PublicKey, Verifier};
use ed25519_dalek::ed25519::signature::Signature;
use hex;
use sha2::{Sha256, Digest};
use ledger::{ApduCommand, LedgerApp};

fn main() {
    // Account transaction header.
    let from_address = "2ae13c414a03176e887c91b7f93f47af4c1130c5ece7b9e250113ea40beb0e4d";
    let nonce = "0000000000000083";
    let energy = "0000000000001388";
    let payload_size = "00000000";
    let expiry = "0000017579871035";
    let transaction_header = format!("{}{}{}{}{}", &from_address, &nonce, &energy, &payload_size, &expiry);

    // Account transactions must prefix command_data with the identity and account index to use.
    // One byte for identity and one byte for account index. Here identity 0, account 0.
    let path_prefix = "0000";

    // Transaction kind is 19 -> 13 in hexadecimal.
    let transaction_kind = "13";
    let to_address = "2ae13c414a03176e887c91b7f93f47af4c1130c5ece7b9e250113ea40beb0e4d";

    // For scheduled amounts we have to split the transaction into multiple packages, as we can
    // only move 255 bytes at a time. In the first command we send the list size, which we
    // restrict to be less than 255 items, i.e. the number fits within 1 byte. For this example
    // we send 17 pairs to demonstrate that multiple packets are handled correctly.
    let number_of_scheduled_amounts = "11";

    // Send initial command.
    let initial_command_data = format!("{}{}{}{}{}", &path_prefix, &number_of_scheduled_amounts, &transaction_header, &transaction_kind, &to_address);

    let initial_command = ApduCommand {
        cla: 224, // Has to be this value for all commands.
        ins: 3,   // Scheduled transfer
        p1: 0,
        p2: 0,
        length: 0,
        data: hex::decode(&initial_command_data).unwrap()
    };
    let ledger = LedgerApp::new().unwrap();
    ledger.exchange(initial_command).expect("Initial packet failed.");

    // Generate 17 scheduled transfers to demonstrate that splitting by 15 transfers works.
    let mut command_data = "".to_string();

    for i in 1..18 {
        let scheduled_timestamp = "00000000604445A8";
        let amount = "0000000256245C73";
        command_data = format!("{}{}{}", &command_data, &scheduled_timestamp, &amount);

        // Send APDU 15 pairs at a time, or when done iterating.
        if i % 15 == 0 || i == 17 {
            println!("{}", &command_data.len());
            let command = ApduCommand {
                cla: 224,
                ins: 3,
                p1: 1,
                p2: 0,
                length: 0,
                data: hex::decode(&command_data).unwrap()
            };

            ledger.exchange(command).expect("Scheduled transfer command failed");
            command_data = "".to_string();
        }
    }

    // Receive signature (if approved by the user).
}
