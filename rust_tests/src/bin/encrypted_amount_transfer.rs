mod path;

use hex;
use ledger::{ApduCommand, LedgerApp};
use base58check::*;
use std::panic::resume_unwind;

fn main() {

    // Base58 part of header, so we can't just use hex and map to bytes.
    let sender_address = "3C8N65hBwc2cNtJkGmVyGeWYxhZ6R3X77mLWTwAKsnAnyworTq";
    let mut transaction_header = sender_address.from_base58check().unwrap().1;

    // Hex part of header.
    let nonce = "000000000000000A";
    let energy = "0000000000000064";
    let payload_size = "00000029";
    let expiry = "0000000063DE5DA7";
    let transaction_header_blob = format!("{}{}{}{}", &nonce, &energy, &payload_size, &expiry);
    let mut transaction_header_blob_bytes = hex::decode(transaction_header_blob).unwrap();

    // The full transaction header (sender_address + blob)
    transaction_header.append(&mut transaction_header_blob_bytes);

    // Transaction payload
    let transaction_kind = "10";

    // These values should be encrypted amounts, and not just random bytes like in this test.
    let mut to_address = sender_address.from_base58check().unwrap().1;
    let mut remaining_amount = hex::decode("00000000000F4240").unwrap();
    let mut transfer_amount = hex::decode("0000C0A0000F4240").unwrap();
    let mut index = hex::decode("000C0A0000000001").unwrap();
    let proofs = hex::decode("a47cdf9133572e9ad5c02c3a7ffd1d05db7bb98860d918092454146153d62788f224c0157c65853ed4a0245ab3e0a593a3f85fa81cc4cb99eeaa643bfc793eab01fc695a8c51d4599cbe032a39832ad49bab900d88105b01d025b760b0d0d555b8c828f2d8fe29cc78c6307d979e6358b8bba9cf4d8200f272cc85b2a3813eff957aec4b2b7ed979ba2079d62246d135aefd61e7f46690c452fec8bcbb593481e229f6f1968194a09cf612490887e71d96730e2d852201e53fec9c89d36f8a90a124bfe9d3a0da01249bbbfa5d51cde2da81e4f905849b9e0706bdbb7eb0c0875e12a18902359e613b64633146166872000100842763340db76ac5c80a205bda5b5316ff71683d78b482f7854b83ad55b294ca76219fe1a3cc33079bee95d88fcacff90000000000000005a43287b922ec1f58e48e9f66c5d73b14193b35c19d06b1726f284514c25db2954566e4943cd3589e98c1a6685f20c99d96bc2ca5f2d1b1dd98e9ee8b73bc3a84dc31a94f44bb043406c59229a11b741da702a7621524e7bee85f7fcd9fa2a2b08174536be08461dd43bec45838de2e7e5bc06bc1794403844ccd22a283897d8fc9f19b82032b0b3009ca22a4f935871483bae012befeb6374ac4549e615c20b8378049385f129c7bcaa73f7dff53475ab3e5c45f75ada7ec14ef0fb73b43a04ba2b17ef2bdad6fa5ecfec277d85426afd328b112132d6777b7ab49ee74c990c349f57126196f9d92b8216a03494b5d10ca0e16ea6cd6206e538eef8bb2aad9e575e75243e586064de5c1584eba1fd72e0000000500000001307a73f17a6ee00535dce62f022ab2246eddacb9ab3904eb0b1cf2f8fe598ea750a26560b1f8f1355f632ef5ee97098c04d6d8e9de6d0e77078e5e09d6f6355426978499bb410a7c015d86b26f72a32be1b9a0c3f6c7f205be9fbf49b4c4fd7e0000000204eff935bdd56a489ef400e642873f8c9472a739ed4b92222076165b8ef4f1886af3dd283d7866baa42fc7bd1e326674944d7b524b6ef12ebd6099c42627b5bf70adecb3b92b9ee996a06419d45e06ae059fcef4545acf59e612e3782ca6c458000000033b60dbcdca743789710d4ba9ce59f295a836cc64ce97c8c378d6e1367d49467c53f8bc63f6dfffae872181ea483f226e2b45292df65be921425de20cf0cb9b96131695525b2af5c0bc4780fd5f958f95bd948e155e8a3a61a44e5367e4645d37000000046ab002aa8779122cd9b0b043e83288a30a9f29707bd2c781b7b33b73abc025ab041e9578cc2337264913f9bf3aca5849dc285a54de3b098efe7cd44bbb60956f5b8c5ddec6a6056db2f6e4ec5cb705686cbfeefc15468229a0d40a92ca67bf900000000573d0721be638df4be39e1dd7fe1c171b6c3a710313be643da7c1f41bc164678c40b818a3d9060519c54d83d8fb55f6b652101476d93e22b124fc3ad78ad3fee609eb93ee519337f0e60fdd01b95456fc2c9165564c9ef6e70e07ab43dc8f31676da6743b0b5b4edb34687e4b22598af0296cfdd178319a69fd13f6ee81e468820000000851cf206b3d5fd7eaa043893517e7759c8a1380879f11327bbc2c84bb543daf83629c2332df19a349985d4512475b99773e75e2bd9b0c88e07014ce5b3b30411d624cb52699853264f031bce7e940250bbde60419e457400047a14e3c37576be35fcf0b0cca05a4cff3a2b3c88051fa2cafc89fb707aa1ca86769961f67dcf3560df1b51d5fb909414a3265d39d135a8007a3d92604f106f7380dcf94db8ea94124701f9657e6527e0dbab7d8c0993b027f60280e797eef2c848dd7e99698dfa512e152352e81ff2140c978f532d41c3ba6cb298c0aaee78424c81a42c89c1dd84e4f4ec62e1344c63237d34e1dfd9a0473e74de11e3681c6f525076b9a4089336d6622b55ffa2636f7d0a8488e7f4f9b5fbacc7c67e0ffe7024d9fa05eaf924a658f1f1d23ef0c63fd882371345517277f3027d7c7925129dbcc0d86f63193082a55f26ef315a9727268eaf8d7f290c1b8126305ced248048ee015024f78f2712c30aed9988375247df8fe614b925dbed6b8265e420c12cceefbad6c4fcc46c437c43ca4a02f0009cab6f92d45844ccd615a7f8f5d9c3e8395ec8720c7aec226058d6625a16202d6687b98c4287b5893691cd96de6e32bdb9db7f33a0b6b61e86a7773bddc4f5a27e89a6d2710afb62f56df8e794442d3c150382410b76236441fc6a3be61a33808d509c5623d8ca959a7e6aabef772713a2bd22bad3639b0182baee029aeee7863320af187579fd7ee73042b690e515fdc801b0fc905a11ecf119738ca62ad42f12e71a7d4d0aa3ef9f1428efe3346f45ee5fcede357ff03cb64e8a03ee5b467ec62db77733492cd2aee90f724975b3c3397de5f6e00eaa91148442c814f923bf2a0d3560447be8c350723777cf4a29d95733e4dbc755c2d0b616bb13392f38c49a5e21b0570db22492dfac261d214cf72bea26154f75c5b4803000b39f0b179499e5bafb5a53f9a25099a791a7ff8fcdfe02f9c9b271eea7e4407722b9bb0a70f04e538c3407d05734b629517e6146fa0b38f0d46717ba7048d0501d62d16a443e23ba180e67c37e5a85f102a35e2ee8bf2921a3e321036cd064a7f9ce3080db6b9b9cdaa658cffab5d2114f4f17f6397f82e35b4b4da39c50463070201af9df19e915b222f80b02fc2db1adf3e3fd1d90b7254d0360252d9baf1ba134dc6a20eecc2679e57f4d41b6358dba244091337769ea6172177b1549710a30aa087b877d8c3d6fc2c6a01d0d8ac6632ccfef6bb01720d61283604854a4ad0efe7c8501223ee671ce6dea2262dc9fe93954f42b69b186f78754e1a3eb45bf04c42e24f323a2a222a5e66c9fce617d62b445cfcffce789c315332ac6708bb4e4b8d24bcaa7130fca5332ffd0353e34a9c06ee0d3bba5811e506842a8c6a1049f20163ec4caaaf1b74d5ee000263653064a2f6cb5a92106ebe746a626fbc2cd04b13f96e897a0d9fe923bd8702e077625191728b17d0fe1c32ee49beb370cd0bbc57796c5c7e59d221903d814950de86ae5bd4bbcb6bbb8afc472f974a25b6f55e71ba298b718855d605a69503d855e659d610cb161f52cbb84b14d7a2c73824d63c8b1f449ef98e9857fa1435e9fb1e733060dd7a36edd0c5ce605ba95e4598a100000004aa9ef709ad51fbc44978124e1f07e2bdd7d2ae4030c6bc35b7a137cebebf9e2c94261f7ffd3d29798eed266776a46559a1bed13fd8ccda57df3aa2cca53e2241914f2f1ae93c6e11f45e149a30dbf48ecb193c58b96c4d0e4ef54ab48578aaf180f3be8b6691c31c03756b4145e9172617eadedef24dd41c6fefa4284fe0bb093574578bcb6153e16e339dcd339c68d682526770ac78df0c355ae3d5cbf3d279fc48aba80ba85b5502832039e78f1da8a30e9facae8712da6a56c526454104c2987499629970c704c761a2e4ca1074e517f71eaffe0056d4fc597f54c133923ce57284f87af842903a8187be8c1c6d07a6b68d84f0c45ed4661a84767608946a63d2a208529a0964248670a9bead664f5c6389d7a33cfe5f6237c71cd158b7dd8f57b9a108644f0faf1f8d362591d683edc8b951d03e52749d8c62ab92175310f33ad98221cde75265e201f70a14bbf2b20bf8d36524eb6b6eccead65382ce63c500b367407f1a43dbd2092d59426ce927bc0a1c0db982cb5fa58af5a7e5c32725af354be28346778cfae8194bcd76e174d1f7763dd5887d772f2e80343bfab80de4eddcd0417fe86d47f8abc2ff57ab8a42e6fb6856173dd0d8750abbad9678").unwrap();
    let mut proofs_size = (proofs.len() as u16).to_be_bytes().to_vec();

    // Build transaction payload bytes.
    let mut transaction_payload = hex::decode(transaction_kind).unwrap();
    transaction_payload.append(&mut to_address);
    transaction_payload.append(&mut remaining_amount);
    transaction_payload.append(&mut transfer_amount);
    transaction_payload.append(&mut index);
    transaction_payload.append(&mut proofs_size);

    let mut command_data = path::generate_key_derivation_path();
    command_data.append(&mut transaction_header);
    command_data.append(&mut transaction_payload);

    println!("{}", command_data.len());

    let command = ApduCommand {
        cla: 224,   // Has to be this value for all commands.
        ins: 16,
        p1: 0,
        p2: 0,
        length: 0, //command_data.len() as u8,
        data: command_data
    };

    let ledger = LedgerApp::new().unwrap();
    ledger.exchange(command).unwrap();

    for proof_partition in proofs.chunks(255) {
        println!("{}", proof_partition.len());
        let command = ApduCommand {
            cla: 224,   // Has to be this value for all commands.
            ins: 16,
            p1: 1,
            p2: 0,
            length: proof_partition.len() as u8,
            data: proof_partition.to_vec()
        };
        let result = ledger.exchange(command).unwrap();
        if !result.data.is_empty() {
            println!("Signature: {}", hex::encode(result.data));
        }
    }
}