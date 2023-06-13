use std::fs::File;
use std::path::Path;
use std::io::{Seek, SeekFrom, Read};

use crate::cia_header::CIAHeaderInfo;

const RSA4096: u32 = 0x010003;
const RSA2048: u32 = 0x010004;
const ECDSA: u32 = 0x010005;

struct Ticket {
    signature_type: u32,
    signature: Vec<u8>,
    title_id: u64
}

impl Ticket {
    fn get_ticket_id_hex_string(&self) -> String {
        let title_id = self.title_id;
        format!("{title_id:016x}")
    }
}

fn get_ticket(header_info: &CIAHeaderInfo) -> Ticket {
    let path = Path::new(header_info.filepath);

    let mut file = File::open(&path).expect("Could not open file.");
    let mut type_buf = [0; 4];
    file.seek(SeekFrom::Start(header_info.get_ticket_offset().into())).unwrap();
    file.read(&mut type_buf).unwrap();
    
    let signature_type = u32::from_be_bytes(type_buf);
    let mut signature = Vec::new();
    if signature_type == RSA2048 {
        let mut sig_buf = [0; 0x100];
        file.read(&mut sig_buf).unwrap();
        signature = sig_buf.to_vec();
        file.seek(SeekFrom::Current(0x3C)).unwrap();
    }
    else if signature_type == RSA4096 {
        let mut sig_buf = [0; 0x200];
        file.read(&mut sig_buf).unwrap();
        signature = sig_buf.to_vec();
        file.seek(SeekFrom::Current(0x3C)).unwrap();
    }
    else if signature_type == ECDSA {
        let mut sig_buf = [0; 0x3C];
        file.read(&mut sig_buf).unwrap();
        signature = sig_buf.to_vec();
        file.seek(SeekFrom::Current(0x40)).unwrap();
    }
    let mut issuer_buf = [0; 64];
    let mut ecc_public_key_buf = [0; 0x3C];
    let mut version_bef = [0; 1];
    let mut ca_crl_version_buf = [0; 1];
    let mut signer_crl_version_buf = [0; 1];
    let mut titlekey_buf = [0; 16];
    let mut ticket_id_buf = [0; 8];
    let mut console_id_buf = [0; 4];
    let mut title_id_buf = [0; 8];

    file.read(&mut issuer_buf).unwrap();
    file.read(&mut ecc_public_key_buf).unwrap();
    file.read(&mut version_bef).unwrap();
    file.read(&mut ca_crl_version_buf).unwrap();
    file.read(&mut signer_crl_version_buf).unwrap();
    file.read(&mut titlekey_buf).unwrap();
    file.seek(SeekFrom::Current(1)).unwrap();
    file.read(&mut ticket_id_buf).unwrap();
    file.read(&mut console_id_buf).unwrap();
    file.read(&mut title_id_buf).unwrap();

    Ticket {
        signature_type,
        signature,
        title_id: u64::from_be_bytes(title_id_buf)
    }
}

#[cfg(test)]
mod tests {
    use crate::cia_header::open_header;

    use super::*;

    #[test]
    fn it_works() {
        let header = open_header("E:/gm9/out/0004000000126100_v00.standard.cia");
        let ticket = get_ticket(&header);
        assert_eq!(ticket.get_ticket_id_hex_string(), "0004000000126100")
    }
}