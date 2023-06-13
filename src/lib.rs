use std::fs::File;
use std::io::{Read, Seek};
use std::path::Path;

pub struct CIAHeaderInfo {
    size: u32,
    type_num: u16,
    version: u16,
    cert_chain_size: u32,
    ticket_size: u32,
    tmd_size: u32,
    meta_size: u32,
    content_size: u64
}

pub fn read(filepath: &str) -> CIAHeaderInfo {
    let path = Path::new(filepath);

    let mut file = match File::open(&path) {
        Err(why) => panic!("couldn't open {}: {}", path.display(), why),
        Ok(file) => file,
    };

    let mut header_size_buf = [0; 4];
    let mut type_buf = [0; 2];
    let mut version_buf = [0; 2];
    let mut cert_size_buf = [0; 4];
    let mut ticket_size_buf = [0; 4];
    let mut tmd_size_buf = [0; 4];
    let mut meta_size_buf = [0; 4];
    let mut content_size_buf = [0; 8];


    file.read(&mut header_size_buf).unwrap();
    file.read(&mut type_buf).unwrap();
    file.read(&mut version_buf).unwrap();
    file.read(&mut cert_size_buf).unwrap();
    file.read(&mut ticket_size_buf).unwrap();
    file.read(&mut tmd_size_buf).unwrap();
    file.read(&mut meta_size_buf).unwrap();
    file.read(&mut content_size_buf).unwrap();
    CIAHeaderInfo {
        size: u32::from_le_bytes(header_size_buf),
        type_num: u16::from_le_bytes(type_buf),
        version: u16::from_le_bytes(version_buf),
        cert_chain_size: u32::from_le_bytes(cert_size_buf),
        ticket_size: u32::from_le_bytes(ticket_size_buf),
        tmd_size: u32::from_le_bytes(tmd_size_buf),
        meta_size: u32::from_le_bytes(meta_size_buf),
        content_size: u64::from_le_bytes(content_size_buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let info = read("E:/gm9/out/0004000000126100_v00.standard.cia");
        println!("{}", info.size + info.cert_chain_size + info.ticket_size);
        println!("{}", info.size + info.size);
    }
}
