use std::fs::File;
use std::io::Read;
use std::path::Path;

pub struct CIAHeaderInfo {
    pub(crate) filepath: &'static str,
    pub size: u32,
    pub type_num: u16,
    pub version: u16,
    pub cert_chain_size: u32,
    pub ticket_size: u32,
    pub tmd_size: u32,
    pub meta_size: u32,
    pub content_size: u64
}

impl CIAHeaderInfo {
    fn get_cert_chain_offset(&self) -> u32 {
        self.size + self.size % 64
    }

    pub fn get_ticket_offset(&self) -> u32 {
        (self.size + self.size % 64) +
            (self.cert_chain_size + self.cert_chain_size % 64)
    }

    fn get_tmd_offset(&self) -> u32 {
        (self.size + self.size % 64) +
            (self.cert_chain_size + self.cert_chain_size % 64) +
            (self.ticket_size + self.ticket_size % 64)
    }

    pub fn open_header(filepath: &'static str) -> Self {
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
            filepath,
            size: u32::from_le_bytes(header_size_buf),
            type_num: u16::from_le_bytes(type_buf),
            version: u16::from_le_bytes(version_buf),
            cert_chain_size: u32::from_le_bytes(cert_size_buf),
            ticket_size: u32::from_le_bytes(ticket_size_buf),
            tmd_size: u32::from_le_bytes(tmd_size_buf),
            meta_size: u32::from_le_bytes(meta_size_buf),
            content_size: u64::from_le_bytes(content_size_buf),
        }
    }
}
