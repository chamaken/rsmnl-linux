use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use crossbeam_channel::{select, Receiver};

use crate::msg::{Message, Set};

pub fn file_out(out: &mut dyn Write, tmpl_rx: Receiver<Set>, data_rx: Receiver<Set>) {
    let mut seq = 0u32;
    let mut msg = Message::new();

    while let Ok(sr) = select! {
        recv(tmpl_rx) -> set => set,
        recv(data_rx) -> set => {
            seq += 1;
            set
        }
    } {
        if msg.len() + sr.len() >= 512 {
            let mut hdr = msg.header_mut();
            hdr.export_time = u32::to_be(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as u32,
            );
            out.write_all(msg.bytes()).unwrap(); // XXX

            msg = Message::new();
            hdr = msg.header_mut();
            hdr.seq = u32::to_be(seq);
        }
        msg.put_set(&sr);
    }
}
