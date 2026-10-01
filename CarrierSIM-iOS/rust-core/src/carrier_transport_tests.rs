//! Wire-level AFC regressions. Only the transport is fake: these tests call the
//! production catalogue reader and the vendored AfcClient implementation.

use super::*;
use idevice::afc::opcode::AfcOpcode;
use idevice::afc::packet::{AfcPacket, AfcPacketHeader};

#[tokio::test]
async fn basic_device_identity_does_not_request_sim_information() {
    let (client,mut server)=tokio::io::duplex(8192);
    let server=tokio::spawn(async move {
        let mut keys=Vec::new();
        for _ in 0..7 {
            let length=server.read_u32().await.unwrap();assert!(length<8192);
            let mut bytes=vec![0;length as usize];server.read_exact(&mut bytes).await.unwrap();
            let request=Plist::from_reader(std::io::Cursor::new(bytes)).unwrap();
            let key=request.as_dictionary().unwrap().get("Key").and_then(Plist::as_string).unwrap();
            assert_ne!(key,"CarrierBundleInfoArray");keys.push(key.to_string());
            let value=match key {"UniqueDeviceID"=>"TEST-IPHONE","ProductVersion"=>"26.0","ActivationState"=>"Activated",_=>"test"};
            let mut response=Dictionary::new();response.insert("Value".into(),Plist::String(value.into()));
            let mut bytes=Vec::new();Plist::Dictionary(response).to_writer_xml(&mut bytes).unwrap();
            server.write_u32(bytes.len() as u32).await.unwrap();server.write_all(&bytes).await.unwrap();
        } keys
    });
    let mut lockdown=LockdownClient::new(idevice::Idevice::new(Box::new(client),"test"));
    let identity=identity_from_lockdown(&mut lockdown).await.unwrap();
    assert_eq!(identity.udid_hash,data::digest(b"TEST-IPHONE"));
    assert_eq!(identity.ios,"26.0");assert!(identity.rows.as_array().unwrap().is_empty());
    assert_eq!(server.await.unwrap().len(),7);
}

#[derive(Clone)]
enum FakeNode {
    Directory(Vec<String>),
    File { bytes: Vec<u8>, reported_len: usize, append_on_close: bool, mtime: i64 },
    Symlink(String),
}

impl FakeNode {
    fn file(bytes: &[u8]) -> Self {
        Self::File { bytes: bytes.to_vec(), reported_len: bytes.len(), append_on_close: false, mtime: 1 }
    }

    fn info(&self) -> Vec<u8> {
        let (kind, size, modified, target) = match self {
            Self::Directory(_) => ("S_IFDIR", 0, 1, None),
            Self::File { reported_len, mtime, .. } => ("S_IFREG", *reported_len, *mtime, None),
            Self::Symlink(target) => ("S_IFLNK", target.len(), 1, Some(target)),
        };
        let mut bytes = format!("st_size\0{size}\0st_blocks\01\0st_birthtime\01\0st_mtime\0{modified}\0st_nlink\01\0st_ifmt\0{kind}\0").into_bytes();
        if let Some(target) = target {
            // Exercise the actual AFC attribute spelling handled by the
            // vendored client, including its legacy st_link_target alias.
            bytes.extend_from_slice(b"LinkTarget\0");
            bytes.extend_from_slice(target.as_bytes());
            bytes.push(0);
        }
        bytes
    }
}

#[derive(Debug)]
struct WireCall { opcode: AfcOpcode, path: String, amount: usize }

struct FakeAfc {
    tree: BTreeMap<String, FakeNode>,
    open: BTreeMap<u64, (String, usize)>,
    next_fd: u64,
    calls: Vec<WireCall>,
}

impl FakeAfc {
    fn new(tree: BTreeMap<String, FakeNode>) -> Self {
        Self { tree, open: BTreeMap::new(), next_fd: 1, calls: Vec::new() }
    }

    async fn serve(mut self, mut socket: tokio::io::DuplexStream) -> Vec<WireCall> {
        loop {
            assert!(self.calls.len() < 512, "AFC reader exceeded the fixture operation limit");
            let mut raw = [0u8; 40];
            if socket.read_exact(&mut raw).await.is_err() { break; }
            assert_eq!(u64::from_le_bytes(raw[..8].try_into().unwrap()), idevice::afc::MAGIC);
            let total = u64::from_le_bytes(raw[8..16].try_into().unwrap()) as usize;
            let header_len = u64::from_le_bytes(raw[16..24].try_into().unwrap()) as usize;
            assert!((40..=8192).contains(&total));
            assert!((40..=total).contains(&header_len));
            let number = u64::from_le_bytes(raw[24..32].try_into().unwrap());
            let opcode = AfcOpcode::try_from(u64::from_le_bytes(raw[32..40].try_into().unwrap())).unwrap();
            let mut body = vec![0u8; total - 40];
            socket.read_exact(&mut body).await.unwrap();
            let header = &body[..header_len - 40];
            let path = |bytes: &[u8]| std::str::from_utf8(bytes).unwrap().trim_end_matches('\0').to_owned();
            let status = |code: AfcError| (AfcOpcode::Status, (code as u64).to_le_bytes().to_vec(), Vec::new());
            let (reply_opcode, reply_head, payload) = match opcode {
                AfcOpcode::GetFileInfo => {
                    let name = path(header);
                    self.calls.push(WireCall { opcode, path: name.clone(), amount: 0 });
                    match self.tree.get(&name) {
                        Some(node) => (AfcOpcode::Data, Vec::new(), node.info()),
                        None => status(AfcError::ObjectNotFound),
                    }
                }
                AfcOpcode::ReadDir => {
                    let name = path(header);
                    self.calls.push(WireCall { opcode, path: name.clone(), amount: 0 });
                    match self.tree.get(&name) {
                        Some(FakeNode::Directory(children)) => {
                            let mut listing = b".\0..\0".to_vec();
                            for child in children { listing.extend_from_slice(child.as_bytes()); listing.push(0); }
                            (AfcOpcode::Data, Vec::new(), listing)
                        }
                        Some(FakeNode::Symlink(_)) => panic!("catalogue reader enumerated a symbolic link"),
                        _ => status(AfcError::ObjectNotFound),
                    }
                }
                AfcOpcode::FileOpen => {
                    assert_eq!(u64::from_le_bytes(header[..8].try_into().unwrap()), AfcFopenMode::RdOnly as u64);
                    let name = path(&header[8..]);
                    self.calls.push(WireCall { opcode, path: name.clone(), amount: 0 });
                    match self.tree.get(&name) {
                        Some(FakeNode::File { .. }) => {
                            let fd = self.next_fd;
                            self.next_fd += 1;
                            self.open.insert(fd, (name, 0));
                            (AfcOpcode::FileOpenRes, fd.to_le_bytes().to_vec(), Vec::new())
                        }
                        Some(FakeNode::Symlink(_)) => panic!("catalogue reader opened a symbolic link"),
                        _ => status(AfcError::ObjectNotFound),
                    }
                }
                AfcOpcode::Read => {
                    let fd = u64::from_le_bytes(header[..8].try_into().unwrap());
                    let amount = u64::from_le_bytes(header[8..16].try_into().unwrap()) as usize;
                    let (name, offset) = self.open.get_mut(&fd).expect("read on unopened AFC handle");
                    self.calls.push(WireCall { opcode, path: name.clone(), amount });
                    let Some(FakeNode::File { bytes, .. }) = self.tree.get(name) else { panic!("file handle changed type") };
                    if *offset == bytes.len() {
                        // A real device returns AFC EndOfData here; the
                        // vendored AsyncRead maps it to an I/O error.
                        status(AfcError::EndOfData)
                    } else {
                        let end = (*offset + amount).min(bytes.len());
                        let result = bytes[*offset..end].to_vec();
                        *offset = end;
                        (AfcOpcode::Data, Vec::new(), result)
                    }
                }
                AfcOpcode::FileClose => {
                    let fd = u64::from_le_bytes(header[..8].try_into().unwrap());
                    let (name, _) = self.open.remove(&fd).expect("close on unopened AFC handle");
                    self.calls.push(WireCall { opcode, path: name.clone(), amount: 0 });
                    if let Some(FakeNode::File { bytes, reported_len, append_on_close: true, mtime }) = self.tree.get_mut(&name) {
                        bytes.push(b'!');
                        *reported_len = bytes.len();
                        *mtime += 1;
                    }
                    status(AfcError::Success)
                }
                _ => panic!("read-only catalogue operation sent unexpected AFC opcode {opcode:?}"),
            };
            let reply = AfcPacket {
                header: AfcPacketHeader {
                    magic: idevice::afc::MAGIC,
                    entire_len: (40 + reply_head.len() + payload.len()) as u64,
                    header_payload_len: (40 + reply_head.len()) as u64,
                    packet_num: number,
                    operation: reply_opcode,
                },
                header_payload: reply_head,
                payload,
            };
            socket.write_all(&reply.serialize()).await.unwrap();
        }
        assert!(self.open.is_empty(), "AFC file handles were not closed");
        self.calls
    }
}

async fn read_fixture(node: FakeNode, expected: usize) -> (Result<Vec<u8>>, Vec<WireCall>) {
    let (client, server) = tokio::io::duplex(8192);
    let mut afc = AfcClient::new(idevice::Idevice::new(Box::new(client), "catalogue-test"));
    let reader = async {
        let result = read_file(&mut afc, "fixture", expected).await;
        drop(afc);
        result
    };
    let device = FakeAfc::new(BTreeMap::from([("fixture".into(), node)])).serve(server);
    tokio::time::timeout(Duration::from_secs(2), async { tokio::join!(reader, device) }).await.unwrap()
}

#[tokio::test]
async fn complete_file_reads_exactly_size_without_afc_eof_probe() {
    let (result, calls) = read_fixture(FakeNode::file(b"exact bytes"), 11).await;
    assert_eq!(result.unwrap(), b"exact bytes");
    assert_eq!(calls.iter().filter(|c| c.opcode == AfcOpcode::Read).map(|c| c.amount).collect::<Vec<_>>(), vec![11]);
}

#[tokio::test]
async fn empty_file_does_not_issue_zero_byte_or_eof_read() {
    let (result, calls) = read_fixture(FakeNode::file(b""), 0).await;
    assert_eq!(result.unwrap(), b"");
    assert!(!calls.iter().any(|c| c.opcode == AfcOpcode::Read));
}

#[tokio::test]
async fn truncated_file_is_rejected_and_its_handle_is_closed() {
    let node = FakeNode::File { bytes: b"short".to_vec(), reported_len: 10, append_on_close: false, mtime: 1 };
    let (result, calls) = read_fixture(node, 10).await;
    assert!(result.is_err());
    assert!(calls.iter().any(|c| c.opcode == AfcOpcode::FileClose));
}

#[tokio::test]
async fn appended_bytes_after_read_are_detected_by_second_stat() {
    let node = FakeNode::File { bytes: b"before".to_vec(), reported_len: 6, append_on_close: true, mtime: 1 };
    let (result, calls) = read_fixture(node, 6).await;
    assert!(result.is_err());
    assert_eq!(calls.iter().filter(|c| c.opcode == AfcOpcode::GetFileInfo).count(), 2);
    assert_eq!(calls.iter().filter(|c| c.opcode == AfcOpcode::Read).map(|c| c.amount).collect::<Vec<_>>(), vec![6]);
}

#[tokio::test]
async fn direct_file_read_refuses_symlink_without_opening_it() {
    let (result, calls) = read_fixture(FakeNode::Symlink("/private/never-open".into()), 19).await;
    assert!(result.is_err());
    assert!(!calls.iter().any(|c| c.opcode == AfcOpcode::FileOpen || c.opcode == AfcOpcode::Read));
}

#[tokio::test]
async fn remote_catalogue_preserves_symlink_bytes_without_following_target() {
    let target = "/private/never-open";
    let nodes = BTreeMap::from([
        ("catalogue".into(), FakeNode::Directory(vec!["data".into(), "alias".into()])),
        ("catalogue/data".into(), FakeNode::file(b"owned catalogue data")),
        ("catalogue/alias".into(), FakeNode::Symlink(target.into())),
        (target.into(), FakeNode::file(b"must never be read")),
    ]);
    let (client, server) = tokio::io::duplex(8192);
    let mut afc = AfcClient::new(idevice::Idevice::new(Box::new(client), "catalogue-test"));
    let reader = async {
        let result = remote_tree(&mut afc, "catalogue").await;
        drop(afc);
        result
    };
    let device = FakeAfc::new(nodes).serve(server);
    let (result, calls) = tokio::time::timeout(Duration::from_secs(2), async { tokio::join!(reader, device) }).await.unwrap();
    let tree = result.unwrap();
    assert_eq!(tree.get("alias"), Some(&Node::symlink(target.as_bytes().to_vec())));
    assert_eq!(tree.get("data"), Some(&Node::file(b"owned catalogue data".to_vec())));
    assert_eq!(tree.len(), 2);
    assert!(!calls.iter().any(|c| c.path == target));
    assert!(!calls.iter().any(|c| c.path == "catalogue/alias" && (c.opcode == AfcOpcode::FileOpen || c.opcode == AfcOpcode::ReadDir)));
}

#[tokio::test]
async fn symbolic_link_catalogue_root_is_rejected_without_traversal() {
    let (client, server) = tokio::io::duplex(8192);
    let mut afc = AfcClient::new(idevice::Idevice::new(Box::new(client), "catalogue-test"));
    let reader = async {
        let result = remote_tree(&mut afc, "catalogue").await;
        drop(afc);
        result
    };
    let device = FakeAfc::new(BTreeMap::from([("catalogue".into(), FakeNode::Symlink("/private/never-open".into()))])).serve(server);
    let (result, calls) = tokio::time::timeout(Duration::from_secs(2), async { tokio::join!(reader, device) }).await.unwrap();
    assert!(result.is_err());
    assert!(calls.iter().all(|c| c.opcode == AfcOpcode::GetFileInfo && c.path == "catalogue"));
}
