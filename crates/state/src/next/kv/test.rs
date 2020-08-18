use super::{BufferedStore, KvBuf, Op, Scratch};
use crate::{
    env::{ReadManager, WriteManager},
    error::{DatabaseError, DatabaseResult},
    test_utils::test_cell_env,
};
use ::fixt::prelude::*;
use rkv::StoreOptions;
use serde_derive::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tracing::*;

// #[derive(Clone, Debug, PartialEq, Eq, derive_more::From)]
// struct TestKey(Vec<u8>);

// impl TestKey {
//     pub fn new(s: &str) -> Self {
//         Self(s.to_owned().as_bytes())
//     }
// }

// impl AsRef<[u8]> for TestKey {
//     fn as_ref(&self) -> &[u8] {
//         self.0.as_ref()
//     }
// }

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
struct DbString(String);

impl AsRef<[u8]> for DbString {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl From<Vec<u8>> for DbString {
    fn from(bytes: Vec<u8>) -> Self {
        Self(String::from_utf8(bytes).unwrap())
    }
}

impl From<&str> for DbString {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

#[tokio::test(threaded_scheduler)]
async fn kvbuf_scratch_and_persistence() -> DatabaseResult<()> {
    let arc = test_cell_env();
    let env = arc.guard().await;
    let db1 = env.inner().open_single("kv1", StoreOptions::create())?;
    let db2 = env.inner().open_single("kv1", StoreOptions::create())?;

    let testval = DbString::from("Joe");

    env.with_reader::<DatabaseError, _, _>(|reader| {
        let mut kv1: KvBuf<DbString, DbString> = KvBuf::new(arc.clone().into(), db1)?;
        let mut kv2: KvBuf<DbString, DbString> = KvBuf::new(arc.clone().into(), db2)?;

        env.with_commit(|writer| {
            kv1.put("hi".into(), testval.clone()).unwrap();
            kv2.put("salutations".into(), "folks".into()).unwrap();
            // Check that the underlying store contains no changes yet
            assert_eq!(kv1.store().get(&reader, &"hi".into())?, None);
            assert_eq!(kv2.store().get(&reader, &"salutations".into())?, None);

            // Check that the values are available due to the scratch space
            assert_eq!(kv1.get_used(&reader, &"hi".into())?, Some(testval.clone()));
            assert_eq!(
                kv2.get_used(&reader, &"salutations".into())?,
                Some("folks".into())
            );

            kv1.flush_to_txn(writer)
        })?;

        assert_eq!(kv2.scratch().len(), 1);

        // Ensure that mid-transaction, there has still been no persistence,
        // just for kicks

        env.with_commit(|writer| {
            let kv1a: KvBuf<DbString, DbString> = KvBuf::new(arc.clone().into(), db1)?;
            assert_eq!(kv1a.store().get(&reader, &"hi".into())?, None);
            kv2.flush_to_txn(writer)
        })?;

        Ok(())
    })?;

    env.with_reader(|reader| {
        // Now open some fresh Readers to see that our data was persisted
        let kv1b: KvBuf<DbString, DbString> = KvBuf::new(arc.clone().into(), db1)?;
        let kv2b: KvBuf<DbString, DbString> = KvBuf::new(arc.clone().into(), db2)?;
        // Check that the underlying store contains no changes yet
        assert_eq!(kv1b.store().get(&reader, &"hi".into())?, Some(testval));
        assert_eq!(
            kv2b.store().get(&reader, &"salutations".into())?,
            Some("folks".into())
        );
        Ok(())
    })
}

pub(super) type TestBuf<'a> = KvBuf<&'a str, V>;

macro_rules! res {
    ($key:expr, $op:ident, $val:expr) => {
        ($key, Op::$op(Box::new(V($val))))
    };
    ($key:expr, $op:ident) => {
        ($key, Op::$op)
    };
}

fn test_buf(a: &BTreeMap<Vec<u8>, Op<V>>, b: impl Iterator<Item = (&'static str, Op<V>)>) {
    for (k, v) in b {
        let val = a.get(k.as_bytes()).expect("Missing key");
        assert_eq!(*val, v);
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct V(pub u32);

impl From<u32> for V {
    fn from(s: u32) -> Self {
        Self(s)
    }
}

fixturator!(V; from u32;);

// #[tokio::test(threaded_scheduler)]
// async fn kv_iterators() -> DatabaseResult<()> {
//     let arc = test_cell_env();
//     let env = arc.guard().await;
//     let db = env.inner().open_single("kv", StoreOptions::create())?;

//     env.with_reader::<DatabaseError, _, _>(|reader| {
//         let mut buf: TestBuf = KvBuf::new)?;

//         buf.put("a", V(1)).unwrap();
//         buf.put("b", V(2)).unwrap();
//         buf.put("c", V(3)).unwrap();
//         buf.put("d", V(4)).unwrap();
//         buf.put("e", V(5)).unwrap();

//         env.with_commit(|mut writer| buf.flush_to_txn(&mut writer))?;
//         Ok(())
//     })?;

//     env.with_reader(|reader| {
//         let buf: TestBuf = KvBuf::new)?;

//         let forward: Vec<_> = buf.iter_raw()?.map(|(_, v)| Ok(v)).collect().unwrap();
//         let reverse: Vec<_> = buf
//             .iter_raw_reverse()?
//             .map(|(_, v)| Ok(v))
//             .collect()
//             .unwrap();

//         assert_eq!(forward, vec![V(1), V(2), V(3), V(4), V(5)]);
//         assert_eq!(reverse, vec![V(5), V(4), V(3), V(2), V(1)]);
//         Ok(())
//     })
// }

// #[tokio::test(threaded_scheduler)]
// async fn kv_empty_iterators() -> DatabaseResult<()> {
//     let arc = test_cell_env();
//     let env = arc.guard().await;
//     let db = env
//         .inner()
//         .open_single("kv", StoreOptions::create())
//         .unwrap();

//     env.with_reader(|reader| {
//         let buf: TestBuf = KvBuf::new(arc.clone().into(),  db();

//         let forward: Vec<_> = buf.iter_raw().unwrap().collect().unwrap();
//         let reverse: Vec<_> = buf.iter_raw_reverse().unwrap().collect().unwrap();

//         assert_eq!(forward, vec![]);
//         assert_eq!(reverse, vec![]);
//         Ok(())
//     })
// }