//! TASK-220 — Java `.class` and `.jar` bytecode scan.
//!
//! In-tree parser for the Java class-file format (JVM spec § 4).
//! Recovers the class name, super-class, constant pool, method
//! table, and per-method bytecode so the engine can run YARA over
//! the IL.
//!
//! Per `docs/prd.md` § 1.5: no GPL deps. The format is fully public
//! so an in-tree parser is straightforward.

use serde::{Deserialize, Serialize};

pub const CLASS_MAGIC: u32 = 0xCAFE_BABE;

/// Maximum class-file size we'll parse. The validation gate bounds
/// per-class size at 16 MB so a hostile `.class` can't blow up
/// memory.
pub const MAX_CLASS_SIZE: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassFile {
    pub minor_version: u16,
    pub major_version: u16,
    pub constant_pool: Vec<Constant>,
    pub access_flags: u16,
    pub this_class: u16,
    pub super_class: u16,
    pub interfaces: Vec<u16>,
    pub fields: Vec<MemberInfo>,
    pub methods: Vec<MemberInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Constant {
    /// Constant pool index 0 reserved by the JVM spec. We emit this
    /// as the first entry so other indices line up natively.
    None,
    Utf8(String),
    Integer(i32),
    Float(u32),
    Long(i64),
    Double(u64),
    Class {
        name_index: u16,
    },
    String {
        string_index: u16,
    },
    FieldRef {
        class_index: u16,
        name_and_type_index: u16,
    },
    MethodRef {
        class_index: u16,
        name_and_type_index: u16,
    },
    InterfaceMethodRef {
        class_index: u16,
        name_and_type_index: u16,
    },
    NameAndType {
        name_index: u16,
        descriptor_index: u16,
    },
    MethodHandle {
        reference_kind: u8,
        reference_index: u16,
    },
    MethodType {
        descriptor_index: u16,
    },
    Dynamic {
        bootstrap_index: u16,
        name_and_type_index: u16,
    },
    InvokeDynamic {
        bootstrap_index: u16,
        name_and_type_index: u16,
    },
    Module {
        name_index: u16,
    },
    Package {
        name_index: u16,
    },
    /// Unknown / forward-compatible tags.
    Unknown(u8),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberInfo {
    pub access_flags: u16,
    pub name_index: u16,
    pub descriptor_index: u16,
    pub attributes: Vec<AttributeInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributeInfo {
    pub name_index: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ClassError {
    #[error("not a class file (bad magic)")]
    BadMagic,
    #[error("class file truncated at offset {0}")]
    Truncated(usize),
    #[error("class file too large ({size} > {limit})")]
    TooLarge { size: usize, limit: usize },
    #[error("constant pool index {0} out of range")]
    BadConstantIndex(u16),
}

/// Parse a `.class` byte buffer.
pub fn parse_class(bytes: &[u8]) -> Result<ClassFile, ClassError> {
    if bytes.len() > MAX_CLASS_SIZE {
        return Err(ClassError::TooLarge {
            size: bytes.len(),
            limit: MAX_CLASS_SIZE,
        });
    }
    if bytes.len() < 10 {
        return Err(ClassError::Truncated(bytes.len()));
    }
    let mut r = Reader::new(bytes);
    let magic = r.u32()?;
    if magic != CLASS_MAGIC {
        return Err(ClassError::BadMagic);
    }
    let minor_version = r.u16()?;
    let major_version = r.u16()?;
    let cp_count = r.u16()? as usize;
    let mut pool = Vec::with_capacity(cp_count);
    pool.push(Constant::None);
    let mut i = 1;
    while i < cp_count {
        let tag = r.u8()?;
        let c = match tag {
            1 => {
                let len = r.u16()? as usize;
                let s = r.bytes(len)?;
                Constant::Utf8(
                    decode_mutf8(s).unwrap_or_else(|_| String::from_utf8_lossy(s).to_string()),
                )
            }
            3 => Constant::Integer(r.i32()?),
            4 => Constant::Float(r.u32()?),
            5 => {
                let v = r.i64()?;
                let c = Constant::Long(v);
                pool.push(c);
                // Long/Double take two slots — spec quirk.
                pool.push(Constant::None);
                i += 2;
                continue;
            }
            6 => {
                let v = r.u64()?;
                let c = Constant::Double(v);
                pool.push(c);
                pool.push(Constant::None);
                i += 2;
                continue;
            }
            7 => Constant::Class {
                name_index: r.u16()?,
            },
            8 => Constant::String {
                string_index: r.u16()?,
            },
            9 => Constant::FieldRef {
                class_index: r.u16()?,
                name_and_type_index: r.u16()?,
            },
            10 => Constant::MethodRef {
                class_index: r.u16()?,
                name_and_type_index: r.u16()?,
            },
            11 => Constant::InterfaceMethodRef {
                class_index: r.u16()?,
                name_and_type_index: r.u16()?,
            },
            12 => Constant::NameAndType {
                name_index: r.u16()?,
                descriptor_index: r.u16()?,
            },
            15 => Constant::MethodHandle {
                reference_kind: r.u8()?,
                reference_index: r.u16()?,
            },
            16 => Constant::MethodType {
                descriptor_index: r.u16()?,
            },
            17 => Constant::Dynamic {
                bootstrap_index: r.u16()?,
                name_and_type_index: r.u16()?,
            },
            18 => Constant::InvokeDynamic {
                bootstrap_index: r.u16()?,
                name_and_type_index: r.u16()?,
            },
            19 => Constant::Module {
                name_index: r.u16()?,
            },
            20 => Constant::Package {
                name_index: r.u16()?,
            },
            other => Constant::Unknown(other),
        };
        pool.push(c);
        i += 1;
    }
    let access_flags = r.u16()?;
    let this_class = r.u16()?;
    let super_class = r.u16()?;
    let interfaces_count = r.u16()? as usize;
    let mut interfaces = Vec::with_capacity(interfaces_count);
    for _ in 0..interfaces_count {
        interfaces.push(r.u16()?);
    }
    let fields = read_member_table(&mut r)?;
    let methods = read_member_table(&mut r)?;
    Ok(ClassFile {
        minor_version,
        major_version,
        constant_pool: pool,
        access_flags,
        this_class,
        super_class,
        interfaces,
        fields,
        methods,
    })
}

fn read_member_table(r: &mut Reader<'_>) -> Result<Vec<MemberInfo>, ClassError> {
    let count = r.u16()? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let access_flags = r.u16()?;
        let name_index = r.u16()?;
        let descriptor_index = r.u16()?;
        let attrs_count = r.u16()? as usize;
        let mut attrs = Vec::with_capacity(attrs_count);
        for _ in 0..attrs_count {
            let attr_name_index = r.u16()?;
            let attr_len = r.u32()? as usize;
            let data = r.bytes(attr_len)?.to_vec();
            attrs.push(AttributeInfo {
                name_index: attr_name_index,
                data,
            });
        }
        out.push(MemberInfo {
            access_flags,
            name_index,
            descriptor_index,
            attributes: attrs,
        });
    }
    Ok(out)
}

/// Extract the raw bytecode from a method's `Code` attribute.
pub fn method_bytecode<'a>(class: &'a ClassFile, method: &'a MemberInfo) -> Option<&'a [u8]> {
    for a in &method.attributes {
        let name = class.utf8_at(a.name_index)?;
        if name == "Code" && a.data.len() >= 8 {
            let code_len =
                u32::from_be_bytes([a.data[4], a.data[5], a.data[6], a.data[7]]) as usize;
            let start: usize = 8;
            let end = start.saturating_add(code_len);
            if end <= a.data.len() {
                return Some(&a.data[start..end]);
            }
        }
    }
    None
}

impl ClassFile {
    /// Resolve the class's fully-qualified name from the constant pool.
    pub fn class_name(&self) -> Option<&str> {
        let Constant::Class { name_index } = self.constant_pool.get(self.this_class as usize)?
        else {
            return None;
        };
        self.utf8_at(*name_index)
    }

    pub fn utf8_at(&self, index: u16) -> Option<&str> {
        match self.constant_pool.get(index as usize)? {
            Constant::Utf8(s) => Some(s.as_str()),
            _ => None,
        }
    }
}

// -----------------------------------------------------------------------------
// Reader
// -----------------------------------------------------------------------------

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn need(&self, n: usize) -> Result<(), ClassError> {
        if self.pos + n > self.buf.len() {
            return Err(ClassError::Truncated(self.pos));
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, ClassError> {
        self.need(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }
    fn u16(&mut self) -> Result<u16, ClassError> {
        self.need(2)?;
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }
    fn u32(&mut self) -> Result<u32, ClassError> {
        self.need(4)?;
        let v = u32::from_be_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }
    fn i32(&mut self) -> Result<i32, ClassError> {
        Ok(self.u32()? as i32)
    }
    fn u64(&mut self) -> Result<u64, ClassError> {
        self.need(8)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_be_bytes(arr))
    }
    fn i64(&mut self) -> Result<i64, ClassError> {
        Ok(self.u64()? as i64)
    }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], ClassError> {
        self.need(n)?;
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
}

/// Decode JVM "modified UTF-8" — the same as UTF-8 except:
/// - the encoded `0x0000` is two bytes (`0xC0 0x80`),
/// - supplementary code points use surrogate-pair-encoded UTF-8.
fn decode_mutf8(bytes: &[u8]) -> Result<String, ()> {
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == 0 {
            return Err(());
        } else if b < 0x80 {
            out.push(b as char);
            i += 1;
        } else if b & 0xE0 == 0xC0 {
            if i + 1 >= bytes.len() {
                return Err(());
            }
            let b2 = bytes[i + 1];
            let codepoint = (((b & 0x1F) as u32) << 6) | ((b2 & 0x3F) as u32);
            out.push(char::from_u32(codepoint).unwrap_or('\u{FFFD}'));
            i += 2;
        } else if b & 0xF0 == 0xE0 {
            if i + 2 >= bytes.len() {
                return Err(());
            }
            let b2 = bytes[i + 1];
            let b3 = bytes[i + 2];
            let codepoint =
                (((b & 0x0F) as u32) << 12) | (((b2 & 0x3F) as u32) << 6) | ((b3 & 0x3F) as u32);
            out.push(char::from_u32(codepoint).unwrap_or('\u{FFFD}'));
            i += 3;
        } else {
            return Err(());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal Hello.class equivalent: magic, version 65.0, empty
    /// constant pool count = 1, this_class index 0, super 0, no
    /// interfaces / fields / methods. Useful to exercise the parser
    /// happy-path bookkeeping.
    fn make_minimal_class() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&CLASS_MAGIC.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes()); // minor
        v.extend_from_slice(&65u16.to_be_bytes()); // major (Java 21)
        v.extend_from_slice(&1u16.to_be_bytes()); // cp count = 1 (just the reserved entry)
        v.extend_from_slice(&0x0021u16.to_be_bytes()); // access flags
        v.extend_from_slice(&0u16.to_be_bytes()); // this_class
        v.extend_from_slice(&0u16.to_be_bytes()); // super_class
        v.extend_from_slice(&0u16.to_be_bytes()); // interfaces_count
        v.extend_from_slice(&0u16.to_be_bytes()); // fields_count
        v.extend_from_slice(&0u16.to_be_bytes()); // methods_count
        v
    }

    #[test]
    fn parse_minimal_class_succeeds() {
        let v = make_minimal_class();
        let c = parse_class(&v).unwrap();
        assert_eq!(c.major_version, 65);
        assert_eq!(c.constant_pool.len(), 1); // just the reserved index
        assert!(c.methods.is_empty());
    }

    #[test]
    fn bad_magic_errors() {
        let mut v = make_minimal_class();
        v[0] = 0;
        assert_eq!(parse_class(&v), Err(ClassError::BadMagic));
    }

    #[test]
    fn truncated_input_errors() {
        let v = vec![0xCAu8, 0xFE, 0xBA, 0xBE];
        match parse_class(&v) {
            Err(ClassError::Truncated(_)) => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn over_size_input_errors() {
        // We don't allocate; just test the up-front length check.
        let v = vec![0u8; MAX_CLASS_SIZE + 1];
        match parse_class(&v) {
            Err(ClassError::TooLarge { .. }) => {}
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn constant_pool_long_double_take_two_slots() {
        let mut v = Vec::new();
        v.extend_from_slice(&CLASS_MAGIC.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&65u16.to_be_bytes());
        v.extend_from_slice(&3u16.to_be_bytes()); // cp_count = 3 means 2 real entries
        v.push(5); // Long
        v.extend_from_slice(&0xDEAD_BEEF_DEAD_BEEFu64.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes()); // access flags
        v.extend_from_slice(&0u16.to_be_bytes()); // this_class
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        let c = parse_class(&v).unwrap();
        // After parse: cp_count = 3, pool has 3 entries (None, Long, None).
        assert_eq!(c.constant_pool.len(), 3);
        assert!(matches!(c.constant_pool[1], Constant::Long(_)));
        assert!(matches!(c.constant_pool[2], Constant::None));
    }

    #[test]
    fn utf8_constant_resolves_to_string() {
        let mut v = Vec::new();
        v.extend_from_slice(&CLASS_MAGIC.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&65u16.to_be_bytes());
        v.extend_from_slice(&2u16.to_be_bytes()); // cp_count = 2
        let s = "Hello/World";
        v.push(1); // Utf8 tag
        v.extend_from_slice(&(s.len() as u16).to_be_bytes());
        v.extend_from_slice(s.as_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        let c = parse_class(&v).unwrap();
        assert_eq!(c.utf8_at(1), Some("Hello/World"));
    }

    #[test]
    fn class_name_resolves_via_pool() {
        // Constant pool: [None, Class{2}, Utf8("My/Class")]
        let class_name = "My/Class";
        let mut v = Vec::new();
        v.extend_from_slice(&CLASS_MAGIC.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&65u16.to_be_bytes());
        v.extend_from_slice(&3u16.to_be_bytes()); // cp_count = 3
        // Index 1: Class
        v.push(7);
        v.extend_from_slice(&2u16.to_be_bytes());
        // Index 2: Utf8
        v.push(1);
        v.extend_from_slice(&(class_name.len() as u16).to_be_bytes());
        v.extend_from_slice(class_name.as_bytes());
        v.extend_from_slice(&0u16.to_be_bytes()); // access
        v.extend_from_slice(&1u16.to_be_bytes()); // this_class -> index 1
        v.extend_from_slice(&0u16.to_be_bytes()); // super
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        let c = parse_class(&v).unwrap();
        assert_eq!(c.class_name(), Some(class_name));
    }

    #[test]
    fn method_bytecode_returns_code_attribute() {
        let mut v = Vec::new();
        v.extend_from_slice(&CLASS_MAGIC.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&65u16.to_be_bytes());
        v.extend_from_slice(&2u16.to_be_bytes()); // cp_count = 2
        v.push(1); // Utf8 "Code"
        v.extend_from_slice(&4u16.to_be_bytes());
        v.extend_from_slice(b"Code");
        v.extend_from_slice(&0u16.to_be_bytes()); // access flags
        v.extend_from_slice(&0u16.to_be_bytes()); // this
        v.extend_from_slice(&0u16.to_be_bytes()); // super
        v.extend_from_slice(&0u16.to_be_bytes()); // interfaces
        v.extend_from_slice(&0u16.to_be_bytes()); // fields
        v.extend_from_slice(&1u16.to_be_bytes()); // 1 method
        // method 0: access=0 name=0 desc=0 attrs=1
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes()); // attrs_count
        // attr: name_index=1 (Utf8 "Code"), length=8+3
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&11u32.to_be_bytes());
        v.extend_from_slice(&[0u8; 4]); // max_stack, max_locals
        v.extend_from_slice(&3u32.to_be_bytes()); // code_length = 3
        v.extend_from_slice(&[0x01u8, 0xb1, 0xb1]); // aconst_null, areturn, areturn (junk but bytes)
        let c = parse_class(&v).unwrap();
        let m = &c.methods[0];
        let code = method_bytecode(&c, m).unwrap();
        assert_eq!(code, &[0x01, 0xb1, 0xb1]);
    }

    #[test]
    fn decode_mutf8_basic_ascii() {
        assert_eq!(decode_mutf8(b"hello").unwrap(), "hello");
    }

    #[test]
    fn decode_mutf8_rejects_null_byte() {
        assert!(decode_mutf8(&[0x00]).is_err());
    }
}
