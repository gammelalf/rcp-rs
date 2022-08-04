use std::fmt::{Write, Display};
use sha2::{Sha512, Digest};
use chrono::Utc;

/// Parameters for communicating with a single partner.
#[derive(Debug, Clone)]
pub struct RCPConfig {
    /// An arbitrary but secure string to only known by both partners.
    pub shared_secret: String,

    /// Whether or not to include timestamps into the checksum
    ///
    /// For two servers there is really no reason not to to it.
    /// It prevents a valid checksum to be reused by a man in the middle to a later time.
    ///
    /// For a server and client, one has to estimate network latency and possibly out of sync clocks.
    pub use_time_component: bool,

    /// By how many second is the partner's timestamp allowed to deviate from your own?
    ///
    /// Only relevant if `use_time_component` is `true`.
    ///
    /// **Beware:**
    /// Since the checksum is a hash, there is no way to get the actual timestamp out of it again.
    /// This means, the only thing the receiver can do is to take its own one and iterate over small
    /// permutations to see if any matches.
    /// Therefore if your `time_delta` is to large, checking all possible deviations might take
    /// longer than you want a validation to.
    /// *This protocol was never designed to handle time spans above a few seconds.*
    pub time_delta: i64,
}
impl Default for RCPConfig {
    /// ```hidden
    /// RCPConfig {
    ///     shared_secret: "".to_string(),
    ///     use_time_component: true,
    ///     time_delta: 5,
    /// }
    /// ```
    fn default() -> Self {
        RCPConfig {
            shared_secret: String::new(),
            use_time_component: true,
            time_delta: 5
        }
    }
}
impl RCPConfig {
    /// Calculate a request's checksum from its payload and a salt.
    ///
    /// When writing HTTP APIs it is a good rule of thumb to use a request's endpoint as salt.
    pub fn get_checksum<R: Request>(&self, request: R, salt: &str) -> String {
        let mut string = pre_assemble(request, &self.shared_secret, salt);

        if self.use_time_component {
            // Append current utc timestamp (unix epoch - just seconds)
            write!(string, "{}", Utc::now().timestamp()).unwrap();
        }

        // Hash with SHA512
        // Represent the hash as hex string (lowercase)
        sha512(string)
    }

    /// Check whether or not a checksum matches a given payload and salt.
    ///
    /// If your not using timestamps, this will basically to a `get_checksum(..) == checksum`.
    /// If you are, it iterates over the `time_delta` checking multiple timestamps.
    pub fn validate_checksum<R: Request>(&self, request: R, salt: &str, checksum: &str) -> bool {
        if self.use_time_component {
            let string = pre_assemble(request, &self.shared_secret, salt);
            let now = Utc::now().timestamp();
            for delta in (-self.time_delta)..(self.time_delta) {
                let string = format!("{}{}", string, now + delta);
                if sha512(string) == checksum {
                    return true;
                }
            }
            false
        } else {
            self.get_checksum(request, salt) == checksum
        }
    }
}

/// Everything in `get_checksum` before adding a timestamp
fn pre_assemble(request: impl Request, shared_secret: &str, salt: &str) -> String {
    let mut pairs = request.into_pairs();

    // Sort the dictionary alphanumerical by its keys.
    pairs.sort_by(|(k1, _), (k2, _)| k1.as_ref().cmp(k2.as_ref()));

    // Concat its values to the respective key and join them: `key1value1key2value2...`
    // Optional: Add a salt (this may be the method's endpoint): `saltkey1value1...`
    // Append the shared secret of your target
    let mut string = salt.to_string();
    for (key, value) in pairs.into_iter() {
        write!(string, "{}", key.as_ref()).unwrap();
        write!(string, "{}", value).unwrap();
    }
    write!(string, "{}", shared_secret).unwrap();

    string
}

/// Wrapper for computing a String's sha512
///
/// Effectivly everything in `get_checksum` after adding a timestamp
fn sha512(data: impl AsRef<[u8]>) -> String {
    let mut hasher = Sha512::new();
    hasher.update(data);
    let bytes = &hasher.finalize()[..];

    let mut string = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(string, "{:02x}", byte).unwrap();
    }

    string
}

/// Trait implemented for all accepted payload types.
///
/// It is just a nice wrapper for hiding a slightly more complex type constraint behind.
pub trait Request {
    type Key: AsRef<str>;
    type Value: Display;

    fn into_pairs(self) -> Vec<(Self::Key, Self::Value)>;
}
impl<I, K, V> Request for I
where
    I: IntoIterator<Item=(K, V)>,
    K: AsRef<str>,
    V: Display,
{
    type Key = K;
    type Value = V;

    fn into_pairs(self) -> Vec<(Self::Key, Self::Value)> {
        self.into_iter().collect()
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::fmt::Display;
    use crate::RCPConfig;

    /// Check the generic's ease of use with a few common types.
    ///
    /// This doesn't contain any asserts, the compiling is the actual test.
    #[test]
    fn syntax() {
        let config = RCPConfig::default();

        // HaspMap of i32
        let mut request = HashMap::new();
        request.insert("foo".to_string(), 4);
        request.insert("bar".to_string(), 10);
        request.insert("bar".to_string(), -7);
        config.get_checksum(request, "");

        // Vec of &'static str
        let mut request = Vec::new();
        request.push(("foo", "4"));
        request.push(("bar", "10"));
        request.push(("baz", "-7"));
        config.get_checksum(request, "");

        // Array of f64
        let request = [
            ("foo", 4.0),
            ("bar", 10.0),
            ("baz", -7.0),
        ];
        config.get_checksum(request, "");

        // Array of trait objects
        let request = [
            ("foo", &4 as &dyn Display),
            ("bar", &"10" as &dyn Display),
            ("baz", &-7.0 as &dyn Display),
        ];
        config.get_checksum(request, "");

        // TODO
        // "empty" request need a type annotation using effectively arbitrary type
        // which fulfill the constraints.
        // This is really ugly, but I have no idea how to fix it yet and it's not that common.
        //
        // A consideration was implementing Request for () but this potentially collides
        // with the generic implementation, as "upstream" i.e. rust could implement IntoIterator
        // for (). I'm sure they won't but neither me nor the compiler can guarantee that,
        // so he won't let me.
        config.get_checksum::<[(&'static str, u8); 0]>([], "");
    }

    /// Check the correctness of validate_checksum against python's reference implementation
    #[test]
    fn validate_checksum() {
        let mut config = RCPConfig {
            use_time_component: false,
            shared_secret: "Hallo-123".to_string(),
            time_delta: 5,
        };
        let request = [("b", "test"), ("a", " long test")];

        // Output of reference implementation:
        // rc_protocol.get_checksum({}, "Hallo-123", use_time_component=False)
        let checksum = "477cec82c1c05f7acd42e4c9bd354f3021a59f9a0e8f6cca451c74511a75a8ee0aa4cddcf0a966e91de09b5708d26ce2a7737b65f286a368c87e751135cdc706";
        assert!(config.validate_checksum::<[(&str, u8); 0]>([], "", checksum));

        // Output of reference implementation:
        // rc_protocol.get_checksum({"b": "test", "a": " long test"}, "Hallo-123", salt="TestSalt", use_time_component=False)
        let checksum = "a85a29e01f295cba43de859a097b6f816826a0ef47bad9d210ab1410cc6ea8490f72a99e62c27b3aefd3b334b1a034d1b8ba1b8b0c6599c27674aeb96cebd591";
        assert!(config.validate_checksum(request, "TestSalt", checksum));

        config.use_time_component = true;
        let checksum = config.get_checksum(request, "TestSalt");
        assert!(config.validate_checksum(request, "TestSalt", &checksum));
    }

    /// Check the correctness of get_checksum against python's reference implementation
    #[test]
    fn get_checksum() {
        let config = RCPConfig {
            use_time_component: false,
            shared_secret: "Hallo-123".to_string(),
            time_delta: 5,
        };

        // Output of reference implementation:
        // rc_protocol.get_checksum({}, "Hallo-123", use_time_component=False)
        let checksum = "477cec82c1c05f7acd42e4c9bd354f3021a59f9a0e8f6cca451c74511a75a8ee0aa4cddcf0a966e91de09b5708d26ce2a7737b65f286a368c87e751135cdc706";
        assert_eq!(config.get_checksum::<[(&str, u8); 0]>([], ""), checksum);

        // Output of reference implementation:
        // rc_protocol.get_checksum({}, "Hallo-123", salt="TestSalt", use_time_component=False)
        let checksum = "50acbd16790dc2ebcc246ea9050acf4bee79088d1a9b0a0cd9f812a3b054b7c39e6ce44aa9c6e53b6d31c9d7da527cdd9a85ecaf2f5d007533d4cde289432683";
        assert_eq!(config.get_checksum::<[(&str, u8); 0]>([], "TestSalt"), checksum);

        // Output of reference implementation:
        // rc_protocol.get_checksum({"b": "test", "a": " long test"}, "Hallo-123", salt="TestSalt", use_time_component=False)
        let checksum = "a85a29e01f295cba43de859a097b6f816826a0ef47bad9d210ab1410cc6ea8490f72a99e62c27b3aefd3b334b1a034d1b8ba1b8b0c6599c27674aeb96cebd591";
        assert_eq!(config.get_checksum([("b", "test"), ("a", " long test")], "TestSalt"), checksum);
    }
}