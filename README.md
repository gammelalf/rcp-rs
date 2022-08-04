# rcp-rs

Implemention of [RCP](https://github.com/myOmikron/rcp) in rust


## Usage

```rust
use std::collections::HashMap;
use rc_protocol::RCPConfig;

// Config is used to create a checksum as well as validate a checksum
let config = RCPConfig {
  shared_secret: "Shared Secret Key".to_string(),
  use_time_component: true,
  time_delta: 5,
};

let mut m = HashMap::new();
m.insert("key1", "value1");
m.insert("key2", "value2");

// Get the checksum for a given dictionary
let checksum = config.get_checksum(&m, "TestSalt"); 

// Validate a given checksum
if !config.validate_checksum(&m, "TestSalt", &checksum) {
     println!("Checksum was incorrect");
}
```
