#!/bin/bash
# Apply patches to the nxp-se050 driver for simulator compatibility
set -e

DRIVER_DIR="${1:-/app/nxp-se050}"

# 1. Pin embedded-hal to 0.2 (driver uses "blocking" module from 0.2.x)
sed -i 's/embedded-hal = "\*"/embedded-hal = "0.2"/' "$DRIVER_DIR/se050/Cargo.toml"

# 2. Fix CApduByteIterator panic when body deque is empty (commands with no TLV data)
sed -i 's/self.area = 1;/if self.body.is_empty() { self.area = 2; } else { self.area = 1; }/' \
    "$DRIVER_DIR/se050/src/types.rs"

# 3. Fix CApduByteIterator panic when TLV has empty data (e.g., empty policy)
sed -i 's/obj.body.push_back(tlv.data).unwrap();/if !tlv.data.is_empty() { obj.body.push_back(tlv.data).unwrap(); }/' \
    "$DRIVER_DIR/se050/src/types.rs"

# 4. Fix response buffers that are too small (16 bytes can't hold TLV responses)
sed -i 's/rapdu_buf: \[u8; 16\] = \[0; 16\]/rapdu_buf: [u8; 260] = [0; 260]/g' \
    "$DRIVER_DIR/se050/src/se050.rs"

# 5. Fix SimpleTlv header capacity (3 bytes too small for extended TLV length form)
sed -i 's/heapless::Vec<u8, 3>/heapless::Vec<u8, 4>/g' \
    "$DRIVER_DIR/se050/src/types.rs"

echo "Driver patches applied successfully."
