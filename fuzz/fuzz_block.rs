//! Fuzzing harness for StatementBlock deserialization
#![no_main]
use libfuzzer_sys::fuzz_target;
use kovanica_types::block::StatementBlock;
use bincode;

fuzz_target!(|data: &[u8]| {
    // Try to deserialize as StatementBlock
    if let Ok(block) = bincode::deserialize::<StatementBlock>(data) {
        // If successful, verify the block structure
        let _ = block.digest;
        let _ = block.author;
        let _ = block.round;
    }
});