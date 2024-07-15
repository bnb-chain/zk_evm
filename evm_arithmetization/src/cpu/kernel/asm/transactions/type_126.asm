// Type 126(0x7e) transactions, introduced by EIP 2718 and
// https://specs.optimism.io/protocol/deposits.html#l1-attributes-deposited-transaction
// , have the format
//     0x7e || rlp([sourceHash, from, to, mint, value, gas, isSystemTx, data])

// TODO TODO TODO unconditional mint value
global process_type_126_txn:
    // stack: retdest
    // Initial rlp address offset of 1 (skipping over the 0x7e byte)
    PUSH 1
    PUSH @INITIAL_TXN_RLP_ADDR
    %build_kernel_address
    // stack: rlp_addr, retdest
    %decode_rlp_list_len
    // We don't actually need the length.
    %stack (rlp_addr, len) -> (rlp_addr)

    // stack: rlp_addr, retdest
    %decode_and_store_source_hash
    %decode_and_store_from
    %decode_and_store_to
    %decode_and_store_mint
    %decode_and_store_value
    %decode_and_store_gas_limit
    %decode_and_store_is_system_tx
    %decode_and_store_data

    // stack: rlp_addr, retdest
    POP
    // stack: retdest

// // jump_to_processor:
// //     // stack: retdest
// //     %jump(process_normalized_deposit_txn)

// Pre stack: retdest
// Post stack: success, leftover_gas
process_normalized_deposit_txn:
    // stack: retdest
    %compute_deposit_fees
    // stack: retdest

    // Compute this transaction's intrinsic gas and store it.
    %intrinsic_gas
    DUP1
    %mstore_txn_field(@TXN_FIELD_INTRINSIC_GAS)
    // stack: intrinsic_gas, retdest

    // Assert gas_limit >= intrinsic_gas.
    %mload_txn_field(@TXN_FIELD_GAS_LIMIT)
    %assert_ge(invalid_deposit_txn)

    // Assert block gas limit >= txn gas limit.
    %mload_txn_field(@TXN_FIELD_GAS_LIMIT)
    %mload_global_metadata(@GLOBAL_METADATA_BLOCK_GAS_LIMIT)
    %assert_ge(invalid_deposit_txn)

    %mload_txn_field(@TXN_FIELD_ORIGIN)
    // stack: sender, retdest

    // Check that txn nonce matches account nonce.
    // TODO check from receipt depositNonce

    // // Assert sender has no code.

    // Assert sender balance >= gas_limit * 0 + value.
    %balance
    %mload_txn_field(@TXN_FIELD_VALUE)
    %assert_le(invalid_deposit_txn)
    // stack: retdest

increment_deposit_sender_nonce:
    %mload_txn_field(@TXN_FIELD_ORIGIN)
    DUP1 %increment_nonce

warm_deposit_origin:
    // stack: origin, retdest
    %insert_accessed_addresses_no_return

warm_deposit_precompiles:
    // Add precompiles to accessed addresses.
    PUSH @ECREC %insert_accessed_addresses_no_return
    PUSH @SHA256 %insert_accessed_addresses_no_return
    PUSH @RIP160 %insert_accessed_addresses_no_return
    PUSH @ID %insert_accessed_addresses_no_return
    PUSH @EXPMOD %insert_accessed_addresses_no_return
    PUSH @BN_ADD %insert_accessed_addresses_no_return
    PUSH @BN_MUL %insert_accessed_addresses_no_return
    PUSH @SNARKV %insert_accessed_addresses_no_return
    PUSH @BLAKE2_F %insert_accessed_addresses_no_return

// EIP-3651
warm_deposit_coinbase:
    %mload_global_metadata(@GLOBAL_METADATA_BLOCK_BENEFICIARY)
    %insert_accessed_addresses_no_return
// TODO warm L1 system accounts

process_deposit_based_on_type:
    %is_contract_creation
    %jumpi(process_deposit_contract_creation_txn)
    %jump(process_deposit_message_txn)

process_deposit_contract_creation_txn:
    // stack: retdest

    %mload_txn_field(@TXN_FIELD_ORIGIN)
    // stack: origin, retdest
    DUP1 %nonce
    // stack: origin_nonce, origin, retdest
    %decrement // Need the non-incremented nonce
    SWAP1
    // stack: origin, origin_nonce, retdest
    %get_create_address
    // stack: address, retdest
    DUP1 %insert_accessed_addresses_no_return

    %checkpoint

    // Create the new contract account in the state trie.
    DUP1
    // stack: address, address, retdest
    %create_contract_account
    // stack: status, address, retdest
    %jumpi(create_contract_account_fault)

    // stack: address, retdest
    // Transfer value to new contract
    DUP1 %mload_txn_field(@TXN_FIELD_VALUE)
    SWAP1
    %mload_txn_field(@TXN_FIELD_ORIGIN)
    DUP3 DUP3 DUP3
    %transfer_eth %jumpi(panic)
    %journal_add_balance_transfer
    // stack: address, retdest

    %create_context
    // stack: new_ctx, address, retdest

    // Store constructor code length
    PUSH @CTX_METADATA_CODE_SIZE
    // stack: offset, new_ctx, address, retdest
    DUP2 // new_ctx
    ADD // CTX_METADATA_CODE_SIZE is already scaled by its segment
    // stack: addr, new_ctx, address, retdest
    %mload_txn_field(@TXN_FIELD_DATA_LEN)
    // stack: data_len, addr, new_ctx, address, retdest
    MSTORE_GENERAL
    // stack: new_ctx, address, retdest

    // Copy the code from txdata to the new context's code segment.
    PUSH process_deposit_contract_creation_txn_after_code_loaded
    %mload_txn_field(@TXN_FIELD_DATA_LEN)
    PUSH @SEGMENT_TXN_DATA // SRC (context == offset == 0)
    DUP4 // DST (segment == 0 (i.e. CODE), and offset == 0)
    %jump(memcpy_bytes)

process_deposit_contract_creation_txn_after_code_loaded:
    // stack: new_ctx, address, retdest

    // Each line in the block below does not change the stack.
    DUP2 %set_new_ctx_addr
    %mload_txn_field(@TXN_FIELD_ORIGIN) %set_new_ctx_caller
    %mload_txn_field(@TXN_FIELD_VALUE) %set_new_ctx_value
    %set_new_ctx_parent_ctx
    %set_new_ctx_parent_pc(process_deposit_contract_creation_txn_after_constructor)
    %deposit_non_intrinisic_gas %set_new_ctx_gas_limit
    // stack: new_ctx, address, retdest

    %enter_new_ctx
    // (Old context) stack: new_ctx, address, retdest

process_deposit_contract_creation_txn_after_constructor:
    // stack: success, leftover_gas, new_ctx, address, retdest
    // We eventually return leftover_gas and success.
    %stack (success, leftover_gas, new_ctx, address, retdest) -> (success, leftover_gas, new_ctx, address, retdest, success)

    ISZERO %jumpi(contract_creation_fault_3)

    // EIP-3541: Reject new contract code starting with the 0xEF byte
    PUSH 0 %mload_current(@SEGMENT_RETURNDATA) %eq_const(0xEF) %jumpi(contract_creation_fault_3_zero_leftover)

    // stack: leftover_gas, new_ctx, address, retdest, success
    %returndatasize // Size of the code.
    // stack: code_size, leftover_gas, new_ctx, address, retdest, success
    DUP1 %gt_const(@MAX_CODE_SIZE) %jumpi(contract_creation_fault_4)
    // stack: code_size, leftover_gas, new_ctx, address, retdest, success
    %mul_const(@GAS_CODEDEPOSIT) SWAP1
    // stack: leftover_gas, codedeposit_cost, new_ctx, address, retdest, success
    DUP2 DUP2 LT %jumpi(contract_creation_fault_4)
    // stack: leftover_gas, codedeposit_cost, new_ctx, address, retdest, success
    SUB

    // Store the code hash of the new contract.
    // stack: leftover_gas, new_ctx, address, retdest, success
    %returndatasize
    PUSH @SEGMENT_RETURNDATA
    GET_CONTEXT
    %build_address_no_offset
    // stack: addr, len
    KECCAK_GENERAL
    // stack: codehash, leftover_gas, new_ctx, address, retdest, success
    %observe_new_contract
    DUP4
    // stack: address, codehash, leftover_gas, new_ctx, address, retdest, success
    %set_codehash

    %stack (leftover_gas, new_ctx, address, retdest, success) -> (leftover_gas, new_ctx, address, retdest, success, leftover_gas)
    %deposit_pay_coinbase_and_refund_sender
    // stack: leftover_gas', new_ctx, address, retdest, success, leftover_gas
    SWAP5 POP
    %delete_all_touched_addresses
    %delete_all_selfdestructed_addresses
    // stack: new_ctx, address, retdest, success, leftover_gas
    POP
    POP
    JUMP

global process_deposit_message_txn:
    // stack: retdest
    %mload_txn_field(@TXN_FIELD_VALUE)
    %mload_txn_field(@TXN_FIELD_TO)
    DUP1 %insert_accessed_addresses_no_return
    %mload_txn_field(@TXN_FIELD_ORIGIN)
    // stack: from, to, amount, retdest
    %transfer_eth
    // stack: transfer_eth_status, retdest
    %jumpi(process_deposit_message_txn_insufficient_balance)
    // stack: retdest

    %handle_precompiles_from_eoa

    // If to's code is empty, return.
    %mload_txn_field(@TXN_FIELD_TO) %ext_code_empty
    // stack: code_empty, retdest
    %jumpi(process_deposit_message_txn_return)

    // Otherwise, load to's code and execute it in a new context.
    // stack: retdest
    %create_context
    // stack: new_ctx, retdest
    PUSH process_deposit_message_txn_code_loaded
    DUP2 // new_ctx
    %mload_txn_field(@TXN_FIELD_TO)
    // stack: address, new_ctx, process_deposit_message_txn_code_loaded, new_ctx, retdest
    %jump(load_code_padded)

process_deposit_message_txn_insufficient_balance:
    // stack: retdest
    PANIC // TODO

process_deposit_message_txn_return:
    // stack: retdest
    // Since no code was executed, the leftover gas is the non-intrinsic gas.
    %deposit_non_intrinisic_gas
    DUP1
    // stack: leftover_gas, leftover_gas, retdest
    %deposit_pay_coinbase_and_refund_sender
    // stack: leftover_gas', leftover_gas, retdest
    SWAP1 POP
    %delete_all_touched_addresses
    // stack: leftover_gas', retdest
    SWAP1
    PUSH 1 // success
    SWAP1
    // stack: retdest, success, leftover_gas
    JUMP

process_deposit_message_txn_code_loaded:
    // stack: code_size, new_ctx, retdest
    %set_new_ctx_code_size
    // stack: new_ctx, retdest

    // Each line in the block below does not change the stack.
    %mload_txn_field(@TXN_FIELD_TO) %set_new_ctx_addr
    %mload_txn_field(@TXN_FIELD_ORIGIN) %set_new_ctx_caller
    %mload_txn_field(@TXN_FIELD_VALUE) %set_new_ctx_value
    %set_new_ctx_parent_ctx
    %set_new_ctx_parent_pc(process_deposit_message_txn_after_call)
    %deposit_non_intrinisic_gas %set_new_ctx_gas_limit
    // stack: new_ctx, retdest

    // Set calldatasize and copy txn data to calldata.
    %mload_txn_field(@TXN_FIELD_DATA_LEN)
    %stack (calldata_size, new_ctx, retdest) -> (calldata_size, new_ctx, calldata_size, retdest)
    %set_new_ctx_calldata_size
    %stack (new_ctx, calldata_size, retdest) -> (new_ctx, @SEGMENT_CALLDATA, @SEGMENT_TXN_DATA, calldata_size, process_deposit_message_txn_code_loaded_finish, new_ctx, retdest)
    %build_address_no_offset // DST
    %jump(memcpy_bytes)

process_deposit_message_txn_code_loaded_finish:
    %enter_new_ctx
    // (Old context) stack: new_ctx, retdest

process_deposit_message_txn_after_call:
    // stack: success, leftover_gas, new_ctx, retdest
    // We will return leftover_gas and success.
    %stack (success, leftover_gas, new_ctx, retdest) -> (success, leftover_gas, new_ctx, retdest, success, leftover_gas)
    ISZERO %jumpi(process_deposit_message_txn_fail)
process_deposit_message_txn_after_call_contd:
    // stack: leftover_gas, new_ctx, retdest, success, leftover_gas
    %deposit_pay_coinbase_and_refund_sender
    // stack: leftover_gas', new_ctx, retdest, success, leftover_gas
    SWAP4 POP
    %delete_all_touched_addresses
    %delete_all_selfdestructed_addresses
    // stack: new_ctx, retdest, success, leftover_gas
    POP
    JUMP

process_deposit_message_txn_fail:
    // stack: leftover_gas, new_ctx, retdest, success, leftover_gas
    // Transfer value back to the caller.
    %mload_txn_field(@TXN_FIELD_VALUE) ISZERO %jumpi(process_deposit_message_txn_after_call_contd)
    %mload_txn_field(@TXN_FIELD_VALUE)
    %mload_txn_field(@TXN_FIELD_ORIGIN)
    %mload_txn_field(@TXN_FIELD_TO)
    %transfer_eth %jumpi(panic)
    %jump(process_deposit_message_txn_after_call_contd)

%macro deposit_pay_coinbase_and_refund_sender
    // stack: leftover_gas
%endmacro

// Sets @TXN_FIELD_MAX_FEE_PER_GAS and @TXN_FIELD_MAX_PRIORITY_FEE_PER_GAS.
%macro compute_deposit_fees
    // stack: (empty)
    PUSH 0
    PUSH 0
    // stack: computed_fee, computed_priority_fee
    %mstore_txn_field(@TXN_FIELD_COMPUTED_FEE_PER_GAS)
    %mstore_txn_field(@TXN_FIELD_COMPUTED_PRIORITY_FEE_PER_GAS)
    // stack: (empty)
%endmacro

%macro deposit_non_intrinisic_gas
    // stack: (empty)
    %mload_txn_field(@TXN_FIELD_INTRINSIC_GAS)
    %mload_txn_field(@TXN_FIELD_GAS_LIMIT)
    SUB
    // stack: gas_limit - intrinsic_gas
%endmacro

create_contract_account_fault:
    %revert_checkpoint
    // stack: address, retdest
    POP
    PUSH 0 // leftover_gas
    // stack: leftover_gas, retdest
    %deposit_pay_coinbase_and_refund_sender
    // stack: leftover_gas', retdest
    %delete_all_touched_addresses
    %delete_all_selfdestructed_addresses
    // stack: leftover_gas', retdest
    SWAP1 PUSH 0 // success
    // stack: success, retdest, leftover_gas
    SWAP1
    JUMP

contract_creation_fault_3:
    %revert_checkpoint
    %stack (leftover_gas, new_ctx, address, retdest, success) -> (leftover_gas, retdest, success)
    %deposit_pay_coinbase_and_refund_sender
    // stack: leftover_gas', retdest, success
    %delete_all_touched_addresses
    %delete_all_selfdestructed_addresses
    %stack (leftover_gas, retdest, success) -> (retdest, 0, leftover_gas)
    JUMP

contract_creation_fault_3_zero_leftover:
    %revert_checkpoint
    // stack: leftover_gas, new_ctx, address, retdest, success
    %pop3
    PUSH 0 // leftover gas
    // stack: leftover_gas, retdest, success
    %deposit_pay_coinbase_and_refund_sender
    %delete_all_touched_addresses
    %delete_all_selfdestructed_addresses
    %stack (leftover_gas, retdest, success) -> (retdest, 0, leftover_gas)
    JUMP

contract_creation_fault_4:
    %revert_checkpoint
    // stack: code_size/leftover_gas, leftover_gas/codedeposit_cost, new_ctx, address, retdest, success
    %pop4
    PUSH 0 // leftover gas
    // stack: leftover_gas, retdest, success
    %deposit_pay_coinbase_and_refund_sender
    %delete_all_touched_addresses
    %delete_all_selfdestructed_addresses
    %stack (leftover_gas, retdest, success) -> (retdest, 0, leftover_gas)
    JUMP


invalid_deposit_txn:
    POP
    %mload_txn_field(@TXN_FIELD_GAS_LIMIT)
    PUSH 0
    %jump(txn_after)

invalid_deposit_txn_1:
    %pop2
    %mload_txn_field(@TXN_FIELD_GAS_LIMIT)
    PUSH 0
    %jump(txn_after)

invalid_deposit_txn_2:
    %pop3
    %mload_txn_field(@TXN_FIELD_GAS_LIMIT)
    PUSH 0
    %jump(txn_after)

invalid_deposit_txn_3:
    %pop4
    %mload_txn_field(@TXN_FIELD_GAS_LIMIT)
    PUSH 0
    %jump(txn_after)
