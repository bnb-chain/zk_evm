// struct AccountCreated { address }

%macro journal_add_account_created
    %journal_add_1(@JOURNAL_ENTRY_ACCOUNT_CREATED)
%endmacro

global revert_account_created:
    // stack: entry_type, ptr, retdest
    POP
    %journal_load_1
    // stack: address, retdest
    %addr_to_state_key
    %remove_account_from_linked_list
    JUMP
