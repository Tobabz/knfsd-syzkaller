
typedef bool            fattr4_offline;


const FATTR4_OFFLINE            = 83;


struct open_arguments4 {
  bitmap4  oa_share_access;
  bitmap4  oa_share_deny;
  bitmap4  oa_share_access_want;
  bitmap4  oa_open_claim;
  bitmap4  oa_create_mode;
};


enum open_args_share_access4 {
   OPEN_ARGS_SHARE_ACCESS_READ  = 1,
   OPEN_ARGS_SHARE_ACCESS_WRITE = 2,
   OPEN_ARGS_SHARE_ACCESS_BOTH  = 3
};


enum open_args_share_deny4 {
   OPEN_ARGS_SHARE_DENY_NONE  = 0,
   OPEN_ARGS_SHARE_DENY_READ  = 1,
   OPEN_ARGS_SHARE_DENY_WRITE = 2,
   OPEN_ARGS_SHARE_DENY_BOTH  = 3
};


enum open_args_share_access_want4 {
   OPEN_ARGS_SHARE_ACCESS_WANT_ANY_DELEG           = 3,
   OPEN_ARGS_SHARE_ACCESS_WANT_NO_DELEG            = 4,
   OPEN_ARGS_SHARE_ACCESS_WANT_CANCEL              = 5,
   OPEN_ARGS_SHARE_ACCESS_WANT_SIGNAL_DELEG_WHEN_RESRC_AVAIL
                                                   = 17,
   OPEN_ARGS_SHARE_ACCESS_WANT_PUSH_DELEG_WHEN_UNCONTENDED
                                                   = 18,
   OPEN_ARGS_SHARE_ACCESS_WANT_DELEG_TIMESTAMPS    = 20,
   OPEN_ARGS_SHARE_ACCESS_WANT_OPEN_XOR_DELEGATION = 21
};


enum open_args_open_claim4 {
   OPEN_ARGS_OPEN_CLAIM_NULL          = 0,
   OPEN_ARGS_OPEN_CLAIM_PREVIOUS      = 1,
   OPEN_ARGS_OPEN_CLAIM_DELEGATE_CUR  = 2,
   OPEN_ARGS_OPEN_CLAIM_DELEGATE_PREV = 3,
   OPEN_ARGS_OPEN_CLAIM_FH            = 4,
   OPEN_ARGS_OPEN_CLAIM_DELEG_CUR_FH  = 5,
   OPEN_ARGS_OPEN_CLAIM_DELEG_PREV_FH = 6
};


enum open_args_createmode4 {
   OPEN_ARGS_CREATEMODE_UNCHECKED4     = 0,
   OPEN_ARGS_CREATE_MODE_GUARDED       = 1,
   OPEN_ARGS_CREATEMODE_EXCLUSIVE4     = 2,
   OPEN_ARGS_CREATE_MODE_EXCLUSIVE4_1  = 3
};


typedef open_arguments4 fattr4_open_arguments;


%/*
% * Determine what OPEN supports.
% */
const FATTR4_OPEN_ARGUMENTS     = 86;


const OPEN4_SHARE_ACCESS_WANT_OPEN_XOR_DELEGATION = 0x200000;


const OPEN4_RESULT_NO_OPEN_STATEID = 0x00000010;


/*
 * attributes for the delegation times being
 * cached and served by the "client"
 */
typedef nfstime4        fattr4_time_deleg_access;
typedef nfstime4        fattr4_time_deleg_modify;


%/*
% * New RECOMMENDED Attribute for
% * delegation caching of times
% */
const FATTR4_TIME_DELEG_ACCESS  = 84;
const FATTR4_TIME_DELEG_MODIFY  = 85;


const OPEN4_SHARE_ACCESS_WANT_DELEG_TIMESTAMPS = 0x100000;

enum open_delegation_type4 {
       OPEN_DELEGATE_NONE                  = 0,
       OPEN_DELEGATE_READ                  = 1,
       OPEN_DELEGATE_WRITE                 = 2,
       OPEN_DELEGATE_NONE_EXT              = 3, /* new to v4.1 */
       OPEN_DELEGATE_READ_ATTRS_DELEG      = 4,
       OPEN_DELEGATE_WRITE_ATTRS_DELEG     = 5
};
