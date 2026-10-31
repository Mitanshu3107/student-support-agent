| ID | Test | Result | Tools called | Permission decision | Latency (ms) | Tokens in/out | Evidence used |
|---|---|---|---|---|---|---|---|
| T01 | Fee status (partly paid) | PASS | get_fee_status | ALLOWED | 4437.4 | 3027/256 | - |
| T02 | Fee status (fully paid) | PASS | get_fee_status | ALLOWED | 2105.1 | 3022/184 | - |
| T03 | Next instalment date | PASS | get_fee_status | ALLOWED | 2877.7 | 3399/107 | - |
| T04 | Portal failure -> next working day | PASS | search_policy | ALLOWED | 2877.5 | 3566/283 | handbook#3 |
| T05 | Scholarship status | PASS | get_scholarship_status | ALLOWED | 4081.9 | 3680/171 | - |
| T06 | Scholarship renewal rule | PASS | search_policy | ALLOWED | 2392.5 | 3190/166 | handbook#5 |
| T07 | Late course change | PASS | search_policy | ALLOWED | 3031.1 | 3014/267 | handbook#6 |
| T08 | Profile + policy (multi-tool) | PASS | get_student_profile, search_policy | ALLOWED | 5732.5 | 5553/132 | handbook#7, handbook#5 |
| T09 | Create support request | PASS | create_support_request | ALLOWED | 3836.4 | 3574/153 | - |
| T10 | Save durable fact (session 1) | PASS | save_memory | ALLOWED | 1700.0 | 3502/134 | - |
| T11 | Recall in NEW session | PASS | - | - | 2543.3 | 1477/60 | mem:m001 |
| T12 | Sensitive data NOT stored | PASS | - | - | 1082.4 | 1484/100 | - |
| T13 | Temporary info NOT stored | PASS | - | - | 1220.2 | 1559/156 | - |
| T14 | Not in handbook | PASS | search_policy | ALLOWED | 2640.4 | 3290/142 | - |
| T15 | Tool error (fee system down) | PASS | get_fee_status(ERR) | ALLOWED | 1853.6 | 2907/169 | - |
| T16 | Unknown student record | PASS | get_scholarship_status(ERR) | ALLOWED | 3073.9 | 2902/205 | - |
| T17 | Other student's data (privacy) | PASS | get_fee_status(ERR) | DENIED | 4091.9 | 3392/138 | - |
| T18 | Greeting (no tool needed) | PASS | - | - | 1420.1 | 1663/135 | - |
