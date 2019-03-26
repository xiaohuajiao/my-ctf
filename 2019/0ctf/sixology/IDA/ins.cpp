#include <idp.hpp>
#include "0ctf.hpp"

#ifndef RELEASE
instruc_t Instructions[] =
{
    { "",                       0                                             },
    { "ins_1",                       0                                             },
    { "allocframe",             CF_USE1                                       },
    { "store",                  CF_USE1 | CF_CHG2                             },
    { "exchange",               CF_CHG1 | CF_CHG2                                             },
    { "deallocframe",           0                                             },
    { "ins_6",                       0                                             },
    { "loop",                   CF_USE1 | CF_USE2                             },
    { "add",                    CF_CHG1 | CF_USE2 | CF_USE3                   },
    { "ins_9",                       0                                             },
    { "ins_10",                       0                                             },
    { "li",                     CF_CHG1 | CF_USE2                             },
    { "nor",                    CF_CHG1 | CF_USE2 | CF_USE3                   },
    { "ins_13",                       0                                             },
    { "sub",                    CF_CHG1 | CF_USE2 | CF_USE3                   },
    { "ins_15",                       0                                             },
    { "mov",                    CF_CHG1 | CF_USE2                             },
    // HINT: call
    { "call",                   CF_USE1 | CF_CALL                                       },
    { "ins_18",                       0                                             },
    { "jmp",                    CF_USE1 | CF_JUMP                                       },
    { "cmp",                    CF_CHG1 | CF_USE2 | CF_USE3                   },
    { "ins_21",                       0                                             },
    { "ins_22",                       0                                             },
    { "endloop",                CF_USE1 | CF_JUMP                                       },
    { "div",                    CF_CHG1 | CF_CHG2 | CF_USE3 | CF_USE4         },
    { "ins_25",                       0                                             },
    { "switch",                 CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP                        },
    { "lexcmp",                    CF_CHG1 | CF_USE2 | CF_USE3                   },
    { "ins_28",                       0                                             },
    { "ret",                    CF_STOP                                      },
    { "jmpcond",                CF_USE1 | CF_USE2 | CF_JUMP                                       },
    { "load",                   CF_CHG1 | CF_USE2                             },
};
#else
instruc_t Instructions[] =
{
    { "6666666666_____",                       0                                             },
    { "6666666______________",                       0                                             },
    { "666666666__________",             CF_USE1                                       },
    { "66666_____",                  CF_USE1 | CF_CHG2                             },
    { "6666____",                  CF_CHG1 | CF_CHG2                                                  },
    { "6666____________",           0                                             },
    { "66666666____",                       0                                             },
    { "666666666____________",                   CF_USE1 | CF_USE2                             },
    { "66666666____________",                    CF_CHG1 | CF_USE2 | CF_USE3                   },
    { "6666666666_______",                       0                                             },
    { "666666_____________",                       0                                             },
    { "6666666_________",                     CF_CHG1 | CF_USE2                             },
    { "666666666______",                    CF_CHG1 | CF_USE2 | CF_USE3                   },
    { "6666666_______",                       0                                             },
    { "666666____________",                    CF_CHG1 | CF_USE2 | CF_USE3                   },
    { "6666__________",                       0                                             },
    { "6666666________",                    CF_CHG1 | CF_USE2                             },
    // HINT: call
    { "666666666_________",                   CF_USE1 | CF_CALL                                       },
    { "6666___________",                       0                                             },
    { "6666666_____________",                    CF_USE1 | CF_JUMP                                       },
    { "66666666_________",                    CF_CHG1 | CF_USE2 | CF_USE3                   },
    { "6666_______",                       0                                             },
    { "6666666__________",                       0                                             },
    { "6666_____",                CF_USE1 | CF_JUMP                                       },
    { "6666666___",                    CF_CHG1 | CF_CHG2 | CF_USE3 | CF_USE4         },
    { "6666666666____________",                       0                                             },
    { "666666______",                    CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP                },
    { "66666666_____",                    CF_CHG1 | CF_USE2 | CF_USE3                          },
    { "6666666666______________",                       0                                             },
    { "6666666666________",                    CF_STOP                                      },
    { "66666______________",                CF_USE1 | CF_USE2 | CF_JUMP                                       },
    { "666666666_____________",                   CF_CHG1 | CF_USE2                             },
};
#endif


 CASSERT(qnumber(Instructions) == MEMEDA_last);
