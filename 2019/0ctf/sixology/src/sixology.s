db. 0xb80=3 6 115 250 41 76 8 248 85 10 41 244 205 2 122 241 196 155 229 241 241 187 26 244 24 71 248 253 209 63 8 240 43 237 186 241 199 234 42 250 3 204 82 246 141 176 120 241 181 142 25 241 149 37 103 240 144 54 117 241 37 120 230 242 122 25 176 242 85 135 76 248 143 166 114 251 7 211 86 246 128 94 0 252 42 55 80 243 62 132 123 242 155 46 174 241 147 183 236 242 61 35 207 242 127 72 171 253 238 137 121 251 167 232 133 245 52 82 21 251 53 88 97 248 225 46 152 254 62 46 196 246 124 55 110 249 224 167 2 241 232 145 35 254 165 0 117 250 145 243 64 246 15 103 225 241 95 35 208 249 125 45 193 247 44 118 99 248 138 91 237 251 199 222 184 253 110 19 134 241 243 172 223 242 200 26 93 254 13 119 94 242 221 214 86 251 35 177 62 243 218 250 183 244 137 40 36 246 143 4 159 245 41 250 134 252 105 71 208 252 99 128 75 241 34 242 166 250 144 57 210 240 140 106 132 246 52 130 205 243 225 13 68 250 231 78 222 245 202 43 12 244 88 3 89 240 203 104 169 244 255 45 90 246 
db. 0xca0=119 35 250 2 62 195 209 6 68 45 178 1 69 243 113 1 71 255 131 1 9 150 135 2 215 185 110 3 187 17 8 0 176 45 193 0 32 219 183 1 201 46 79 5 59 137 26 1 68 219 72 0 208 97 31 0 114 115 139 0 239 23 167 1 42 105 103 1 155 206 90 5 35 9 125 4 142 79 158 0 98 97 3 2 25 172 249 2 247 219 224 1 155 45 133 1 186 78 109 2 134 52 14 2 2 247 176 11 246 13 228 3 75 40 36 0 142 65 71 4 166 17 187 7 188 48 163 6 90 129 197 0 13 170 239 2 112 225 193 0 81 241 40 6 207 41 198 1 130 76 224 2 93 68 21 0 167 226 189 1 112 186 106 4 65 19 26 1 130 57 115 11 96 122 232 6 93 113 247 0 130 54 79 2 49 193 129 1 246 167 58 2 81 75 164 0 79 27 158 2 161 134 38 0 71 96 149 1 172 180 20 2 240 59 15 0 179 1 151 0 0 62 28 0 175 74 107 0 154 58 119 0 209 180 188 2 248 10 105 1 216 155 19 4 48 70 224 0 0 83 126 1 153 55 71 0 5 177 1 4 17 166 115 3 
li r5, 0
li r4, 4
li r7, 66
li r8, 2944
li r9, 3232
li r16, 2184
loop Mainloop, r7
Mainloop:
    add r3, r8, r5
    load r0, dword ptr [r3]
    add r3, r9, r5
    load r1, dword ptr [r3]
    call Count
    add r3, r16, r5
    store r0, dword ptr[r3]
    add r5, r5, r4
endloop Mainloop
    
li r7, 66
li r13, 1
li r16, 3
li r17, 2640
li r18, 2560
li r19, 2184
li r20, 1638
li r21, 0x100
    
nor r0, r10, r10
nor r1, r10, r0
nor r2, r10, r0
nor r3, r1, r2
nor r10, r3, r3
    
loop PRINT, r7
PRINT:
    add r11, r18, r10
    load r29, byte ptr [r11]
    
nor r0, r29, r29
nor r1, r16, r16
nor r5, r0, r1
    
    switch r5, DEFAULT, JTABLE, [DEC0, DEC1, DEC2]

DEC0:
    
add r11, r10, r10
add r11, r11, r11
    
    add r11, r19, r11
    load r22, dword ptr [r11]
    div r25, r26, r22, r21
    
nor r0, r26, r26
nor r1, r29, r29
nor r0, r0, r1
nor r1, r26, r29
nor r28, r0, r1
    
    add r11, r17, r10
    load r30, byte ptr [r11]
    add r28, r28, r30
    add r11, r20, r10
    store r28, byte ptr [r11]
    jmp PRINT_END

DEC1:
    
add r11, r10, r10
add r11, r11, r10
add r11, r11, r10
    
    add r11, r19, r11
    load r22, dword ptr [r11]
    div r25, r26, r22, r21
    
nor r0, r26, r29
nor r1, r26, r0
nor r2, r29, r0
nor r3, r1, r2
nor r28, r3, r3
    
    add r11, r17, r10
    load r30, byte ptr [r11]
    add r28, r28, r30
    add r11, r20, r10
    store r28, byte ptr [r11]
    jmp PRINT_END

DEC2:
    
add r11, r10, r10
add r12, r10, r10
add r11, r11, r12
    
    add r11, r19, r11
    load r22, dword ptr [r11]
    div r25, r26, r22, r21
    
nor r0, r26, r26
nor r1, r29, r29
nor r0, r0, r1
nor r1, r26, r29
nor r28, r0, r1
    
    add r11, r17, r10
    load r30, byte ptr [r11]
    sub r28, r28, r30
    add r11, r20, r10
    store r28, byte ptr [r11]
    jmp PRINT_END

DEFAULT:
    
add r11, r10, r10
add r11, r11, r11
    
    add r11, r19, r11
    load r22, dword ptr [r11]
    div r25, r26, r22, r21
    
nor r0, r26, r29
nor r1, r26, r0
nor r2, r29, r0
nor r3, r1, r2
nor r28, r3, r3
    
    add r11, r17, r10
    load r30, byte ptr [r11]
    sub r28, r28, r30
    add r11, r20, r10
    store r28, byte ptr [r11]
    jmp PRINT_END

PRINT_END:
add r10, r10, r13
endloop PRINT
ret
    
db. 2560=78 228 76 122 254 201 183 78 254 241 30 59 190 65 179 90 214 187 82 55 98 238 103 50 246 3 85 11 86 180 18 89 19 166 142 86 4 116 106 18 229 195 63 151 244 130 71 166 203 70 151 189 101 19 7 240 46 222 54 76 68 38 2 251 163 66
db. 2640=151 21 67 152 17 47 62 6 109 18 69 51 88 15 106 142 132 35 62 173 77 121 33 29 123 64 28 200 143 17 106 24 55 151 46 130 45 46 40 124 60 139 12 104 20 125 73 53 55 99 84 19 115 204 156 84 124 31 25 89 64 48 19 32 206 100
    
jmp END

Count:
    allocframe 0x100
    mov r10, r0
    mov r11, r1
    li r25, 0x2019
    li r23, 0
    li r24, 0
    li r19, 4
    li r18, 1
    loop Init, r0
    Init:
        add r6, r23, r1
        div r14, r15, r6, r0
        add r15, r15, r18
        add r17, r25, r24
        store r15, dword ptr [r17]
        add r23, r23, r18
        add r24, r24, r19
    endloop Init

    li r15, 1
    li r23, 1
    sub r2, r0, r15
    loop First, r2
    First:
        li r24, 0
        li r22, 0
        sub r3, r0, r23
        loop Second, r3
        Second:
            add r26, r25, r22
            load r12, dword ptr [r26]
            add r27, r26, r19
            load r13, dword ptr [r27]
            lexcmp.lt p0, r12, r13
            jmpcond p0, NOEXCHG
            exchange r12, r13
            store r12, dword ptr [r26]
            store r13, dword ptr [r27]
            NOEXCHG:
            add r24, r24, r15
            add r22, r22, r19
        endloop Second
        add r23, r23, r15
    endloop First

    li r24, 0
    cmp.eq p1, r1, r15
    jmpcond p1, FINISH
    sub r2, r1, r15
    loop Result, r2
    Result:
        add r24, r24, r19
    endloop Result

    FINISH:
    add r26, r25, r24
    load r0, dword ptr [r26]
    deallocframe
    ret
    
END:
    mov r0, r20
    