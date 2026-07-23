`timescale 1ns / 1ps

module ascon_top_module (
    input         clk,
    input         rst,
    input  [3:0]  key_in,
    input  [3:0]  nonce_in,
    input         ad_in,
    input         pt_in,
    input         encryption_start,
    output reg [3:0]  cipher_text_nibble,  // 4-bit cipher text output
    output reg [3:0]  tag_nibble,  
    output        encryption_ready
);

    reg [127:0] key;
    reg [127:0] nonce;
    reg [31:0]  ad;
    reg [31:0]  pt;
    reg [5:0]   count;

    wire [127:0] tag_full;
    wire [127:0] cipher_text_full;

    reg [6:0] tag_cnt;    
    reg [6:0] cipher_cnt;    

    reg        start_serializing;
    reg        encrypt_done_d;

    // Input serialization
    always @(posedge clk or posedge rst) begin
        if (rst) begin
            key    <= 128'b0;
            nonce  <= 128'b0;
            ad     <= 32'b0;
            pt     <= 32'b0;
            count  <= 6'b0;
        end else if (count < 32) begin
            key   <= {key[123:0], key_in};
            nonce <= {nonce[123:0], nonce_in};
            ad    <= {ad[30:0], ad_in};
            pt    <= {pt[30:0], pt_in};
            count <= count + 1;
        end
    end

    // ASCON core instantiation
    Ascon ascon1 (
        .clk(clk),
        .rst(rst),
        .keyxSI(key),
        .noncexSI(nonce),
        .associated_dataxSI(ad),
        .plain_textxSI(pt),
        .encryption_startxSI(encryption_start),
        .cipher_textxSO(cipher_text_full),
        .tagxSO(tag_full),
        .encryption_readyxSO(encryption_ready)
    );

    // Encryption done detection
    always @(posedge clk or posedge rst) begin
        if (rst) begin
            encrypt_done_d <= 1'b0;
            start_serializing <= 1'b0;
        end else begin
            encrypt_done_d <= encryption_ready;
            start_serializing <= (~encrypt_done_d & encryption_ready);
        end
    end

    // Tag serialization counter
    always @(posedge clk or posedge rst) begin
        if (rst) begin
            tag_cnt <= 7'b0;
        end else if (start_serializing) begin
            tag_cnt <= 7'b0;
        end else if (encryption_ready && (tag_cnt < 32)) begin
            tag_cnt <= tag_cnt + 1;
        end
    end

    // Cipher text serialization counter
    always @(posedge clk or posedge rst) begin
        if (rst) begin
            cipher_cnt <= 7'b0;
        end else if (start_serializing) begin
            cipher_cnt <= 7'b0;
        end else if (encryption_ready && (cipher_cnt < 32)) begin
            cipher_cnt <= cipher_cnt + 1;
        end
    end

    // Output registers for nibble outputs
    always @(posedge clk or posedge rst) begin
        if (rst) begin
            cipher_text_nibble <= 4'b0;
            tag_nibble <= 4'b0;
        end else if (encryption_ready) begin
            if (cipher_cnt < 8)
                cipher_text_nibble <= cipher_text_full[31 - cipher_cnt*4 -: 4];
            else
                cipher_text_nibble <= 4'b0;
               
            if (tag_cnt < 32)
                tag_nibble <= tag_full[127 - tag_cnt*4 -: 4];
            else
                tag_nibble <= 4'b0;
        end
    end

endmodule




module Ascon (
    input       clk,
    input       rst,
    input [127:0] keyxSI,
    input [127:0] noncexSI,
    input [31:0]  associated_dataxSI,
    input [31:0]  plain_textxSI,
    input       encryption_startxSI,
    output [31:0] cipher_textxSO,
    output [127:0] tagxSO,
    output      encryption_readyxSO 
);
    
    wire    [31:0]      cipher_text;
    wire    [127:0]     tag;
    wire                encryption_ready;

    assign encryption_readyxSO = encryption_ready;
    assign cipher_textxSO = cipher_text;
    assign tagxSO = tag;

    // Instantiating Encryption module
    Encryption enc(
        .clk(clk),
        .rst(rst),
        .key(keyxSI),
        .nonce(noncexSI),
        .associated_data(associated_dataxSI),
        .plain_text(plain_textxSI),
        .encryption_start(encryption_startxSI),
        .cipher_text(cipher_text),
        .tag(tag),           
        .encryption_ready(encryption_ready)
    );
endmodule

module Encryption (
    input           clk,
    input           rst,
    input  [127:0]  key,
    input  [127:0]  nonce,
    input  [31:0]   associated_data,
    input  [31:0]   plain_text,
    input           encryption_start,

    output [31:0]   cipher_text,            // Plain text converted to cipher text
    output [127:0]  tag,                    // Final Tag after Encryption 
    output          encryption_ready        // To indicate the end of Encryption
);

    // Constants
    parameter c = 320-128;  // c = 192

    parameter nz_ad =  ((32+1)%128 == 0)? 0 : 128-((32+1)%128);  // nz_ad = 95
    parameter L = 32+1+95;  // L = 128
    parameter s = 128/128;  // s = 1

    parameter nz_p =  ((32+1)%128 == 0)? 0 : 128-((32+1)%128);  // nz_p = 95
    parameter Y = 32+1+95;  // Y = 128
    parameter t = 128/128;  // t = 1

    // Buffer variables
    reg  [4:0]          rounds;
    reg  [127:0]        Tag;
    reg  [127:0]        Tag_d;
    reg                 encryption_ready_1;
    wire [61:0]         IV;
    reg  [319:0]        S;
    wire [127:0]        Sr;
    wire [191:0]        Sc;
    reg  [319:0]        P_in;
    wire [319:0]        P_out;
    wire                permutation_ready;
    reg                 permutation_start;
    wire [127:0]        A;
    wire [127:0]        P;
    reg  [127:0]        C;
    reg  [127:0]        C_d;
    reg  [1:0]          block_ctr;
    wire [4:0]          ctr;
    reg [2:0] state;
    
    assign IV = 128 << 24 | 128 << 16 | 12 << 8 | 6;
    assign {Sr,Sc} = S;
    assign encryption_ready = encryption_ready_1;
    assign A = {associated_data, 1'b1, {95{1'b0}}};
    assign P = {plain_text, 1'b1, {95{1'b0}}};
    assign tag = (encryption_ready_1)? Tag : 0;
    
    assign cipher_text = (32>0 && encryption_ready_1)? C[127 : 127-31] : 0;

    // FSM States
    parameter IDLE              = 'd0,
              INITIALIZE        = 'd1,
              ASSOCIATED_DATA   = 'd2,
              PTCT              = 'd3,
              FINALIZE          = 'd4, 
              DONE              = 'd5;  

    // ---------------------------------------------------------------------------------------
    //                               FSM Starts here
    // ---------------------------------------------------------------------------------------

    // Sequential Block
    always @(posedge clk) begin
        if(rst) begin
            rounds <= 0;
            Tag_d <= 0;
            P_in <= 0;
            C_d <=0;
            permutation_start <= 0;
            state <= IDLE;
            S <= 0;
            Tag <= 0;
            C <= 0;
            block_ctr <= 0;
        end
        else begin
            case(state)

                // IDLE Stage
                IDLE: begin
                    S <= {IV, 32'b0, key, nonce};
                    if(encryption_start)
                        state <= INITIALIZE;
                end

                // Initialization
                INITIALIZE: begin
                    if(permutation_ready) begin
                        if (32 != 0)
                            state <= ASSOCIATED_DATA;
                        else if (32 == 0 && 32 != 0)
                            state <= PTCT;
                        else
                            state <= FINALIZE;
                        S <= P_out ^ {192'b0, key};
                    end
                end

                //Processing Associated Data
                ASSOCIATED_DATA: begin
                    if(permutation_ready && block_ctr == 0) begin  // s-1 = 0
                        if (32 != 0)
                            state <= PTCT;
                        else
                            state <= FINALIZE;
                        S <= P_out^{{319{1'b0}}, 1'b1};
                    end
                    else if(permutation_ready && block_ctr != 1)  // s = 1
                        S <= P_out;
                    
                    if (permutation_ready && block_ctr == 0) 
                        block_ctr <= 0;
                    else if(permutation_ready && block_ctr != 1)
                        block_ctr <= block_ctr+1; 
                end

                // Processing Plain Text
                PTCT: begin
                    if(block_ctr == 0) begin  // t-1 = 0
                        state <= FINALIZE;
                        S <= {C_d[127:0], Sc};
                        C <= C + C_d;
                    end
                    else if(permutation_ready && block_ctr != 1) begin  // t = 1
                        S <= P_out;
                        C <= C + C_d;
                    end

                    if (permutation_ready && block_ctr == 0) 
                        block_ctr <= 0;
                    else if(permutation_ready && block_ctr != 1)
                        block_ctr <= block_ctr + 1; 
                end

                // Finalization
                FINALIZE: begin
                    if(permutation_ready) begin
                        S <= P_out;
                        state <= DONE;
                        Tag <= Tag_d;
                    end
                end

                // Done Stage
                DONE: begin
                    if(encryption_start)
                        state <= IDLE;
                end

                // Invalid state? go to idle
                default: 
                    state <= IDLE;
            endcase
        end
    end

    // Combinational Block
    always @(*) begin
        C_d = 0;
        Tag_d = 0;
        encryption_ready_1 = 0;
        case (state)
            IDLE: begin
                C_d = 0;
                Tag_d = 0;
                encryption_ready_1 = 0;
                permutation_start = 0;
                rounds = 12;
                P_in = S;
            end

            INITIALIZE: begin
                C_d = 0;
                Tag_d = 0;
                encryption_ready_1 = 0;
                rounds = 12;
                permutation_start = (permutation_ready)? 1'b0: 1'b1;
                P_in = S;
            end
            
            ASSOCIATED_DATA: begin
                C_d = 0;
                encryption_ready_1 = 0;
                rounds = 6;
                Tag_d = 0;
                if(permutation_ready && block_ctr == 0)
                    permutation_start = 0;
                else
                    permutation_start = 1;

                P_in = {Sr^A[127-(block_ctr*128)-:128], Sc};  // Since r=128
            end

            PTCT: begin
                encryption_ready_1 = 0;
                rounds = 6;
                Tag_d = 0;
                C_d[127-(block_ctr*128)-:128] = Sr ^ P[127-(block_ctr*128)-:128];
                P_in = {Sr ^ P[127-(block_ctr*128)-:128], Sc};
                if(block_ctr == 0)
                    permutation_start = 0;
                else
                    permutation_start = 1;
            end

            FINALIZE: begin
                C_d = 0;
                rounds = 12;
                P_in = S ^ {{128{1'b0}},key,{64{1'b0}}};
                permutation_start = (permutation_ready)? 1'b0: 1'b1;
                encryption_ready_1 = 1'b0;
                Tag_d = P_out ^ key;
            end

            DONE: begin
                Tag_d = 0;
                C_d = 0;
                rounds = 12;
                P_in = 0;
                permutation_start = 0;
                encryption_ready_1 = 1;
            end

            default: begin
                Tag_d = 0;
                rounds = 0;
                P_in = S;
                permutation_start = 0;
                encryption_ready_1 = 0;
                C_d = 0;
            end
        endcase
    end

    // Permutation Block
    Permutation p1(
        .clk(clk),
        .reset(rst),
        .S(P_in),
        .out(P_out),
        .done(permutation_ready),
        .ctr(ctr),
        .rounds(rounds),
        .start(permutation_start)
    );

    // Round Counter
    RoundCounter RC(
        clk,
        rst,
        permutation_start,
        permutation_ready,
        ctr
    );
endmodule




module Permutation (
    
    // Inputs
    input           clk,
    input           reset,
    input   [4:0]   ctr,
    input   [319:0] S,
    input   [4:0]   rounds,
    input           start,

    // Outputs
    output  [319:0] out,
    output          done            // Done signal when counter = no. of rounds
);

    // No. of rounds * (Add round constant -> Substitution Layer -> Linear Diffusion Layer)

    // Splitting the input state into 5 registers
    reg [63:0] x0_q, x1_q, x2_q, x3_q, x4_q;
    wire [63:0] x0_d, x1_d, x2_d, x3_d, x4_d;

    // Done register
    reg Done;

    // Updating the registers with clock cycles
    always @(posedge clk) begin
        if(reset)
            {x0_q, x1_q, x2_q, x3_q, x4_q, Done} <= 0;
        else begin
            if(start) begin
                if(ctr == 0)
                    {x0_q, x1_q, x2_q, x3_q, x4_q} <= S; 
                else begin
                    x0_q <= x0_d;
                    x1_q <= x1_d;
                    x2_q <= x2_d;
                    x3_q <= x3_d;
                    x4_q <= x4_d;
                end
            end
        end
        if(ctr == rounds)
            Done <= 1;
        else
            Done <= 0;
    end

    // Done signal
    assign done = Done;

    // Output
    assign out = {x0_q, x1_q, x2_q, x3_q, x4_q};

    // Adding Round Constant
    wire [63:0] rc_out;
    roundconstant u0(
        .x2(x2_q),
        .ctr(ctr),
        .out(rc_out),
        .rounds(rounds)
    );

    // Substituition Layer
    wire [63:0] sl0, sl1, sl2, sl3, sl4;
    sub_layer u1(
        .x0(x0_q), .x1(x1_q), .x2(rc_out), .x3(x3_q), .x4(x4_q),
        .sl0(sl0), .sl1(sl1), .sl2(sl2), .sl3(sl3), .sl4(sl4) 
    );

    // Linear Layer
    linear_layer u2(
        .X0(sl0), .X1(sl1), .X2(sl2), .X3(sl3), .X4(sl4),
        .Y0(x0_d), .Y1(x1_d), .Y2(x2_d), .Y3(x3_d), .Y4(x4_d) 
    );
    
endmodule

module linear_layer (
    input [63:0] X0, X1, X2, X3, X4,
    output [63:0] Y0, Y1, Y2, Y3, Y4
);
    wire [319:0] s;
    assign s = {X0, X1, X2, X3, X4};

    assign Y0 = {(s[319] ^ s[283] ^ s[274]), (s[318] ^ s[282] ^ s[273]), (s[317] ^ s[281] ^ s[272]), (s[316] ^ s[280] ^ s[271]), (s[315] ^ s[279] ^ s[270]), (s[314] ^ s[278] ^ s[269]), (s[313] ^ s[277] ^ s[268]), (s[312] ^ s[276] ^ s[267]),
                (s[311] ^ s[275] ^ s[266]), (s[310] ^ s[274] ^ s[265]), (s[309] ^ s[273] ^ s[264]), (s[308] ^ s[272] ^ s[263]), (s[307] ^ s[271] ^ s[262]), (s[306] ^ s[270] ^ s[261]), (s[305] ^ s[269] ^ s[260]), (s[304] ^ s[268] ^ s[259]),
                (s[303] ^ s[267] ^ s[258]), (s[302] ^ s[266] ^ s[257]), (s[301] ^ s[265] ^ s[256]), (s[319] ^ s[300] ^ s[264]), (s[318] ^ s[299] ^ s[263]), (s[317] ^ s[298] ^ s[262]), (s[316] ^ s[297] ^ s[261]), (s[315] ^ s[296] ^ s[260]),
                (s[314] ^ s[295] ^ s[259]), (s[313] ^ s[294] ^ s[258]), (s[312] ^ s[293] ^ s[257]), (s[311] ^ s[292] ^ s[256]), (s[319] ^ s[310] ^ s[291]), (s[318] ^ s[309] ^ s[290]), (s[317] ^ s[308] ^ s[289]), (s[316] ^ s[307] ^ s[288]),
                (s[315] ^ s[306] ^ s[287]), (s[314] ^ s[305] ^ s[286]), (s[313] ^ s[304] ^ s[285]), (s[312] ^ s[303] ^ s[284]), (s[311] ^ s[302] ^ s[283]), (s[310] ^ s[301] ^ s[282]), (s[309] ^ s[300] ^ s[281]), (s[308] ^ s[299] ^ s[280]),
                (s[307] ^ s[298] ^ s[279]), (s[306] ^ s[297] ^ s[278]), (s[305] ^ s[296] ^ s[277]), (s[304] ^ s[295] ^ s[276]), (s[303] ^ s[294] ^ s[275]), (s[302] ^ s[293] ^ s[274]), (s[301] ^ s[292] ^ s[273]), (s[300] ^ s[291] ^ s[272]),
                (s[299] ^ s[290] ^ s[271]), (s[298] ^ s[289] ^ s[270]), (s[297] ^ s[288] ^ s[269]), (s[296] ^ s[287] ^ s[268]), (s[295] ^ s[286] ^ s[267]), (s[294] ^ s[285] ^ s[266]), (s[293] ^ s[284] ^ s[265]), (s[292] ^ s[283] ^ s[264]),
                (s[291] ^ s[282] ^ s[263]), (s[290] ^ s[281] ^ s[262]), (s[289] ^ s[280] ^ s[261]), (s[288] ^ s[279] ^ s[260]), (s[287] ^ s[278] ^ s[259]), (s[286] ^ s[277] ^ s[258]), (s[285] ^ s[276] ^ s[257]), (s[284] ^ s[275] ^ s[256])};

    assign Y1 = {(s[255] ^ s[252] ^ s[230]), (s[254] ^ s[251] ^ s[229]), (s[253] ^ s[250] ^ s[228]), (s[252] ^ s[249] ^ s[227]), (s[251] ^ s[248] ^ s[226]), (s[250] ^ s[247] ^ s[225]), (s[249] ^ s[246] ^ s[224]), (s[248] ^ s[245] ^ s[223]),
                (s[247] ^ s[244] ^ s[222]), (s[246] ^ s[243] ^ s[221]), (s[245] ^ s[242] ^ s[220]), (s[244] ^ s[241] ^ s[219]), (s[243] ^ s[240] ^ s[218]), (s[242] ^ s[239] ^ s[217]), (s[241] ^ s[238] ^ s[216]), (s[240] ^ s[237] ^ s[215]),
                (s[239] ^ s[236] ^ s[214]), (s[238] ^ s[235] ^ s[213]), (s[237] ^ s[234] ^ s[212]), (s[236] ^ s[233] ^ s[211]), (s[235] ^ s[232] ^ s[210]), (s[234] ^ s[231] ^ s[209]), (s[233] ^ s[230] ^ s[208]), (s[232] ^ s[229] ^ s[207]),
                (s[231] ^ s[228] ^ s[206]), (s[230] ^ s[227] ^ s[205]), (s[229] ^ s[226] ^ s[204]), (s[228] ^ s[225] ^ s[203]), (s[227] ^ s[224] ^ s[202]), (s[226] ^ s[223] ^ s[201]), (s[225] ^ s[222] ^ s[200]), (s[224] ^ s[221] ^ s[199]),
                (s[223] ^ s[220] ^ s[198]), (s[222] ^ s[219] ^ s[197]), (s[221] ^ s[218] ^ s[196]), (s[220] ^ s[217] ^ s[195]), (s[219] ^ s[216] ^ s[194]), (s[218] ^ s[215] ^ s[193]), (s[217] ^ s[214] ^ s[192]), (s[255] ^ s[216] ^ s[213]),
                (s[254] ^ s[215] ^ s[212]), (s[253] ^ s[214] ^ s[211]), (s[252] ^ s[213] ^ s[210]), (s[251] ^ s[212] ^ s[209]), (s[250] ^ s[211] ^ s[208]), (s[249] ^ s[210] ^ s[207]), (s[248] ^ s[209] ^ s[206]), (s[247] ^ s[208] ^ s[205]),
                (s[246] ^ s[207] ^ s[204]), (s[245] ^ s[206] ^ s[203]), (s[244] ^ s[205] ^ s[202]), (s[243] ^ s[204] ^ s[201]), (s[242] ^ s[203] ^ s[200]), (s[241] ^ s[202] ^ s[199]), (s[240] ^ s[201] ^ s[198]), (s[239] ^ s[200] ^ s[197]),
                (s[238] ^ s[199] ^ s[196]), (s[237] ^ s[198] ^ s[195]), (s[236] ^ s[197] ^ s[194]), (s[235] ^ s[196] ^ s[193]), (s[234] ^ s[195] ^ s[192]), (s[255] ^ s[233] ^ s[194]), (s[254] ^ s[232] ^ s[193]), (s[253] ^ s[231] ^ s[192])};

    assign Y2 = {(s[191] ^ s[133] ^ s[128]), (s[191] ^ s[190] ^ s[132]), (s[190] ^ s[189] ^ s[131]), (s[189] ^ s[188] ^ s[130]), (s[188] ^ s[187] ^ s[129]), (s[187] ^ s[186] ^ s[128]), (s[191] ^ s[186] ^ s[185]), (s[190] ^ s[185] ^ s[184]),
                (s[189] ^ s[184] ^ s[183]), (s[188] ^ s[183] ^ s[182]), (s[187] ^ s[182] ^ s[181]), (s[186] ^ s[181] ^ s[180]), (s[185] ^ s[180] ^ s[179]), (s[184] ^ s[179] ^ s[178]), (s[183] ^ s[178] ^ s[177]), (s[182] ^ s[177] ^ s[176]),
                (s[181] ^ s[176] ^ s[175]), (s[180] ^ s[175] ^ s[174]), (s[179] ^ s[174] ^ s[173]), (s[178] ^ s[173] ^ s[172]), (s[177] ^ s[172] ^ s[171]), (s[176] ^ s[171] ^ s[170]), (s[175] ^ s[170] ^ s[169]), (s[174] ^ s[169] ^ s[168]),
                (s[173] ^ s[168] ^ s[167]), (s[172] ^ s[167] ^ s[166]), (s[171] ^ s[166] ^ s[165]), (s[170] ^ s[165] ^ s[164]), (s[169] ^ s[164] ^ s[163]), (s[168] ^ s[163] ^ s[162]), (s[167] ^ s[162] ^ s[161]), (s[166] ^ s[161] ^ s[160]),
                (s[165] ^ s[160] ^ s[159]), (s[164] ^ s[159] ^ s[158]), (s[163] ^ s[158] ^ s[157]), (s[162] ^ s[157] ^ s[156]), (s[161] ^ s[156] ^ s[155]), (s[160] ^ s[155] ^ s[154]), (s[159] ^ s[154] ^ s[153]), (s[158] ^ s[153] ^ s[152]),
                (s[157] ^ s[152] ^ s[151]), (s[156] ^ s[151] ^ s[150]), (s[155] ^ s[150] ^ s[149]), (s[154] ^ s[149] ^ s[148]), (s[153] ^ s[148] ^ s[147]), (s[152] ^ s[147] ^ s[146]), (s[151] ^ s[146] ^ s[145]), (s[150] ^ s[145] ^ s[144]),
                (s[149] ^ s[144] ^ s[143]), (s[148] ^ s[143] ^ s[142]), (s[147] ^ s[142] ^ s[141]), (s[146] ^ s[141] ^ s[140]), (s[145] ^ s[140] ^ s[139]), (s[144] ^ s[139] ^ s[138]), (s[143] ^ s[138] ^ s[137]), (s[142] ^ s[137] ^ s[136]),
                (s[141] ^ s[136] ^ s[135]), (s[140] ^ s[135] ^ s[134]), (s[139] ^ s[134] ^ s[133]), (s[138] ^ s[133] ^ s[132]), (s[137] ^ s[132] ^ s[131]), (s[136] ^ s[131] ^ s[130]), (s[135] ^ s[130] ^ s[129]), (s[134] ^ s[129] ^ s[128])};

    assign Y3 = {(s[127] ^ s[80] ^ s[73]), (s[126] ^ s[79] ^ s[72]), (s[125] ^ s[78] ^ s[71]), (s[124] ^ s[77] ^ s[70]), (s[123] ^ s[76] ^ s[69]), (s[122] ^ s[75] ^ s[68]), (s[121] ^ s[74] ^ s[67]), (s[120] ^ s[73] ^ s[66]),
                (s[119] ^ s[72] ^ s[65]), (s[118] ^ s[71] ^ s[64]), (s[127] ^ s[117] ^ s[70]), (s[126] ^ s[116] ^ s[69]), (s[125] ^ s[115] ^ s[68]), (s[124] ^ s[114] ^ s[67]), (s[123] ^ s[113] ^ s[66]), (s[122] ^ s[112] ^ s[65]),
                (s[121] ^ s[111] ^ s[64]), (s[127] ^ s[120] ^ s[110]), (s[126] ^ s[119] ^ s[109]), (s[125] ^ s[118] ^ s[108]), (s[124] ^ s[117] ^ s[107]), (s[123] ^ s[116] ^ s[106]), (s[122] ^ s[115] ^ s[105]), (s[121] ^ s[114] ^ s[104]),
                (s[120] ^ s[113] ^ s[103]), (s[119] ^ s[112] ^ s[102]), (s[118] ^ s[111] ^ s[101]), (s[117] ^ s[110] ^ s[100]), (s[116] ^ s[109] ^ s[99]), (s[115] ^ s[108] ^ s[98]), (s[114] ^ s[107] ^ s[97]), (s[113] ^ s[106] ^ s[96]),
                (s[112] ^ s[105] ^ s[95]), (s[111] ^ s[104] ^ s[94]), (s[110] ^ s[103] ^ s[93]), (s[109] ^ s[102] ^ s[92]), (s[108] ^ s[101] ^ s[91]), (s[107] ^ s[100] ^ s[90]), (s[106] ^ s[99] ^ s[89]), (s[105] ^ s[98] ^ s[88]),
                (s[104] ^ s[97] ^ s[87]), (s[103] ^ s[96] ^ s[86]), (s[102] ^ s[95] ^ s[85]), (s[101] ^ s[94] ^ s[84]), (s[100] ^ s[93] ^ s[83]), (s[99] ^ s[92] ^ s[82]), (s[98] ^ s[91] ^ s[81]), (s[97] ^ s[90] ^ s[80]),
                (s[96] ^ s[89] ^ s[79]), (s[95] ^ s[88] ^ s[78]), (s[94] ^ s[87] ^ s[77]), (s[93] ^ s[86] ^ s[76]), (s[92] ^ s[85] ^ s[75]), (s[91] ^ s[84] ^ s[74]), (s[90] ^ s[83] ^ s[73]), (s[89] ^ s[82] ^ s[72]),
                (s[88] ^ s[81] ^ s[71]), (s[87] ^ s[80] ^ s[70]), (s[86] ^ s[79] ^ s[69]), (s[85] ^ s[78] ^ s[68]), (s[84] ^ s[77] ^ s[67]), (s[83] ^ s[76] ^ s[66]), (s[82] ^ s[75] ^ s[65]), (s[81] ^ s[74] ^ s[64])};

    assign Y4 = {(s[63] ^ s[40] ^ s[6]), (s[62] ^ s[39] ^ s[5]), (s[61] ^ s[38] ^ s[4]), (s[60] ^ s[37] ^ s[3]), (s[59] ^ s[36] ^ s[2]), (s[58] ^ s[35] ^ s[1]), (s[57] ^ s[34] ^ s[0]), (s[63] ^ s[56] ^ s[33]),
                (s[62] ^ s[55] ^ s[32]), (s[61] ^ s[54] ^ s[31]), (s[60] ^ s[53] ^ s[30]), (s[59] ^ s[52] ^ s[29]), (s[58] ^ s[51] ^ s[28]), (s[57] ^ s[50] ^ s[27]), (s[56] ^ s[49] ^ s[26]), (s[55] ^ s[48] ^ s[25]),
                (s[54] ^ s[47] ^ s[24]), (s[53] ^ s[46] ^ s[23]), (s[52] ^ s[45] ^ s[22]), (s[51] ^ s[44] ^ s[21]), (s[50] ^ s[43] ^ s[20]), (s[49] ^ s[42] ^ s[19]), (s[48] ^ s[41] ^ s[18]), (s[47] ^ s[40] ^ s[17]),
                (s[46] ^ s[39] ^ s[16]), (s[45] ^ s[38] ^ s[15]), (s[44] ^ s[37] ^ s[14]), (s[43] ^ s[36] ^ s[13]), (s[42] ^ s[35] ^ s[12]), (s[41] ^ s[34] ^ s[11]), (s[40] ^ s[33] ^ s[10]), (s[39] ^ s[32] ^ s[9]),
                (s[38] ^ s[31] ^ s[8]), (s[37] ^ s[30] ^ s[7]), (s[36] ^ s[29] ^ s[6]), (s[35] ^ s[28] ^ s[5]), (s[34] ^ s[27] ^ s[4]), (s[33] ^ s[26] ^ s[3]), (s[32] ^ s[25] ^ s[2]), (s[31] ^ s[24] ^ s[1]),
                (s[30] ^ s[23] ^ s[0]), (s[63] ^ s[29] ^ s[22]), (s[62] ^ s[28] ^ s[21]), (s[61] ^ s[27] ^ s[20]), (s[60] ^ s[26] ^ s[19]), (s[59] ^ s[25] ^ s[18]), (s[58] ^ s[24] ^ s[17]), (s[57] ^ s[23] ^ s[16]),
                (s[56] ^ s[22] ^ s[15]), (s[55] ^ s[21] ^ s[14]), (s[54] ^ s[20] ^ s[13]), (s[53] ^ s[19] ^ s[12]), (s[52] ^ s[18] ^ s[11]), (s[51] ^ s[17] ^ s[10]), (s[50] ^ s[16] ^ s[9]), (s[49] ^ s[15] ^ s[8]),
                (s[48] ^ s[14] ^ s[7]), (s[47] ^ s[13] ^ s[6]), (s[46] ^ s[12] ^ s[5]), (s[45] ^ s[11] ^ s[4]), (s[44] ^ s[10] ^ s[3]), (s[43] ^ s[9] ^ s[2]), (s[42] ^ s[8] ^ s[1]), (s[41] ^ s[7] ^ s[0])};

endmodule

module roundconstant (
    input   [63:0]  x2,
    input   [4:0]   ctr,
    input   [4:0]   rounds,
    output  [63:0]  out 
);

    reg [63:0] out_buf;
    assign out = out_buf;

    always @(*) begin
        if(rounds == 6)
            out_buf = x2 ^ (8'h96 - (ctr-1) * 15);
        else if(rounds == 8)
            out_buf = x2 ^ (8'hb4 - (ctr-1) * 15);
        else 
            out_buf = x2 ^ (8'hf0 - (ctr-1) * 15);
    end

endmodule

module sub_layer (
    input [63:0] x0, x1, x2, x3, x4,
    output [63:0] sl0, sl1, sl2, sl3, sl4
);
    // Since TYPE = 1, we only implement the optimized SBOX version
    assign sl0 = (x4 & x1) ^ x3 ^ (x2 & x1) ^ x2 ^ (x1 & x0) ^ x1 ^ x0;      
    assign sl1 = x4 ^ (x3 & x2) ^ (x3 & x1) ^ x3 ^ x2 ^ x1 ^ x0 ^ (x2 & x1);
    assign sl2 = (x4 & x3) ^ x4 ^ x2 ^ x1 ^ 64'hffffffffffffffff;               
    assign sl3 = (x4 & x0) ^ (x3 & x0) ^ x4 ^ x3 ^ x2 ^ x1 ^ x0;                 
    assign sl4 = (x4 & x1) ^ x4 ^ x3 ^ (x1 & x0) ^ x1;                          
endmodule

module RoundCounter (
    input        clk,
    input        rst,
    input        permutation_start,
    input        permutation_ready,
    output [4:0] counter
);
    reg [4:0] ctr;
    always @(posedge clk) begin
        if(rst)
            ctr <= 0;
        else begin
            if(permutation_ready || ~permutation_start)
                ctr <= 0;
            else if(permutation_start)
                ctr <= ctr + 1;
        end
    end
    assign counter = ctr;
endmodule
