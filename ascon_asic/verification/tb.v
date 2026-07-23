`timescale 1ns / 1ps

module ascon_top_module_tb;

    //=========================================================
    // Inputs
    //=========================================================
    reg         clk;
    reg         rst;
    reg  [3:0]  key_in;
    reg  [3:0]  nonce_in;
    reg         ad_in;
    reg         pt_in;
    reg         encryption_start;

    //=========================================================
    // Outputs
    //=========================================================
    wire [3:0]  cipher_text_nibble;
    wire [3:0]  tag_nibble;
    wire        encryption_ready;

    //=========================================================
    // Collected Outputs
    //=========================================================
    reg [31:0]  cipher_text_collected;
    reg [127:0] tag_collected;

    //=========================================================
    // DUT
    //=========================================================
    ascon_top_module dut (
        .clk                (clk),
        .rst                (rst),
        .key_in             (key_in),
        .nonce_in           (nonce_in),
        .ad_in              (ad_in),
        .pt_in              (pt_in),
        .encryption_start   (encryption_start),
        .cipher_text_nibble (cipher_text_nibble),
        .tag_nibble         (tag_nibble),
        .encryption_ready   (encryption_ready)
    );

    //=========================================================
    // CLOCK
    //
    // SDC:
    // create_clock -period 1000
    //
    // Period    = 1000 ns
    // Frequency = 1 MHz
    //=========================================================

    initial begin
        clk = 1'b0;
    end

    always #500 clk = ~clk;


    //=========================================================
    // TEST VECTORS
    //=========================================================

    reg [127:0] key_test =
        128'h000102030405060708090A0B0C0D0E0F;

    reg [127:0] nonce_test =
        128'h101112131415161718191A1B1C1D1E1F;

    reg [31:0] ad_test =
        32'h20212223;

    reg [31:0] pt_test =
        32'h24252627;

    integer i;


    //=========================================================
    // MAIN TEST
    //=========================================================

    initial begin

        //=====================================================
        // INITIALIZE
        //=====================================================

        rst              = 1'b1;

        key_in           = 4'b0000;
        nonce_in         = 4'b0000;

        ad_in            = 1'b0;
        pt_in            = 1'b0;

        encryption_start = 1'b0;

        cipher_text_collected = 32'b0;
        tag_collected         = 128'b0;


        //=====================================================
        // RESET
        //
        // Hold reset for several full 1 MHz clock cycles
        //=====================================================

        repeat (5)
            @(posedge clk);

        // Release reset away from active rising edge

        @(negedge clk);

        rst = 1'b0;

        $display("");
        $display("============================================");
        $display("RESET RELEASED at %0t", $time);
        $display("============================================");


        //=====================================================
        // SERIALIZE INPUTS
        //
        // Drive inputs on NEGEDGE.
        //
        // DUT captures them on following POSEDGE.
        //
        // 32 cycles:
        //
        // KEY   = 4 bits/cycle  x 32 = 128 bits
        // NONCE = 4 bits/cycle  x 32 = 128 bits
        // AD    = 1 bit/cycle   x 32 = 32 bits
        // PT    = 1 bit/cycle   x 32 = 32 bits
        //=====================================================

        $display("");
        $display("Sending serialized inputs...");

        for (i = 0; i < 32; i = i + 1) begin

            //-------------------------------------------------
            // We are already at a negedge for i=0.
            // For later iterations wait for next negedge.
            //-------------------------------------------------

            if (i != 0)
                @(negedge clk);


            //-------------------------------------------------
            // Drive data
            //-------------------------------------------------

            key_in =
                key_test[127 - i*4 -: 4];

            nonce_in =
                nonce_test[127 - i*4 -: 4];

            ad_in =
                ad_test[31 - i];

            pt_in =
                pt_test[31 - i];


            $display(
                "INPUT[%02d] KEY=%h NONCE=%h AD=%b PT=%b",
                i,
                key_in,
                nonce_in,
                ad_in,
                pt_in
            );

        end


        //=====================================================
        // IMPORTANT
        //
        // Last input was placed at negedge.
        // Allow DUT to capture it at next posedge.
        //=====================================================

        @(posedge clk);

        // Then move to negedge before changing inputs.

        @(negedge clk);


        //=====================================================
        // CLEAR INPUT PINS
        //=====================================================

        key_in   = 4'b0000;
        nonce_in = 4'b0000;

        ad_in = 1'b0;
        pt_in = 1'b0;


        //=====================================================
        // START ENCRYPTION
        //
        // Assert before posedge.
        // Keep HIGH across one complete posedge.
        //=====================================================

        encryption_start = 1'b1;

        $display("");
        $display(
            "ENCRYPTION START asserted at %0t",
            $time
        );


        //-----------------------------------------------------
        // DUT samples encryption_start here
        //-----------------------------------------------------

        @(posedge clk);


        //-----------------------------------------------------
        // Deassert safely at following negedge
        //-----------------------------------------------------

        @(negedge clk);

        encryption_start = 1'b0;


        $display(
            "ENCRYPTION START deasserted at %0t",
            $time
        );


        //=====================================================
        // WAIT FOR ENCRYPTION
        //=====================================================

        wait (encryption_ready === 1'b1);


        $display("");
        $display("============================================");

        $display(
            "ENCRYPTION READY at %0t",
            $time
        );

        $display("============================================");


        //=====================================================
        // EXISTING SILICON SERIALIZER QUIRK
        //
        // Your RTL causes the serializer counter to start,
        // then restart because of start_serializing.
        //
        // We discard the preliminary sampled outputs.
        //
        // Apply same handling to CT and TAG.
        //=====================================================

        @(negedge clk);

        $display(
            "DISCARD[0] CT=%h TAG=%h",
            cipher_text_nibble,
            tag_nibble
        );


        @(negedge clk);

        $display(
            "DISCARD[1] CT=%h TAG=%h",
            cipher_text_nibble,
            tag_nibble
        );


        @(negedge clk);

        $display(
            "DISCARD[2] CT=%h TAG=%h",
            cipher_text_nibble,
            tag_nibble
        );


        //=====================================================
        // CLEAR OUTPUT COLLECTION REGISTERS
        //=====================================================

        cipher_text_collected = 32'b0;

        tag_collected = 128'b0;


        //=====================================================
        // CAPTURE OUTPUTS
        //
        // Ciphertext:
        //
        //      32 bits
        //      4 bits/cycle
        //      = 8 nibbles
        //
        // Tag:
        //
        //      128 bits
        //      4 bits/cycle
        //      = 32 nibbles
        //
        // Both are read simultaneously.
        //=====================================================

        $display("");
        $display("Capturing outputs...");


        for (i = 0; i < 32; i = i + 1) begin

            @(negedge clk);


            //-------------------------------------------------
            // Collect first 8 CT nibbles
            //-------------------------------------------------

            if (i < 8) begin

                cipher_text_collected = {

                    cipher_text_collected[27:0],

                    cipher_text_nibble

                };

            end


            //-------------------------------------------------
            // Collect all 32 TAG nibbles
            //-------------------------------------------------

            tag_collected = {

                tag_collected[123:0],

                tag_nibble

            };


            //-------------------------------------------------
            // Debug
            //-------------------------------------------------

            if (i < 8) begin

                $display(
                    "OUTPUT[%02d] CT=%h TAG=%h",
                    i,
                    cipher_text_nibble,
                    tag_nibble
                );

            end

            else begin

                $display(
                    "OUTPUT[%02d] CT=- TAG=%h",
                    i,
                    tag_nibble
                );

            end

        end


        //=====================================================
        // FINAL RESULT
        //=====================================================

        $display("");
        $display("============================================");
        $display("                  INPUTS");
        $display("============================================");

        $display(
            "KEY        = %032h",
            key_test
        );

        $display(
            "NONCE      = %032h",
            nonce_test
        );

        $display(
            "AD         = %08h",
            ad_test
        );

        $display(
            "PLAINTEXT  = %08h",
            pt_test
        );


        $display("");
        $display("============================================");
        $display("                  OUTPUTS");
        $display("============================================");

        $display(
            "CIPHERTEXT = %08h",
            cipher_text_collected
        );

        $display(
            "TAG        = %032h",
            tag_collected
        );

        $display("============================================");


        //=====================================================
        // END SIMULATION
        //=====================================================

        repeat (5)
            @(posedge clk);

        $finish;

    end


    //=========================================================
    // TIMEOUT WATCHDOG
    //
    // Prevent simulation from running forever if READY
    // never asserts.
    //
    // 10 ms is much longer than expected.
    //=========================================================

    initial begin

        #10000000;

        $display("");
        $display("ERROR: SIMULATION TIMEOUT");

        $finish;

    end

endmodule
