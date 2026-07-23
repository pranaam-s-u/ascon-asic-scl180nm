# ascon-asic-scl180nm
RTL-to-GDSII implementation, tapeout, and fabrication of an ASCON authenticated-encryption ASIC in SCL 180 nm CMOS.
# ASCON Authenticated Encryption ASIC — SCL 180 nm

## Overview

This project presents the **RTL-to-GDSII implementation and silicon tapeout of an ASCON authenticated-encryption ASIC** fabricated using **SCL 180 nm CMOS technology**.

The work involved debugging and modifying an existing Verilog RTL implementation to resolve **X-propagation observed during Gate-Level Simulation (GLS)**, followed by the complete ASIC implementation flow from RTL verification through physical design and signoff.

The design successfully achieved **DRC, LVS, and Antenna Rule Check (ARC) clean signoff**, was submitted for fabrication, and the **fabricated silicon has been received from SCL**. Post-silicon functional testing is planned.

---

## Design Specifications

| Parameter | Specification |
|---|---|
| Technology | SCL 180 nm CMOS |
| Die Size | 1900 × 1900 µm² |
| Operating Frequency | 1 MHz |
| Key | 128-bit |
| Nonce | 128-bit |
| Authentication Tag | 128-bit |
| Plaintext Interface | 32-bit |
| Ciphertext Interface | 32-bit |
| Associated Data Interface | 32-bit |
| Physical Signoff | DRC, LVS & ARC Clean |
| Fabrication Status | Fabricated Silicon Received |
| Post-Silicon Testing | Pending |

---

## ASIC Design Flow

The design was implemented using a complete **RTL-to-GDSII ASIC flow**:

1. RTL Verification
2. RTL Debugging and Modification
3. Logic Synthesis
4. Gate-Level Simulation (GLS)
5. Floorplanning
6. I/O and Power Planning
7. Placement
8. Clock Tree Synthesis (CTS)
9. Routing
10. Static Timing Analysis (STA) and Timing Closure
11. Physical Verification
12. DRC / LVS / Antenna Rule Check
13. GDSII Generation
14. Tapeout and Fabrication

---

## RTL Debugging and Gate-Level Verification

The initial Verilog RTL was based on an existing ASCON hardware implementation.

During ASIC implementation, **unknown (`X`) values were observed at the outputs during Gate-Level Simulation (GLS)**.

The RTL and verification flow were analyzed and modified to resolve the GLS issues and obtain correct functional behavior after synthesis.

This step ensured that the design was suitable for subsequent physical implementation.

---

## Physical Design

The synthesized netlist was taken through the complete physical-design flow using **Cadence Innovus**.

The implementation included:

- Floorplanning
- I/O and pad integration
- Power planning
- Standard-cell placement
- Clock Tree Synthesis (CTS)
- Routing
- Static Timing Analysis
- Timing closure
- Physical verification
- GDSII generation

The final ASIC occupies a die area of approximately:

**1900 µm × 1900 µm**

and operates at a target clock frequency of:

**1 MHz**

---

## Physical Verification and Signoff

The final layout was verified for fabrication readiness.

The design achieved:

- **DRC Clean**
- **LVS Clean**
- **Antenna Rule Check (ARC) Clean**

Physical verification and signoff were performed using **Calibre**.

---

## EDA Tools Used

| Design Stage | Tool |
|---|---|
| RTL / Gate-Level Simulation | Cadence SimVision |
| Logic Synthesis | Cadence Genus |
| Physical Design | Cadence Innovus |
| Custom/Layout Analysis | Cadence Virtuoso |
| Physical Verification | Calibre |

---

## Tapeout and Fabrication

The completed ASIC design was submitted for fabrication using the **SCL 180 nm CMOS process**.

The fabricated chip has been successfully received from **Semiconductor Laboratory (SCL)**.

The next phase of the project involves **post-silicon functional validation and hardware testing** of the fabricated ASIC.

---

## Project Highlights

- Complete **RTL-to-GDSII ASIC implementation**
- Debugged Verilog RTL to resolve **X-propagation during GLS**
- Implemented ASCON authenticated encryption in **SCL 180 nm CMOS**
- Completed synthesis, floorplanning, placement, CTS, routing, and STA
- Achieved **DRC / LVS / ARC clean physical signoff**
- Successfully completed **ASIC tapeout and fabrication**
- Received fabricated silicon for post-silicon validation

---

## Repository Structure

```text
.
ascon-asic-scl180nm/
│
├── README.md
│
├── rtl/
│   └── [ASCON Verilog source files you are allowed to share]
│
├── verification/
│   └── testbench/
│   
│
└── images/
    ├── rtl_simulation/
    ├── floorplan_and_sroute/
    ├── placement/
    ├── cts/
    ├── routing/
    ├── final_layout/
    └── fabricated_chip/
