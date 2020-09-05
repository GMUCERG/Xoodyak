--------------------------------------------------------------------------------
--! @file       xoodoo_round.vhd
--! @brief      
--! @author     Richard Haeussler
--! @copyright  Copyright (c) 2020 Cryptographic Engineering Research Group
--!             ECE Department, George Mason University Fairfax, VA, U.S.A.
--!             All rights Reserved.
--! @license    This project is released under the GNU Public License.
--!             The license and distribution terms for this file may be
--!             found in the file LICENSE in this distribution or at
--!             http://www.gnu.org/licenses/gpl-3.0.txt
--! @note       This is publicly available encryption source code that falls
--!             under the License Exception TSU (Technology and software-
--!             unrestricted)
--------------------------------------------------------------------------------
library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use ieee.numeric_std.all;
use ieee.math_real.all;
library work;
use work.xoodyak_constants.all;


entity xoodoo_round is
	generic( ADDRESS_LEN: integer := ADDRESS_LEN;
	ADDRESS_ENTRIES: integer := ADDRESS_ENTRIES;
	ADDRESS_ENTRIES_BITs: integer := ADDRESS_ENTRIES_BITs
	);
	port(
	    -- Access to that state ram
		RAMA: in std_logic_vector(ADDRESS_LEN-1 downto 0);
		RAMB: in std_logic_vector(ADDRESS_LEN-1 downto 0);
		perm_output: out std_logic_vector(ADDRESS_LEN-1 downto 0);
		ADDRA: out std_logic_vector(ADDRESS_ENTRIES_BITs-1 downto 0);
		ADDRB: out std_logic_vector(ADDRESS_ENTRIES_BITs-1 downto 0);
		-- Counter for current round number 
		RNDCTR: in std_logic_vector(NUM_ROUNDS_BITS - 1  downto 0);
		-- Counter for current instruction number
		ins_counter: in std_logic_vector(NUM_INS-1 downto 0)
		);
end xoodoo_round;

architecture Behavioral of xoodoo_round is
	constant INS_SIZE : integer := 4 + STATE_RAM_ADDRESS + STATE_RAM_ADDRESS;
	constant NUM_OPS_BITS : integer := 4;
    signal instruction: std_logic_vector(INS_SIZE-1 downto 0);
    signal operation: std_logic_vector(NUM_OPS_BITS-1 downto 0);
	signal addout: std_logic_vector(ADDRESS_LEN-1 downto 0);
	signal eshift: std_logic_vector(ADDRESS_LEN-1 downto 0);
	signal andout: std_logic_vector(ADDRESS_LEN-1 downto 0);
	signal notout: std_logic_vector(ADDRESS_LEN-1 downto 0);
	signal storeout: std_logic_vector(ADDRESS_LEN-1 downto 0);
	signal shift0: std_logic_vector(ADDRESS_LEN-1 downto 0);
	signal shift11: std_logic_vector(ADDRESS_LEN-1 downto 0);
	signal shift1: std_logic_vector(ADDRESS_LEN-1 downto 0);
	signal shift8: std_logic_vector(ADDRESS_LEN-1 downto 0);
	signal add_rnd_const: std_logic_vector(ADDRESS_LEN-1 downto 0);
	constant STORE_ins : std_logic_vector(NUM_OPS_BITS-1 downto 0) := x"0";
	constant ADD_INS :   std_logic_vector(NUM_OPS_BITS-1 downto 0) := x"1";
	constant ESHIFT_INS: std_logic_vector(NUM_OPS_BITS-1 downto 0) := x"2";
	constant SHIFT0_INS: std_logic_vector(NUM_OPS_BITS-1 downto 0) := x"3";
	constant SHIFT11_INS : std_logic_vector(NUM_OPS_BITS-1 downto 0) := x"4";
	constant ADD_RND_CONST_INS: std_logic_vector(NUM_OPS_BITS-1 downto 0) := x"5";
	constant NOT_INS :   std_logic_vector(NUM_OPS_BITS-1 downto 0) := x"6";
	constant AND_INS :   std_logic_vector(NUM_OPS_BITS-1 downto 0) := x"7";
	constant SHIFT1_INS  : std_logic_vector(NUM_OPS_BITS-1 downto 0) := x"8";
	constant SHIFT8_INS  : std_logic_vector(NUM_OPS_BITS-1 downto 0) := x"9";
	
	

	-- Currently 4bits instruction + 6bits addr1 + 6bits addr2 
	type vector_array is array(0 to ((2**NUM_INS)-1)) of std_logic_vector(INS_SIZE - 1 downto 0);
	constant instruction_rom: vector_array :=
	   (
	   --a0 0-3 a1 4-7 a2 8-11 p 12-15 e 16-19 e2 20-23
	   --phi section P <- A0 + A1 + A2
	   STORE_ins   & std_logic_vector(to_unsigned(3,STATE_RAM_ADDRESS)) & std_logic_vector(to_unsigned(0,STATE_RAM_ADDRESS)),  --store b0, a0
	   ADD_INS     & std_logic_vector(to_unsigned(3,STATE_RAM_ADDRESS)) & std_logic_vector(to_unsigned(1,STATE_RAM_ADDRESS)),  --add b0, a1
	   ADD_INS     & std_logic_vector(to_unsigned(3,STATE_RAM_ADDRESS)) & std_logic_vector(to_unsigned(2,STATE_RAM_ADDRESS)),  --add b0, a2
	   ESHIFT_INS  & std_logic_vector(to_unsigned(4,STATE_RAM_ADDRESS)) & std_logic_vector(to_unsigned(3,STATE_RAM_ADDRESS)),  --eshift b1, b0
           ADD_INS     & std_logic_vector(to_unsigned(0,STATE_RAM_ADDRESS)) & std_logic_vector(to_unsigned(4,STATE_RAM_ADDRESS)),  --add a0, b1
           ADD_INS     & std_logic_vector(to_unsigned(1,STATE_RAM_ADDRESS)) & std_logic_vector(to_unsigned(4,STATE_RAM_ADDRESS)),  --add a1, b1
           ADD_INS     & std_logic_vector(to_unsigned(2,STATE_RAM_ADDRESS)) & std_logic_vector(to_unsigned(4,STATE_RAM_ADDRESS)),  --add a2, b1
           
           --pwest
           SHIFT0_INS & std_logic_vector(to_unsigned(1,STATE_RAM_ADDRESS)) & std_logic_vector(to_unsigned(1,STATE_RAM_ADDRESS)),  --shift0 a1, a1
           SHIFT11_INS & std_logic_vector(to_unsigned(2,STATE_RAM_ADDRESS)) & std_logic_vector(to_unsigned(2,STATE_RAM_ADDRESS)),  --shift0 a2, a2
           
           --rnd const
           ADD_RND_CONST_INS & std_logic_vector(to_unsigned(0,STATE_RAM_ADDRESS)) & std_logic_vector(to_unsigned(0,STATE_RAM_ADDRESS)),  --ADD_RND_CONST_INS a0, a0
           
           --X
           NOT_INS & std_logic_vector(to_unsigned(3,STATE_RAM_ADDRESS)) & std_logic_vector(to_unsigned(1,STATE_RAM_ADDRESS)),  --not b0, a1
           AND_INS & std_logic_vector(to_unsigned(3,STATE_RAM_ADDRESS)) & std_logic_vector(to_unsigned(2,STATE_RAM_ADDRESS)),  --and b0, a2
           NOT_INS & std_logic_vector(to_unsigned(4,STATE_RAM_ADDRESS)) & std_logic_vector(to_unsigned(2,STATE_RAM_ADDRESS)),  --not b1, a2
           AND_INS & std_logic_vector(to_unsigned(4,STATE_RAM_ADDRESS)) & std_logic_vector(to_unsigned(0,STATE_RAM_ADDRESS)),  --and b1, a0
           NOT_INS & std_logic_vector(to_unsigned(5,STATE_RAM_ADDRESS)) & std_logic_vector(to_unsigned(0,STATE_RAM_ADDRESS)),  --not b2, a0
           AND_INS & std_logic_vector(to_unsigned(5,STATE_RAM_ADDRESS)) & std_logic_vector(to_unsigned(1,STATE_RAM_ADDRESS)),  --and b2, a1
           ADD_INS & std_logic_vector(to_unsigned(0,STATE_RAM_ADDRESS)) & std_logic_vector(to_unsigned(3,STATE_RAM_ADDRESS)),  --add a0, b0
           ADD_INS & std_logic_vector(to_unsigned(1,STATE_RAM_ADDRESS)) & std_logic_vector(to_unsigned(4,STATE_RAM_ADDRESS)),  --add a1, b1
           ADD_INS & std_logic_vector(to_unsigned(2,STATE_RAM_ADDRESS)) & std_logic_vector(to_unsigned(5,STATE_RAM_ADDRESS)),  --add a2, b2
           
           --pwest
           SHIFT1_INS & std_logic_vector(to_unsigned(1,STATE_RAM_ADDRESS)) & std_logic_vector(to_unsigned(1,STATE_RAM_ADDRESS)),  --shift0 a1, a1
           SHIFT8_INS & std_logic_vector(to_unsigned(2,STATE_RAM_ADDRESS)) & std_logic_vector(to_unsigned(2,STATE_RAM_ADDRESS)),  --shift0 a2, a2
           --21
           
           --STORE KEY
           STORE_ins   & std_logic_vector(to_unsigned(6,STATE_RAM_ADDRESS)) & std_logic_vector(to_unsigned(0,STATE_RAM_ADDRESS)),  --store ks0, a0
           STORE_ins   & std_logic_vector(to_unsigned(7,STATE_RAM_ADDRESS)) & std_logic_vector(to_unsigned(1,STATE_RAM_ADDRESS)),  --store ks1, a1
           STORE_ins   & std_logic_vector(to_unsigned(8,STATE_RAM_ADDRESS)) & std_logic_vector(to_unsigned(2,STATE_RAM_ADDRESS)),  --store ks2, a2
           --24
           --LOAD KEY
           STORE_ins   & std_logic_vector(to_unsigned(0,STATE_RAM_ADDRESS)) & std_logic_vector(to_unsigned(6,STATE_RAM_ADDRESS)),  --store a0, ks0
           STORE_ins   & std_logic_vector(to_unsigned(1,STATE_RAM_ADDRESS)) & std_logic_vector(to_unsigned(7,STATE_RAM_ADDRESS)),  --store a1, ks1
           STORE_ins   & std_logic_vector(to_unsigned(2,STATE_RAM_ADDRESS)) & std_logic_vector(to_unsigned(8,STATE_RAM_ADDRESS)),  --store a2, ks2       
       --27
	   others => (others => '0')
	   );
	
	-- Ci round constants rom
	type rom_array is array (0 to 11) of std_logic_vector(11 downto 0); 
	constant rnd_const_rom: rom_array :=(
		x"058",
		x"038",
		x"3C0",
		x"0D0",
		x"120",
		x"014",
		x"060",
		x"02C",
		x"380",
		x"0F0",
		x"1A0",
		x"012",
		others => x"000"
	);
begin
    --Determine instruction
    instruction <= instruction_rom(to_integer(unsigned(ins_counter)));
    --parse instruction
    operation <= instruction(INS_SIZE - 1 downto 2*STATE_RAM_ADDRESS);
    ADDRA <= instruction(2*STATE_RAM_ADDRESS-1 downto STATE_RAM_ADDRESS);
    ADDRB <= instruction(STATE_RAM_ADDRESS-1 downto 0);
    
    storeout <= RAMB;
    addout <= RAMA xor RAMB;
    --shift (1,5) xor shift (1,14)
    eshift <= (RAMB(26 downto 0) & RAMB(31 downto 27) &
              RAMB(122 downto 96) & RAMB(ADDRESS_LEN-1 downto 123) &
              RAMB(90 downto 64) & RAMB(95 downto 91) &
              RAMB(58 downto 32) & RAMB(63 downto 59)) xor
              (RAMB (17 downto 0) & RAMB(31 downto 18) &
              RAMB (113 downto 96) & RAMB(ADDRESS_LEN-1 downto 114) &
              RAMB (81 downto 64) & RAMB(95 downto 82) &
              RAMB (49 downto 32) & RAMB(63 downto 50));
    shift0 <= RAMB(31 downto 0) & RAMB(ADDRESS_LEN-1 downto 32);
    shift11 <= RAMB(116 downto 96) & RAMB(ADDRESS_LEN-1 downto 117) &
               RAMB(84 downto 64) & RAMB(95 downto 85) &
               RAMB(52 downto 32) & RAMB(63 downto 53) &
               RAMB(20 downto 0) & RAMB(31 downto 21);
    add_rnd_const <= RAMA xor (x"00000" & rnd_const_rom(to_integer(unsigned(RNDCTR))) & x"00000000" & x"00000000" & x"00000000");
	notout <= not RAMB;
	andout <= RAMA and RAMB;
	shift1 <= RAMB(126 downto 96) & RAMB(ADDRESS_LEN-1) &
	          RAMB(94 downto 64)  & RAMB(95) &
	          RAMB(62 downto 32)  & RAMB(63) &
	          RAMB(30 downto 0)   & RAMB(31);
    shift8 <= RAMB(55 downto 32) & RAMB(63 downto 56) &
              RAMB(23 downto 0)  & RAMB(31 downto 24) &
              RAMB(119 downto 96) & RAMB(ADDRESS_LEN-1 downto 120) &
              RAMB(87 downto 64) & RAMB(95 downto 88);

	
	-- Provide the correct value store in State memory 1
	with operation select
	   perm_output <=
	               storeout when STORE_ins,
	               addout when ADD_INS,
	               eshift when ESHIFT_INS,
	               shift0 when SHIFT0_INS,
	               shift11 when SHIFT11_INS,
	               add_rnd_const when ADD_RND_CONST_INS,
	               notout when NOT_INS,
	               andout when AND_INS,
	               shift1 when SHIFT1_INS,
	               shift8 when SHIFT8_INS,
	               (others => '1') when others;
	               
end Behavioral;
