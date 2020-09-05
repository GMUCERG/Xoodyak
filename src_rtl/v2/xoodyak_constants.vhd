--------------------------------------------------------------------------------
--! @file       xoodyak_constants.vhd
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


package xoodyak_constants is
	constant ADDRESS_LEN : integer := 128;
	constant DATA_LEN : integer := ADDRESS_LEN;
--	constant ADDRESS_ENTRIES : integer := 64; -- had to bump over to store the key
	constant ADDRESS_ENTRIES : integer := 16; -- had to bump over to 8 for store key
	constant ADDRESS_ENTRIES_BITs : integer := integer(ceil(log2(real(ADDRESS_ENTRIES))));
	constant NUM_ROUNDS : integer := 12;
	constant NUM_ROUNDS_BITS: integer := integer(ceil(log2(real(NUM_ROUNDS))));
	constant STATE_RAM_ADDRESS: integer := ADDRESS_ENTRIES_BITs; -- Same things as ADDRESS_ENTRIES_BITS should clean up
--	constant NUM_INS : integer := 7;  -- 2**7 > 92 based on xml spread sheet of instructions needed
	constant NUM_INS : integer := 5;  -- 2**5 > 21 based on xml spread sheet of instructions needed
	constant NUM_INSTRUCTIONS : integer := 21;

	--Typically 48 bytes.
	--Access in for bytes 44/4 == 11
--	constant FBPRIME: std_logic_vector(ADDRESS_ENTRIES_BITs - 1 downto 0) := "001011";
	constant FBPRIME: std_logic_vector(ADDRESS_ENTRIES_BITs - 1 downto 0) := "0010";
	

	constant STATE_WORDS : integer := 12 ; --12 * 4 * 8bits = 384 bits
	constant STATE_WORDS_PERM_SIZE : integer := 3; --3 * 128bits =384 bits
	constant KEY_WORDS : integer := 4 ; --4*4 = 16 bytes
	constant TAG_SIZE_CW: integer := 4;

end package xoodyak_constants;
