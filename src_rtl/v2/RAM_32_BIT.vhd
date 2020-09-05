--------------------------------------------------------------------------------
--! @file       RAM_32_BIT.vhd
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
USE ieee.numeric_std.all;
use work.xoodyak_constants.all;


entity DUAL_PORT_RAM_32_BIT is
	generic( ADDRESS_LEN: integer := 32;
	ADDR_ENTRIES: integer := ADDRESS_ENTRIES;
	ADD_ENT_BITS: integer := ADDRESS_ENTRIES_BITs);
	port(
	   RAMADDR1: in std_logic_vector(ADD_ENT_BITS-1 downto 0);
	   RAMADDR2: in std_logic_vector(ADD_ENT_BITS-1 downto 0);
	   RAMDIN1: in std_logic_vector(ADDRESS_LEN-1 downto 0);
	   RAMDOUT1: out std_logic_vector(ADDRESS_LEN-1 downto 0);
	   RAMDOUT2: out std_logic_vector(ADDRESS_LEN-1 downto 0);
	   RAMWRITE1: in std_logic;
	   clk: in std_logic
	);
end DUAL_PORT_RAM_32_BIT;



architecture Behavioral of DUAL_PORT_RAM_32_BIT is
	type RAM_ARRAY is array (0 to ADDR_ENTRIES-1) of std_logic_vector(ADDRESS_LEN-1 downto 0); 
	signal RAM: RAM_ARRAY :=(
		others => (others => '0')
	);
	begin
	process(clk)
	begin
		if (rising_edge(clk)) then
			if (RAMWRITE1 = '1') then
				RAM(to_integer(unsigned(RAMADDR1))) <= RAMDIN1;
			end if;
		end if;
	end process;

	RAMDOUT1 <= RAM(to_integer(unsigned(RAMADDR1)));
	RAMDOUT2 <= RAM(to_integer(unsigned(RAMADDR2)));

end Behavioral;
