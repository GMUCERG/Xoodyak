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
	generic( ADDRESS_LEN: integer := 384
	);
	port(
	    -- Access to that state ram
		INPUT: in std_logic_vector(ADDRESS_LEN-1 downto 0);
		perm_output: out std_logic_vector(ADDRESS_LEN-1 downto 0);
		-- Counter for current round number 
		RNDCTR: in std_logic_vector(NUM_ROUNDS_BITS - 1  downto 0)
		);
end xoodoo_round;

architecture Behavioral of xoodoo_round is
    signal plane0: std_logic_vector(PLANE_LEN-1 downto 0);
    signal plane1: std_logic_vector(PLANE_LEN-1 downto 0);
	signal plane2: std_logic_vector(PLANE_LEN-1 downto 0);
	
	signal plane0_2: std_logic_vector(PLANE_LEN-1 downto 0);
    signal plane1_2: std_logic_vector(PLANE_LEN-1 downto 0);
    signal plane2_2: std_logic_vector(PLANE_LEN-1 downto 0);
    
    signal plane0_3: std_logic_vector(PLANE_LEN-1 downto 0);
    signal plane1_3: std_logic_vector(PLANE_LEN-1 downto 0);
    signal plane2_3: std_logic_vector(PLANE_LEN-1 downto 0);
    
	signal p_plane :std_logic_vector(PLANE_LEN-1 downto 0);
	signal eshift :std_logic_vector(PLANE_LEN-1 downto 0);
	
	signal add_rnd_const_small: std_logic_vector(11 downto 0);
    signal add_rnd_const_plane0: std_logic_vector(127 downto 0);
	signal shift0_plane1: std_logic_vector(127 downto 0);
    signal shift11_plane2: std_logic_vector(127 downto 0);
	
	signal shift1: std_logic_vector(127 downto 0);
    signal shift8: std_logic_vector(127 downto 0);

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
    plane0 <= INPUT(127 downto 0);
    plane1 <= INPUT(255 downto 128);
    plane2 <= INPUT(383 downto 256);
    
    --theta
    p_plane <= plane0 xor plane1 xor plane2;
    eshift <= (p_plane(26 downto 0) & p_plane(31 downto 27) &
          p_plane(122 downto 96) & p_plane(127 downto 123) &
          p_plane(90 downto 64) & p_plane(95 downto 91) &
          p_plane(58 downto 32) & p_plane(63 downto 59)) xor
          (p_plane (17 downto 0) & p_plane(31 downto 18) &
          p_plane (113 downto 96) & p_plane(127 downto 114) &
          p_plane (81 downto 64) & p_plane(95 downto 82) &
          p_plane (49 downto 32) & p_plane(63 downto 50));          
    plane2_2 <= plane2 xor eshift;
    plane1_2 <= plane1 xor eshift;
    plane0_2 <= plane0 xor eshift;

    --rho west + i
    add_rnd_const_small <= plane0_2(107 downto 96) xor rnd_const_rom(to_integer(unsigned(RNDCTR)));
    add_rnd_const_plane0 <= plane0_2(127 downto 108) & add_rnd_const_small & plane0_2(95 downto 0);
    shift0_plane1 <= plane1_2(31 downto 0) & plane1_2(127 downto 32);
    shift11_plane2 <= plane2_2(116 downto 96) & plane2_2(127 downto 117) &
               plane2_2(84 downto 64) & plane2_2(95 downto 85) &
               plane2_2(52 downto 32) & plane2_2(63 downto 53) &
               plane2_2(20 downto 0) & plane2_2(31 downto 21);
    
    --chi
    plane0_3 <= add_rnd_const_plane0 xor ((not shift0_plane1) and shift11_plane2);
    plane1_3 <= shift0_plane1 xor ((not shift11_plane2) and add_rnd_const_plane0);
    plane2_3 <= shift11_plane2 xor ((not add_rnd_const_plane0) and shift0_plane1);
    
    --rho east
    shift1 <= plane1_3(126 downto 96) & plane1_3(127) &
              plane1_3(94 downto 64)  & plane1_3(95) &
              plane1_3(62 downto 32)  & plane1_3(63) &
              plane1_3(30 downto 0)   & plane1_3(31);
    shift8 <= plane2_3(55 downto 32) & plane2_3(63 downto 56) &
              plane2_3(23 downto 0)  & plane2_3(31 downto 24) &
              plane2_3(119 downto 96) & plane2_3(127 downto 120) &
              plane2_3(87 downto 64) & plane2_3(95 downto 88);
    perm_output <= shift8 & shift1 & plane0_3;               
end Behavioral;
