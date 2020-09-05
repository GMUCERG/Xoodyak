--------------------------------------------------------------------------------
--! @file       cyclist_ops.vhd
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
use work.xoodyak_constants.all;

entity cyclist_ops is
    generic(
        RAM_LEN: integer := ADDRESS_LEN;
        DATA_LEN: integer := 32
    );
	port(
		--controls for mux
		cyc_state_update_sel: in std_logic_vector(1 downto 0);
		xor_sel: in std_logic_vector(1 downto 0);
		cycd_sel: in std_logic_vector(1 downto 0);
		extract_sel: in std_logic;
		addr_sel2: in std_logic;
		
		--input data
		ramoutd1: in std_logic_vector(RAM_LEN-1 downto 0);
		key: in std_logic_vector(DATA_LEN-1 downto 0);
		bdi_data: in std_logic_vector(DATA_LEN-1 downto 0);
		cu_cd: in std_logic_vector(7 downto 0);
		dcount_in: in std_logic_vector(1 downto 0);

		--output data
		cyc_state_update: out std_logic_vector(RAM_LEN-1 downto 0);
		bdo_out: out std_logic_vector(DATA_LEN-1 downto 0)
		);
end cyclist_ops;

architecture Behavioral of cyclist_ops is
    constant highest_zeros : std_logic_vector(95 downto 0):= (others => '0');
	signal cycd_add: std_logic_vector(DATA_LEN-1 downto 0);
	signal xor_mux_o: std_logic_vector(DATA_LEN-1 downto 0);
	signal temp_xor_out: std_logic_vector(DATA_LEN-1 downto 0);
	signal decrypt_mux: std_logic_vector(DATA_LEN-1 downto 0);
	signal temp_cyc_state: std_logic_vector(DATA_LEN-1 downto 0);
	signal temp_ram: std_logic_vector(32-1 downto 0);

begin
	--cycle down mux
	with cycd_sel select
		cycd_add <=  
		            x"000001" & bdi_data(7 downto 0)  when "01",
					x"0001"   & bdi_data(15 downto 0)  when "10",
					x"01"     & bdi_data(23 downto 0)   when "11",
					x"00000001" when others;

	-- input xor mux
	with xor_sel select
		xor_mux_o <=	bdi_data when "00",
						temp_ram when "01", -- Used to set state to all zeros
						cu_cd & x"000000" when "10", --extend the signal
						cycd_add when others;

	temp_xor_out <= temp_ram xor xor_mux_o;
	
	--extract mux
	bdo_out <= temp_ram when extract_sel = '0' else temp_xor_out;

	--decrypt_mux
	with cycd_sel select
	   decrypt_mux <=  temp_ram(31 downto 9)  & ('1' xor temp_ram(8)) & bdi_data(7 downto 0) when "01",
	                   temp_ram(31 downto 17)  & ('1' xor temp_ram(16)) & bdi_data(15 downto 0) when "10",
	                   temp_ram(31 downto 25) & ('1' xor temp_ram(24)) & bdi_data(23 downto 0) when "11",
	                   bdi_data when others; -- ct is full 4 bytes
	
    with cyc_state_update_sel select
        temp_cyc_state <= 
                            temp_xor_out when "00",
                            key when "01",
                            x"00000100" when "10",
                            decrypt_mux when others;
    -- Added for larger perm
    with dcount_in select
        cyc_state_update <=
                            temp_cyc_state & ramoutd1(95 downto 0)  when "00",
                            ramoutd1(RAM_LEN-1 downto 96) & temp_cyc_state & ramoutd1(63 downto 0) when "01",
                            ramoutd1(RAM_LEN-1 downto 64) & temp_cyc_state & ramoutd1(31 downto 0) when "10",
                            ramoutd1(RAM_LEN-1 downto 32) & temp_cyc_state when others;

    with dcount_in select
        temp_ram <= ramoutd1(127 downto 96) when "00",
                    ramoutd1(95 downto 64) when "01",
                    ramoutd1(63 downto 32) when "10",
                    ramoutd1(31 downto 0) when others;
        
     
end Behavioral;
