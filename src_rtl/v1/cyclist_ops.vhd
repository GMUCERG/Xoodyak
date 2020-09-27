--------------------------------------------------------------------------------
--! @file       cyclilst_ops.vhd (CAESAR API for Lightweight)
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
use work.design_pkg.all;

entity cyclist_ops is
    generic(
        DATA_LEN: integer := 32
    );
	port(
	    clk: in std_logic;
	    key_en: in std_logic;
	    state_main_en: std_logic_vector(2 downto 0);
	    state_main_sel: std_logic_vector(6 downto 0);

		--controls for mux
		cyc_state_update_sel: in std_logic_vector(1 downto 0);
		xor_sel: in std_logic;
		cycd_sel: in std_logic_vector(1 downto 0);
		extract_sel: in std_logic;
		
		--input data
		bdi_key: in std_logic_vector(DATA_LEN-1 downto 0);
		cu_cd: in std_logic_vector(7 downto 0);
		dcount_in: in std_logic_vector(3 downto 0);
        rnd_counter: in std_logic_vector(NUM_ROUNDS_BITS - 1 downto 0);

		--output data
		bdo_out: out std_logic_vector(DATA_LEN-1 downto 0)
		);
end cyclist_ops;

architecture Behavioral of cyclist_ops is
    signal cyc_state_update: std_logic_vector(PLANE_LEN-1 downto 0);
    signal cycd_add: std_logic_vector(DATA_LEN-1 downto 0);
    signal xor_mux_o: std_logic_vector(DATA_LEN-1 downto 0);
    signal temp_xor_out: std_logic_vector(DATA_LEN-1 downto 0);
    signal decrypt_mux: std_logic_vector(DATA_LEN-1 downto 0);
    signal temp_cyc_state: std_logic_vector(DATA_LEN-1 downto 0);
    signal temp_ram: std_logic_vector(32-1 downto 0);

    signal plane_x: std_logic_vector(PLANE_LEN - 1 downto 0);
    signal fb_prime : std_logic_vector(7 downto 0);
    signal bdi_data: std_logic_vector(DATA_LEN-1 downto 0);	
    signal bdo_out_t: std_logic_vector(DATA_LEN-1 downto 0);	
    signal key: std_logic_vector(DATA_LEN-1 downto 0);	
    signal key_in: std_logic_vector(ADDRESS_LEN-1 downto 0);
    signal key_out: std_logic_vector(ADDRESS_LEN-1 downto 0);
    signal perm_input: std_logic_vector(ADDRESS_LEN-1 downto 0);
    signal perm_output: std_logic_vector(ADDRESS_LEN-1 downto 0);
    signal state_main_in_p0: std_logic_vector(PLANE_LEN-1 downto 0);
    signal state_main_in_p1: std_logic_vector(PLANE_LEN-1 downto 0);
    signal state_main_in_p2: std_logic_vector(PLANE_LEN-1 downto 0);

    signal state_main_out_plane0:std_logic_vector(PLANE_LEN-1 downto 0);
    signal state_main_out_plane1:std_logic_vector(PLANE_LEN-1 downto 0);
    signal state_main_out_plane2:std_logic_vector(PLANE_LEN-1 downto 0);
	

	signal plane_2_input: std_logic_vector(PLANE_LEN-1 downto 0);
    constant cycd_add_xor :bit_vector := x"0000000001";
    constant cycd_add_and :bit_vector := x"00FFFFFF";


begin
    bdi_data <= reverse_byte(bdi_key);
    key <= bdi_data;
    with dcount_in(3 downto 2) select
        plane_x <= state_main_out_plane0 when "00",
                   state_main_out_plane1 when "01",
                   state_main_out_plane2 when others;
	--cycle down mux
	--with cycd_sel select
	--	cycd_add <=  
	--	            x"000001" & bdi_data(7 downto 0)  when "01",
	--				x"0001"   & bdi_data(15 downto 0)  when "10",
	--				x"01"     & bdi_data(23 downto 0)   when "11",
	--				x"00000001" when others;
    --xor_mux_o <=	bdi_data when xor_sel = '0' else cycd_add;

    cycd_add <= (bdi_data and to_stdlogicvector(cycd_add_and srl ((3-to_integer(unsigned(cycd_sel)))*8))) xor to_stdlogicvector(cycd_add_xor sll (to_integer(unsigned(cycd_sel))*8))(DATA_LEN-1 downto 0);
    xor_mux_o <=	bdi_data when xor_sel = '0' else cycd_add;

    temp_xor_out <= temp_ram xor xor_mux_o;
	

    bdo_out_t <= temp_ram when extract_sel = '0' else temp_xor_out;
    bdo_out <= reverse_byte(bdo_out_t);


    with dcount_in(1 downto 0) select
        temp_ram <= plane_x(127 downto 96) when "00",
                    plane_x(95 downto 64) when "01",
                    plane_x(63 downto 32) when "10",
                    plane_x(31 downto 0) when others;

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
    with dcount_in(1 downto 0) select
        cyc_state_update <=
                            temp_cyc_state & plane_x(95 downto 0)  when "00",
                            plane_x(PLANE_LEN-1 downto 96) & temp_cyc_state & plane_x(63 downto 0) when "01",
                            plane_x(PLANE_LEN-1 downto 64) & temp_cyc_state & plane_x(31 downto 0) when "10",
                            plane_x(PLANE_LEN-1 downto 32) & temp_cyc_state when others;

    fb_prime <= (state_main_out_plane2(31 downto 24) xor cu_cd);
    plane_2_input <=    state_main_out_plane2(127 downto 32) &
                        fb_prime &
                        state_main_out_plane2(23 downto 0)
                     when state_main_sel(6) = '0' else
                        cyc_state_update(127 downto 32) &
                        fb_prime &
                        cyc_state_update(23 downto 0);

GEN_store_key: if (STORE_KEY) generate 
    -- Muxes to the different plane registers    
    with state_main_sel(1 downto 0) select
        state_main_in_p0 <= cyc_state_update when "00",
                            perm_output(127 downto 0) when "01",
                            key_out(127 downto 0) when "10",
                            (others => '0') when others;
    with state_main_sel(3 downto 2) select
        state_main_in_p1 <= cyc_state_update when "00",
                            perm_output(255 downto 128) when "01",
                            key_out(255 downto 128) when "10",
                            (others => '0') when others;
    with state_main_sel(5 downto 4) select
        state_main_in_p2 <= plane_2_input when "00",
                            perm_output(383 downto 256) when "01",
                            key_out(383 downto 256) when "10",                         
                            (others => '0') when others;
    key_in <= state_main_in_p2 & state_main_in_p1 & state_main_in_p0;
    key_state: entity work.reg_custom
        generic map ( LEN => ADDRESS_LEN)
        port map(
            clk  => clk,
            en   => key_en,
            din  => key_in,
            qout => key_out
        );
end generate GEN_store_key;
GEN_not_store_key: if (not STORE_KEY) generate 
    with state_main_sel(1 downto 0) select
        state_main_in_p0 <= cyc_state_update when "00",
                            perm_output(127 downto 0) when "01",
                            (others => '0') when others;
    with state_main_sel(3 downto 2) select
        state_main_in_p1 <= cyc_state_update when "00",
                            perm_output(255 downto 128) when "01",
                            (others => '0') when others;
    with state_main_sel(5 downto 4) select
        state_main_in_p2 <= plane_2_input when "00",
                            perm_output(383 downto 256) when "01",
                            (others => '0') when others;
end generate GEN_not_store_key;

    state_main_p0: entity work.reg_custom
        generic map ( LEN => PLANE_LEN)
        port map(
            clk  => clk,
            en   => state_main_en(0),
            din  => state_main_in_p0,
            qout => state_main_out_plane0
        );
    state_main_p1: entity work.reg_custom
        generic map ( LEN => PLANE_LEN)
        port map(
            clk  => clk,
            en   => state_main_en(1),
            din  => state_main_in_p1,
            qout => state_main_out_plane1
        );
    state_main_p2: entity work.reg_custom
        generic map ( LEN => PLANE_LEN)
        port map(
            clk  => clk,
            en   => state_main_en(2),
            din  => state_main_in_p2,
            qout => state_main_out_plane2
        );

    perm_input <= state_main_out_plane2 & state_main_out_plane1 & state_main_out_plane0;
    XOODOO_PERM: entity work.xoodoo_round
        generic map(
          ADDRESS_LEN =>ADDRESS_LEN
        )
     port map(
     INPUT => perm_input,
     perm_output  => perm_output,
     RNDCTR => rnd_counter
     );
    
     
end Behavioral;
