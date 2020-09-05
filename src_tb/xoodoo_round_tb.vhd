-------------------------------------------------------------------------------
--! @file       xoodoo_round_tv.vd
--! @brief      Testbench based on the GMU CAESAR project.
--! @project    CAESAR Candidate Evaluation
--! @author     Rich H
--! @copyright  Copyright (c) 2020 Cryptographic Engineering Research Group
--!             ECE Department, George Mason University Fairfax, VA, U.S.A.
--!             All rights Reserved.
--! @version    1.0
--! @license    This project is released under the GNU Public License.
--!             The license and distribution terms for this file may be
--!             found in the file LICENSE in this distribution or at
--!             http://www.gnu.org/licenses/gpl-3.0.txt
--! @note       This is publicly available encryption source code that falls
--!             under the License Exception TSU (Technology and software-
--!             unrestricted)
-------------------------------------------------------------------------------
--Warning unsure if this still works. Most likely not
library IEEE;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;
use ieee.math_real.all;
use std.textio.all;
use ieee.std_logic_textio.all;
library work;
use work.xoodyak_constants.all;

entity xoodoo_round_tb is
	generic( DATA_SIZE: integer := 128);
end xoodoo_round_tb;

architecture xoodoo_round_tb of xoodoo_round_tb is

	signal clk : std_logic :='0';
	signal rst: std_logic;
	
	--round perm counter
	signal round_counter : std_logic_vector(NUM_ROUNDS_BITS-1 downto 0);
	signal en_round: std_logic;
	signal load_round: std_logic;
	--instruction counter
	signal ins_counter: std_logic_vector(NUM_INS-1 downto 0);
	signal en_counter: std_logic;
	signal load_counter: std_logic;
	--data counter
	signal dcount: std_logic_vector(ADDRESS_ENTRIES_BITs-1 downto 0);
	signal en_dcount: std_logic;
	signal load_dcount: std_logic;
	
	--state ram
	signal perm_rom_addr1 : std_logic_vector(ADDRESS_ENTRIES_BITs-1 downto 0);
	signal perm_rom_addr2 : std_logic_vector(ADDRESS_ENTRIES_BITs-1 downto 0);
	signal ramwrite1: std_logic:='0';
	
	--state ram din1 inputs
	signal xor_out: std_logic_vector(DATA_SIZE - 1 downto 0);
	signal perm_ram_input_1 : std_logic_vector(DATA_SIZE - 1 downto 0);
	signal din1_mux_sel: std_logic;
	
	signal addr1_sel: std_logic_vector(1 downto 0);
	
	signal ramd1out: std_logic_vector(DATA_SIZE - 1 downto 0);
	signal ramout2: std_logic_vector(DATA_SIZE - 1 downto 0);
		
	
	constant period: time := 10 ns;
	file dataf: text is in "testdatastart.txt";
	file perm_done: text is in "permutation_done.txt";
begin

    UUT_STATE_RAM: entity work.state_ram_wrapper
        generic map(DATA_SIZE => DATA_SIZE, ADDR_SIZE => ADDRESS_ENTRIES_BITs)
        port map (
        xor_out => xor_out,
        perm_input => perm_ram_input_1,
        din_sel => din1_mux_sel,
        perm_addr => perm_rom_addr1,
        perm_addr2 => perm_rom_addr2,
		dcount => dcount,
        addr1_sel => addr1_sel,
        ramwrite => ramwrite1,
        clk => clk,
        ramout1 => ramd1out,
        ramout2 => ramout2
        );
	UUT_XOODOO: entity work.xoodoo_round
	   generic map(ADDRESS_LEN => DATA_SIZE)
	   port map(
	   RAMA => ramd1out,
	   RAMB => ramout2,
	   perm_output  => perm_ram_input_1,
	   ADDRA => perm_rom_addr1,
	   ADDRB => perm_rom_addr2,
	   RNDCTR => round_counter,
	   ins_counter => ins_counter
	   );
	e_round_counter: entity work.counter
	   generic map (num_bits =>NUM_ROUNDS_BITS)
	   port map (
	   clk => clk,
	   enable => en_round,
	   load => load_round,
	   start_value => (others =>'0'),
	   q => round_counter
	   );
    e_ins_counter: entity work.counter
	   generic map (num_bits => NUM_INS)
	   port map (
	   clk => clk,
	   enable => en_counter,
	   load => load_counter,
	   start_value => (others =>'0'),
	   q => ins_counter
	   );
	--data counter
    E_dcount: entity work.counter
	   generic map (num_bits => ADDRESS_ENTRIES_BITs)
	   port map (
	   clk => clk,
	   enable => en_dcount,
	   start_value => (others =>'0'),
	   load => load_dcount,
	   q => dcount
	   );
    --free running clk
	clk <= not clk after period/2;    
    readf: process
        variable rline: line;
        variable rvalid: boolean;
        variable part0: std_logic_vector(31 downto 0);
        variable part1: std_logic_vector(31 downto 0);
        variable part2: std_logic_vector(31 downto 0);
        variable part3: std_logic_vector(31 downto 0);
        variable msg: line;
        variable comma: character;
        begin
            rst <= '1';
            en_round <= '0';
            en_counter <= '0';
			en_dcount <= '0';
            load_round <= '0';
            load_counter <= '0';
			load_dcount <= '1';
            wait for period; -- Ensures clocks reset
			load_dcount <='0';
            rst <= '0';
            addr1_sel <= "10"; -- select dcount
            din1_mux_sel <= '0';  --xor_out
            ramwrite1 <= '1';
            en_counter <= '1';
			en_dcount <= '1';

            
            --Loads the initial state data in
            while not endfile(dataf) loop
                readline(dataf, rline);
                hread(rline, part0, good => rvalid);
                read(rline, comma);
                hread(rline, part1, good => rvalid);
                read(rline, comma);
                hread(rline, part2, good => rvalid);
                read(rline, comma);
                hread(rline, part3, good => rvalid);
                xor_out <= part0 & part1 & part2 & part3;
                wait for period/2;
                wait for period/2;
            end loop;
            -- Going to setup for the start of permutation
            load_counter <= '1';
			load_dcount <= '1';
            ramwrite1 <= '0';
			en_dcount <= '0';
            wait for period;
            load_counter <= '0';
			load_dcount <= '0';
            --select perm1 output
            din1_mux_sel <= '1'; 
            addr1_sel <="00";  --Using perm input
            ramwrite1 <='1';

            for i in 0 to 11 loop
                wait for period * 20;
                write(msg, string'("Believe that I am done with permutation"));
                write(msg, i);
                writeline(output,msg);
                load_counter <='1';
                if i /= 11 then
                    en_round <= '1';
                else
                    load_round <= '1';
                    en_counter <= '0';
                end if;
                wait for period/2;
                load_counter <='0';
                load_round <= '0';
                en_round <= '0';
                wait for period/2;
            end loop;

            ramwrite1 <= '0';
            wait for period/2;
			
			load_dcount <= '0';
			en_dcount <= '1';
            addr1_sel <="10";  --using ins_counter

            write(msg, string'("Done with all of the rounds"));
            writeline(output,msg);

            --Verify against the end of the permutation
            while not endfile(perm_done) loop
                readline(perm_done, rline);
                hread(rline, part0, good => rvalid);
                read(rline, comma);
                hread(rline, part1, good => rvalid);
                read(rline, comma);
                hread(rline, part2, good => rvalid);
                read(rline, comma);
                hread(rline, part3, good => rvalid);
                xor_out <= part0 & part1 & part2 & part3;
                wait for period/2;
                write(msg, string'("Expected: "));
                hwrite(msg, xor_out, left, 4);
                write(msg, string'(" vs  "));
                hwrite(msg, ramd1out, left, 4);
                writeline(output,msg);
                
				if (xor_out /= ramd1out) then
                    assert false;
                    report "Invalid value!"
                    severity failure;
                end if;
                wait for period/2;
            end loop;
            write(msg, string'("Verified content"));
            writeline(output,msg);
            wait;
    end process;
end;
