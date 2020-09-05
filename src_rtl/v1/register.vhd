--------------------------------------------------------------------------------
--! @file       register.vhd (CAESAR API for Lightweight)
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
library ieee;
use ieee.std_logic_1164.all;

entity reg_custom is
    generic (
        LEN: integer := 128
    );
    port(
        clk: in std_logic;
        en: in std_logic;
        din : in std_logic_vector(LEN-1 downto 0);
        qout: out std_logic_vector(LEN-1 downto 0)
    );
end reg_custom;

architecture RTL of reg_custom is

begin
    process (clk, en)
        begin
        if (rising_edge(clk) and en = '1') then
            qout<=din;
        end if;
    end process; 
end RTL;
