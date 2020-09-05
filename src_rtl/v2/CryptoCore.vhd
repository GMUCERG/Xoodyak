--------------------------------------------------------------------------------
--! @file       CryptoCore.vhd
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
use ieee.numeric_std.all;
use ieee.std_logic_misc.all;
use work.NIST_LWAPI_pkg.all;
use work.Design_pkg.all;
use work.xoodyak_constants.all;


entity CryptoCore is
    Port (
        clk             : in   STD_LOGIC;
        rst             : in   STD_LOGIC;
        --PreProcessor===============================================
        ----!key----------------------------------------------------
        key             : in   STD_LOGIC_VECTOR (CCSW     -1 downto 0);
        key_valid       : in   STD_LOGIC;
        key_ready       : out  STD_LOGIC;
        ----!Data----------------------------------------------------
        bdi             : in   STD_LOGIC_VECTOR (CCW     -1 downto 0);
        bdi_valid       : in   STD_LOGIC;
        bdi_ready       : out  STD_LOGIC;
        bdi_pad_loc     : in   STD_LOGIC_VECTOR (CCWdiv8 -1 downto 0);
        bdi_valid_bytes : in   STD_LOGIC_VECTOR (CCWdiv8 -1 downto 0);
        bdi_size        : in   STD_LOGIC_VECTOR (3       -1 downto 0);
        bdi_eot         : in   STD_LOGIC;
        bdi_eoi         : in   STD_LOGIC;
        bdi_type        : in   STD_LOGIC_VECTOR (4       -1 downto 0);
        decrypt_in      : in   STD_LOGIC;
        key_update      : in   STD_LOGIC;
        hash_in         : in   std_logic;
        --!Post Processor=========================================
        bdo             : out  STD_LOGIC_VECTOR (CCW      -1 downto 0);
        bdo_valid       : out  STD_LOGIC;
        bdo_ready       : in   STD_LOGIC;
        bdo_type        : out  STD_LOGIC_VECTOR (4       -1 downto 0);
        bdo_valid_bytes : out  STD_LOGIC_VECTOR (CCWdiv8 -1 downto 0);
        end_of_block    : out  STD_LOGIC;
        msg_auth_valid  : out  STD_LOGIC;
        msg_auth_ready  : in   STD_LOGIC;
        msg_auth        : out  STD_LOGIC
    );
end CryptoCore;

architecture behavioral of CryptoCore is
    --signals to data path components
    --cyc_ops inputs only
    signal cycd_sel: std_logic_vector(1 downto 0);
    signal extract_sel: std_logic;
    signal cyc_state_update_sel: std_logic_vector(1 downto 0);
    signal xor_sel: std_logic_vector(1 downto 0);
    signal cu_cd_s: std_logic_vector(7 downto 0);
    
    --state memory signals
    signal din_sel: std_logic;
    signal ramwrite: std_logic;
    signal addr_sel: std_logic_vector(1 downto 0);
    signal ramout1: std_logic_vector(DATA_LEN-1 downto 0);
    signal ramout2: std_logic_vector(DATA_LEN-1 downto 0);
      
    --data signals
    signal cyc_state_update: std_logic_vector(DATA_LEN-1 downto 0);
    signal perm_output: std_logic_vector(DATA_LEN-1 downto 0);
    
    --address signals
    signal perm_addr: std_logic_vector(ADDRESS_ENTRIES_BITs-1 downto 0);
    signal perm_addr2: std_logic_vector(ADDRESS_ENTRIES_BITs-1 downto 0);
    
    
    --ins_count
    signal ins_counter: std_logic_vector(NUM_INS-1 downto 0);
    signal ins_start_value: std_logic_vector(NUM_INS-1 downto 0);
    signal ins_counter_int: integer;
    signal en_ins: std_logic;
    signal load_ins: std_logic;
    
    --perm_count
    signal rnd_counter: std_logic_vector(NUM_ROUNDS_BITS-1 downto 0);
    signal rnd_counter_int: integer;
    signal en_rnd: std_logic;
    signal load_rnd: std_logic;
    
    --data counter
    --TODO determine the max data that this counter should need
    signal dcount: std_logic_vector(ADDRESS_ENTRIES_BITs-1 downto 0);
    signal dcount_int: integer;
    signal en_dcount: std_logic;
    signal dcount_start_value: std_logic_vector(ADDRESS_ENTRIES_BITs-1 downto 0);
    signal load_dcount: std_logic;
    
    
    -- State signals
    type cycstate_t is (IDLE, STORE_KEY,
           CYC_DOWN, CYC_ADD_BYTE, CYC_DOWN_CD,
           CYC_UP_ADDBYTE, CYC_UP_PERM, CYC_UP_EXTRACT,
           INIT_HASH);
    signal n_cyc_s, cyc_s: cycstate_t;
    
    type mess_states_t is (ABSORB_NONCE,  ABSORB_AD, ABSORB_MSG, SQUEEZE, ABSORB_HASH, STORE_KEY);
    signal calling_state, n_calling_state: mess_states_t;
    
    signal state_type_match: boolean;
    signal rnd_input_limit: boolean;
    type mode_t is (KEYED, HASH);
    signal mode, n_mode: mode_t;
  
  
    --Key signals
    signal key_ready_s:std_logic;
    signal key_s: std_logic_vector(CCSW-1 downto 0);
    signal key_update_internal, key_update_internal_n: std_logic_vector(1 downto 0);
  
    --data signals
    signal bdi_ready_s:std_logic;
    signal bdi_s : std_logic_vector(CCW - 1 downto 0);
    signal bdi_valid_bytes_s: std_logic_vector(CCWdiv8 - 1 downto 0);
    signal decrypt_op_s, n_decrypt_op_s: std_logic;
    
    -- Output signals
    signal bdo_s                        : std_logic_vector(CCW - 1 downto 0);
    signal bdo_valid_bytes_s            : std_logic_vector(CCWdiv8 - 1 downto 0);
    signal bdo_valid_s                  : std_logic;
    signal bdo_type_s                   : std_logic_vector(3 downto 0);
    
    -- This signal is used to send header messages
    signal n_msg_auth_valid_s           : std_logic;
    signal n_msg_auth_s                 : std_logic;
    signal n_tag_verified, tag_verified :std_logic;
    
    signal gtr_one_perm, n_gtr_one_perm: std_logic;

    --small perm    
--    constant store_key_ins_start : integer:=93;
--    constant store_key_ins_end: integer:= 104;
--    constant load_key_ins_start: integer:= 105;
--    constant load_key_ins_end: integer:= 116;
    constant store_key_ins_start : integer:=21;
    constant store_key_ins_end: integer:= 23;
    constant load_key_ins_start: integer:= 24;
    constant load_key_ins_end: integer:= 26;

    --signals used to control the muxes for the state ram
    signal addrmux1: std_logic_vector(ADDRESS_ENTRIES_BITs-1 downto 0);
    signal addrmux2: std_logic_vector(ADDRESS_ENTRIES_BITs-1 downto 0);
    signal ramainput: std_logic_vector(DATA_LEN - 1 downto 0);

begin
    UUT_RAM: entity work.DUAL_PORT_RAM_32_BIT
    generic map ( ADDRESS_LEN => DATA_LEN)
    port map(
    RAMADDR1 => addrmux2,
    RAMADDR2 => perm_addr2,
    RAMDOUT1 => ramout1,
    RAMDOUT2 => ramout2,
    RAMDIN1 => ramainput,
    RAMWRITE1 => ramwrite,
    clk => clk
    );
    -- Muxes that control the input/outputs of state ram
    --din mux
    ramainput <= perm_output when din_sel = '1' else cyc_state_update;

    -- mux to select the input addressa
    addrmux1 <= perm_addr when addr_sel(0) = '0' else "00" & dcount(ADDRESS_ENTRIES_BITs-1 downto 2);
    addrmux2 <= FBPRIME when addr_sel(1) = '1' else addrmux1;

  XOODOO_PERM: entity work.xoodoo_round
      generic map(
          ADDRESS_LEN =>128,
          ADDRESS_ENTRIES => ADDRESS_ENTRIES,
          ADDRESS_ENTRIES_BITs => ADDRESS_ENTRIES_BITs  
      )
     port map(
     RAMA => ramout1,
     RAMB => ramout2,
     perm_output  => perm_output,
     ADDRA => perm_addr,
     ADDRB => perm_addr2,
     RNDCTR => rnd_counter,
     ins_counter => ins_counter
     );
  --round counter
  round_counter: entity work.counter
     generic map (num_bits =>NUM_ROUNDS_BITS)
     port map (
     clk => clk,
     load => load_rnd,
     enable => en_rnd,
     start_value => (others => '0'),
     q => rnd_counter
     );
  --instruction counter
    E_ins_counter: entity work.counter
     generic map (num_bits => NUM_INS)
     port map (
     clk => clk,
     load => load_ins,
     enable => en_ins,
     start_value => ins_start_value,
     q => ins_counter
     );
  --data counter
    E_dcount: entity work.counter
     generic map (num_bits => ADDRESS_ENTRIES_BITs)
     port map (
     clk => clk,
     load => load_dcount,
     enable => en_dcount,
     start_value => dcount_start_value,
     q => dcount
     );
     
  cyc_ops: entity work.cyclist_ops
    port map (
    cyc_state_update_sel => cyc_state_update_sel,
    xor_sel => xor_sel,
    cycd_sel => cycd_sel,
    extract_sel => extract_sel,
    addr_sel2 => addr_sel(1),
    ramoutd1 => ramout1,
    key => key_s,
    bdi_data => bdi_s,
    cu_cd => cu_cd_s,
    dcount_in => dcount(1 downto 0),
    cyc_state_update => cyc_state_update,
    bdo_out => bdo_s
    );
    
    --convert to integer for comparison 
    dcount_int <= to_integer(unsigned(dcount));
    rnd_counter_int <= to_integer(unsigned(rnd_counter));
    ins_counter_int <= to_integer(unsigned(ins_counter));
    
    --Mapping 
    key_ready <= key_ready_s;
    key_s <= reverse_byte(key);
    --bdi
    bdi_ready <= bdi_ready_s;
    bdi_s               <= reverse_byte(bdi);
    bdi_valid_bytes_s   <= reverse_bit(bdi_valid_bytes);
    
      
    --data outputs
    bdo                 <= reverse_byte(bdo_s);
    bdo_valid_bytes     <= reverse_bit(bdo_valid_bytes_s);
    bdo_valid           <= bdo_valid_s;
    bdo_type            <= bdo_type_s;
    
    --The following are used in the controller to handle the transition between states.
    state_type_match        <= (bdi_type = HDR_AD and calling_state = ABSORB_AD) or
                               (bdi_type = HDR_NPUB and calling_state = ABSORB_NONCE) or
                               ((bdi_type = HDR_MSG or bdi_type = HDR_CT) and calling_state = ABSORB_MSG) or
                               (bdi_type = HDR_TAG and calling_state = SQUEEZE) or
                               (bdi_type = HDR_HASH_MSG and calling_state = ABSORB_HASH);
    rnd_input_limit <= (((calling_state = ABSORB_AD) and dcount_int < 11 ) or
           ((calling_state = ABSORB_MSG or calling_state = SQUEEZE) and dcount_int < 6) or
           (calling_state = ABSORB_HASH and dcount_int < 4));
    
    top_level_states: process(cyc_s, calling_state,
                            decrypt_op_s, decrypt_in,
                            bdo_s, bdo_ready,
                            state_type_match, rnd_input_limit,
                            bdi_valid, bdi_s,  bdi_valid_bytes_s, bdi_type, bdi_size, bdi_eot,
                            hash_in, gtr_one_perm,
                            rnd_counter_int, ins_counter_int, dcount_int,
                            mode,
                            key_update, key_valid, key_update_internal,
                            msg_auth_ready,
                            tag_verified)
    begin
      n_calling_state     <= calling_state;
      n_cyc_s             <= cyc_s;
      n_mode              <= mode;
      
      --default values
      key_ready_s         <= '0';
      key_update_internal_n <= key_update_internal;
      bdi_ready_s         <= '0';
      
      --state_ram_defaults
      din_sel       <= '0';   --defaults to xor_out
      addr_sel      <= "00";    --defaults to perm_addr
      ramwrite      <= '0';
      
      --cyc_ops_defaults
      cycd_sel      <= "00";
      cyc_state_update_sel<= "00";
      xor_sel       <= "00";    --defaults to bdi_data
      extract_sel     <= '0';     --xor_out
      cu_cd_s         <= (others => '0');
      
      --Defaults for counters
      en_dcount <= '0';
      en_ins    <= '0';
      en_rnd    <= '0';
      load_dcount <= '0';
      load_ins  <='0';
      load_rnd  <='0';
      ins_start_value <= (others => '0');
      dcount_start_value <= (others => '0');
      
      --output variables
      bdo_valid_bytes_s <= (others => '0');
      bdo_valid_s <= '0';
      bdo_type_s <= (others => '0');
      end_of_block <= '0';
      n_decrypt_op_s <= decrypt_op_s;
      
      n_msg_auth_valid_s <= '0';
      n_msg_auth_s <= '0';
      n_tag_verified <= '1';
      
      n_gtr_one_perm <= gtr_one_perm;
        
      
    case cyc_s is
    when IDLE =>
        n_tag_verified  <= '0';
        load_dcount <= '1';  --zero out the data counter
        load_ins <= '1';
        n_gtr_one_perm <= '0';
        key_update_internal_n <= '0' & key_update;
        if (key_valid = '1' or bdi_valid = '1') then
            if (hash_in = '1') then
                n_cyc_s <= INIT_HASH;
                n_mode <= HASH;
            else
                n_cyc_s <= STORE_KEY;
                n_mode <= KEYED;
                if (key_update /= '1') then
                    ins_start_value <= std_logic_vector(to_unsigned(load_key_ins_start, ins_start_value'length));
                end if;
            end if;
        end if;

    when INIT_HASH =>
        en_dcount <= '1';
        addr_sel <= "01"; -- select dcount
        xor_sel <= "01"; -- select ramout1
        cyc_state_update_sel <= "00";
        ramwrite <= '1';
        n_decrypt_op_s <= '0';
        if (dcount_int = STATE_WORDS - 1) then
            n_cyc_s <= CYC_DOWN;
            n_calling_state <= ABSORB_HASH;
            load_dcount <= '1';
        end if;

    when STORE_KEY =>
         if (key_update_internal = "01") then
            key_ready_s <= '1';
            addr_sel <= "01"; -- select dcount
            xor_sel <= "01"; -- select ramout1
            en_dcount <= '1';
            -- Filling up the first slots of state with pass in key
            if (dcount_int <= KEY_WORDS-1 and key_valid = '1') then
                cyc_state_update_sel <= "01";
                ramwrite <= '1';
            -- Writing the value of cd to the state
            elsif (dcount_int = KEY_WORDS) then
                cyc_state_update_sel <= "10";
                ramwrite <= '1';
            -- Writing zeros to the rest of the state
            else
                cyc_state_update_sel <= "00";
                ramwrite <= '1';
                if (dcount_int = STATE_WORDS-1) then
                    -- load dcount to write fbprime
                    load_dcount <= '1';
                    dcount_start_value <= "1011";
                    key_update_internal_n <= "10";
                end if;
            end if;
        elsif (key_update_internal = "10") then
           addr_sel <= "11"; -- select fbprime
           xor_sel <= "10"; -- select cu_cd
           cu_cd_s <= x"02";
           ramwrite <= '1';
           load_dcount <= '1';  --zero out the data counter
           load_ins <= '1';
           load_rnd <= '1';
           key_update_internal_n <= "00"; -- Key has been updated.
           n_cyc_s <= CYC_UP_PERM;
           n_calling_state <= STORE_KEY; 
        else -- Only need to read key state from memory
            en_dcount <= '1';
            en_ins <= '1';
            addr_sel <="00";
            din_sel <='1';
            ramwrite <= '1';
            -- Clear both of the signals to get ready for the next state
            if (dcount_int = STATE_WORDS_PERM_SIZE - 1) then
                load_dcount <= '1';
                n_cyc_s <= CYC_DOWN;
                n_calling_state <= ABSORB_NONCE;
                n_decrypt_op_s <= decrypt_in;
            end if;
        end if;

        
    when CYC_DOWN =>
        addr_sel <= "01";
        xor_sel <= "00";
        cycd_sel <= bdi_size(1 downto 0);
        if (calling_state = ABSORB_NONCE) then
            if bdi_valid = '1' then
                if dcount_int = 3 then
                    n_cyc_s <= CYC_ADD_BYTE;
                end if;
                bdi_ready_s <= '1';
                ramwrite <= '1';
                en_dcount <= '1';
            end if;
        elsif calling_state = ABSORB_AD or calling_state = ABSORB_HASH then
            if bdi_type = HDR_AD or bdi_type = "0000"  or bdi_type = HDR_HASH_MSG then
                if bdi_eot = '1' and bdi_size = "100" and bdi_valid = '1' then
                    bdi_ready_s <= '1';
                    ramwrite <= '1';
                    en_dcount <= '1';
                    n_cyc_s <= CYC_ADD_BYTE;
                elsif bdi_eot = '1' or key_valid = '1' then
                    n_cyc_s <= CYC_ADD_BYTE;
                elsif bdi_valid = '1' then
                    if dcount_int = 10  and calling_state = ABSORB_AD then
                        n_cyc_s <= CYC_ADD_BYTE;
                    elsif dcount_int = 3 and calling_state = ABSORB_HASH then
                        n_cyc_s <= CYC_ADD_BYTE;
                    end if;
                    bdi_ready_s <= '1';
                    ramwrite <= '1';
                    en_dcount <= '1';
                end if;
            else
                n_cyc_s <= CYC_ADD_BYTE;
            end if;
        else--if calling_state = ABSORB_MSG then
            bdo_valid_bytes_s <= bdi_valid_bytes_s;
            extract_sel <= '1';
            if bdi_type = HDR_MSG then
                bdo_type_s <= HDR_MSG;
            else
                bdo_type_s <= HDR_CT;
                cyc_state_update_sel <= "11";
            end if;
            if (dcount_int = TAG_SIZE_CW - 1 ) then
                end_of_block <= '1';
            end if;
            if bdi_type = HDR_MSG or bdi_type = HDR_CT or bdi_type = "0000" then
                if bdi_eot = '1' and bdi_size = "100" and bdi_valid = '1' and bdo_ready = '1' then
                    bdi_ready_s <= '1';
                    ramwrite <= '1';
                    en_dcount <= '1';
                    n_cyc_s <= CYC_ADD_BYTE;
                    bdo_valid_s <= '1';
                elsif (bdi_eot = '1' or key_valid = '1') and bdo_ready = '1' then
                    n_cyc_s <= CYC_ADD_BYTE;
                elsif bdi_valid = '1'  and bdo_ready = '1' then
                    if dcount_int = 5 then
                        n_cyc_s <= CYC_ADD_BYTE;
                    end if;
                    bdi_ready_s <= '1';
                    ramwrite <= '1';
                    en_dcount <= '1';
                    bdo_valid_s <= '1';
                end if;
            else
                n_cyc_s <= CYC_ADD_BYTE;
            end if;
        end if;
    when CYC_ADD_BYTE =>
        if bdi_valid = '1' and bdi_size(1 downto 0) /= "00" and rnd_input_limit  and state_type_match then
            bdi_ready_s <= '1';
            cycd_sel <= bdi_size(1 downto 0);
            if (bdi_type = HDR_MSG) then
                bdo_valid_s <= '1';
                bdo_valid_bytes_s <= bdi_valid_bytes_s;
                bdo_type_s <= HDR_MSG;
                extract_sel <= '1';
                if (dcount_int = TAG_SIZE_CW - 1 ) then
                    end_of_block <= '1';
                end if;
            elsif (bdi_type = HDR_CT) then
                bdo_valid_s <= '1';
                bdo_valid_bytes_s <= bdi_valid_bytes_s;
                bdo_type_s <= HDR_CT;
                extract_sel <= '1';
                cyc_state_update_sel <= "11";
            end if;
        else
            cycd_sel <= "00";
        end if;
        -- Handles the case transition of the hash message that is empty
        if (bdi_valid = '1' and bdi_size = "000" and bdi_type = "0111") then
            bdi_ready_s <= '1';
        end if;
        xor_sel <= "11";
        ramwrite <= '1';
        addr_sel <= "01";
        en_dcount <= '1';
        n_cyc_s <= CYC_DOWN_CD;
        load_dcount <= '1';
        dcount_start_value <= "1011";
    when CYC_DOWN_CD =>
        -- If the BDI types no longer match it is type to move on
        n_cyc_s <= CYC_UP_ADDBYTE;
        if state_type_match = False then
            n_gtr_one_perm <= '0';
            load_ins <= '1';
            load_rnd <= '1';
            load_dcount <= '1';
            dcount_start_value <= "1011";
            if (calling_state = ABSORB_NONCE) then
                n_calling_state <= ABSORB_AD;
            elsif (calling_state = ABSORB_AD) then
                n_calling_state <= ABSORB_MSG;
            else
                n_calling_state <= SQUEEZE;
            end if;
        else
            n_gtr_one_perm <= '1';
        end if;
        
        -- This only occurs on absorb first round for the following message types
        xor_sel <= "10";
        addr_sel <= "11";
        if gtr_one_perm = '0' then
            if calling_state = ABSORB_AD or calling_state = ABSORB_NONCE then
                cu_cd_s <= x"03";
                ramwrite <= '1';
            elsif (calling_state = ABSORB_HASH) then
                cu_cd_s <= x"01"; 
                ramwrite <= '1';
            end if;
        end if;

    when CYC_UP_ADDBYTE =>
        --Only ABSORB_MSG and SQUEEZE only are updated
        n_cyc_s <= CYC_UP_PERM;
        load_dcount <= '1';
        xor_sel <= "10"; --cu_cd
        addr_sel <= "11"; --F_BPRIME
        --Must be KEYED and only affected by first permutation
        if (mode = KEYED and gtr_one_perm = '0') then
            if (calling_state = SQUEEZE) then
                cu_cd_s <= x"40";
                ramwrite <='1';
            elsif (calling_state = ABSORB_MSG) then
                cu_cd_s <= x"80";
                ramwrite <='1';
            end if;
        end if;    
        
    when CYC_UP_PERM =>
        --In the permutation
        --Loop through NUM_INSTRUCTIONS and do it for NUM_ROUNDS
        ramwrite <= '1';
        addr_sel <= "00";
        din_sel <= '1';
        n_tag_verified <= '1';
        en_ins <= '1';
        if (ins_counter_int = NUM_INSTRUCTIONS-1) then
            en_rnd <='1';
            load_ins <='1';        
            if (rnd_counter_int = NUM_ROUNDS-1) then
                load_dcount <= '1';
                load_rnd <= '1';
                --Jump to CYC_DOWN_1 unless tag needs to be verified
                if (calling_state = SQUEEZE) then
                    n_cyc_s <= CYC_UP_EXTRACT;
                elsif (calling_state = STORE_KEY) then
                    n_cyc_s <= STORE_KEY;
                    ins_start_value <= std_logic_vector(to_unsigned(store_key_ins_start, ins_start_value'length));
                    load_ins <= '1';
                else
                    n_cyc_s <= CYC_DOWN;
                end if;
            end if;
        end if;
        
    when CYC_UP_EXTRACT =>
        addr_sel <= "01";
        -- performing encryption extract the tag and send it
        if (decrypt_op_s /= '1') then
            bdo_valid_s <= '1';
            bdo_valid_bytes_s <= (others => '1');
            bdo_type_s <= HDR_TAG;
            extract_sel <= '0';
            --Update counter if data if valid
            if (bdo_ready = '1') then
                en_dcount <= '1';
            end if;
            --Send end_of_block when TAG_SIZE_CW is reached
            if (dcount_int = TAG_SIZE_CW - 1 ) then
                end_of_block <= '1';
                n_cyc_s <= IDLE;
            end if; 
        else
            --Verify the TAG if not set the tag to not verified
            if bdi_valid = '1' and msg_auth_ready = '1' then
                bdi_ready_s <= '1';
                en_dcount <= '1';
                if (dcount_int = TAG_SIZE_CW - 1) then
                    n_msg_auth_valid_s <= '1';
                    n_cyc_s <= IDLE;
                    --Final TAG word did not match
                    if (bdi_s /= bdo_s) then
                        n_msg_auth_s <= '0';
                    else
                        --The final tag matched and if there other tags matched
                        --this will be true otherwise false
                        n_msg_auth_s <= tag_verified;
                    end if;
                else
                    --Prior to the final tag update tag_verified to false if they
                    --do nto match
                    if (bdi_s /= bdo_s) then
                        n_tag_verified <= '0';
                    end if;
                end if;
            end if;
        end if;
    end case;
  end process;
  

p_reg: process(clk)
    begin
        if rising_edge(clk) then
            if (rst = '1') then
                cyc_s               <= IDLE;
                mode                <= HASH;
                msg_auth            <= '0';
                msg_auth_valid      <= '0';
                tag_verified        <= '0';
                calling_state       <= ABSORB_NONCE;
                gtr_one_perm        <= '0';
                decrypt_op_s        <= '0';
            else
                cyc_s               <= n_cyc_s;
                mode                <= n_mode;
                key_update_internal <= key_update_internal_n;
                tag_verified        <= n_tag_verified;
                msg_auth_valid      <= n_msg_auth_valid_s;
                msg_auth            <= n_msg_auth_s;
                calling_state       <= n_calling_state;
                gtr_one_perm        <= n_gtr_one_perm;
                decrypt_op_s        <= n_decrypt_op_s;
            end if;
        end if;
    end process p_reg;
end behavioral;
