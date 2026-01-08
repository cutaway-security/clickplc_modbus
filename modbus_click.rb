##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/cutaway-security/click-plc-scanner
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'CLICK PLC Modbus Scanner',
        'Description' => %q{
          This module reads data from AutomationDirect CLICK PLCs via Modbus TCP.
          It supports CLICK-specific address types including discrete inputs (X),
          coil outputs (Y), control relays (C), and data registers (DS, DD, DF).
          The module also reads device information from system data registers (SD)
          including firmware version, IP address, and MAC address.

          This module performs READ-ONLY operations using Modbus function codes
          01 (Read Coils), 02 (Read Discrete Inputs), 03 (Read Holding Registers),
          and 04 (Read Input Registers).

          Byte Order Notes:
          - Modbus registers are transmitted in network byte order (big-endian per word)
          - CLICK PLCs use little-endian word order for 32-bit values (low word first)
          - DD (INT32) and DF (FLOAT) registers span two consecutive 16-bit registers
          - This module handles the word-swap automatically for correct interpretation
        },
        'Author' => [
          'Don C. Weber (cutaway)',  # Module author
          'Cutaway Security, LLC'    # Organization
        ],
        'References' => [
          ['URL', 'https://github.com/cutaway-security/click-plc-scanner'],
          ['URL', 'https://www.automationdirect.com/adc/overview/catalog/programmable_controllers/click_series_plcs'],
          ['URL', 'https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf']
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        },
        'Actions' => [
          ['READ_INPUTS', { 'Description' => 'Read X0 discrete inputs (FC 02)' }],
          ['READ_OUTPUTS', { 'Description' => 'Read Y0 coil outputs (FC 01)' }],
          ['READ_CONTROL_RELAYS', { 'Description' => 'Read C control relays (FC 01)' }],
          ['READ_DS', { 'Description' => 'Read DS registers as INT16 (FC 03)' }],
          ['READ_DD', { 'Description' => 'Read DD registers as INT32 (FC 03)' }],
          ['READ_DF', { 'Description' => 'Read DF registers as FLOAT (FC 03)' }],
          ['READ_DEVICE_INFO', { 'Description' => 'Read device info from SD registers' }],
          ['SCAN_COMMON', { 'Description' => 'Scan common address types' }]
        ],
        'DefaultAction' => 'READ_DEVICE_INFO'
      )
    )

    register_options(
      [
        Opt::RPORT(502),
        OptInt.new('UNIT_ID', [true, 'Modbus Unit ID', 0]),
        OptInt.new('ADDRESS_START', [false, 'Start address override (0-based)']),
        OptInt.new('ADDRESS_COUNT', [false, 'Number of addresses to read']),
        OptInt.new('TIMEOUT', [true, 'Socket timeout in seconds', 2])
      ]
    )
  end

  # CLICK PLC Address Type Definitions
  # Maps address types to their Modbus parameters
  CLICK_ADDRESSES = {
    'X0' => {
      name: 'CPU Discrete Inputs',
      fc: 2,                    # Read Discrete Inputs
      start: 0x0000,
      default_count: 36,
      data_type: :bool,
      description: 'Physical input points on CPU module'
    },
    'Y0' => {
      name: 'CPU Discrete Outputs',
      fc: 1,                    # Read Coils
      start: 0x2000,
      default_count: 36,
      data_type: :bool,
      description: 'Physical output points on CPU module'
    },
    'C' => {
      name: 'Control Relays',
      fc: 1,                    # Read Coils
      start: 0x4000,
      default_count: 100,
      data_type: :bool,
      description: 'Internal control relay bits'
    },
    'DS' => {
      name: 'Data Registers (INT16)',
      fc: 3,                    # Read Holding Registers
      start: 0x0000,
      default_count: 20,
      data_type: :int16,
      description: 'Signed 16-bit integer registers'
    },
    'DD' => {
      name: 'Data Registers (INT32)',
      fc: 3,                    # Read Holding Registers
      start: 0x4000,
      default_count: 10,
      data_type: :int32,
      words_per_value: 2,
      description: 'Signed 32-bit integer registers (little-endian word order)'
    },
    'DF' => {
      name: 'Data Registers (FLOAT)',
      fc: 3,                    # Read Holding Registers
      start: 0x7000,
      default_count: 10,
      data_type: :float,
      words_per_value: 2,
      description: 'IEEE 754 single precision float registers'
    },
    'SD' => {
      name: 'System Data Registers',
      fc: 4,                    # Read Input Registers (some are FC 03)
      start: 0xF000,
      default_count: 20,
      data_type: :int16,
      description: 'System status and configuration registers'
    }
  }.freeze

  # System Data Register locations for device information
  SD_DEVICE_INFO = {
    firmware: { start: 0xF004, count: 4, description: 'Firmware Version (SD5-SD8)' },
    ip_address: { start: 0xF04F, count: 4, description: 'IP Address (SD80-SD83)' },
    subnet_mask: { start: 0xF053, count: 4, description: 'Subnet Mask (SD84-SD87)' },
    gateway: { start: 0xF057, count: 4, description: 'Gateway (SD88-SD91)' },
    mac_address: { start: 0xF0BB, count: 6, description: 'MAC Address (SD188-SD193)' }
  }.freeze

  # Transaction ID counter for Modbus TCP
  def initialize_transaction_id
    @transaction_id = rand(0xFFFF)
  end

  def next_transaction_id
    @transaction_id = (@transaction_id + 1) & 0xFFFF
    @transaction_id
  end

  # Build Modbus TCP request frame
  # MBAP Header (7 bytes) + PDU
  def build_modbus_request(unit_id, function_code, start_address, quantity)
    transaction_id = next_transaction_id
    protocol_id = 0x0000  # Modbus protocol

    # PDU: Function Code (1) + Start Address (2) + Quantity (2)
    pdu = [function_code, start_address, quantity].pack('Cnn')
    length = pdu.length + 1  # PDU + Unit ID

    # MBAP Header: Transaction ID (2) + Protocol ID (2) + Length (2) + Unit ID (1)
    mbap = [transaction_id, protocol_id, length, unit_id].pack('nnnC')

    mbap + pdu
  end

  # Parse Modbus TCP response
  def parse_modbus_response(data, expected_fc)
    return nil if data.nil? || data.length < 9

    # Parse MBAP header
    transaction_id, protocol_id, length, unit_id = data[0, 7].unpack('nnnC')

    # Check protocol ID
    return nil unless protocol_id == 0x0000

    # Parse PDU
    function_code = data[7].ord

    # Check for exception response (FC + 0x80)
    if function_code == (expected_fc | 0x80)
      exception_code = data[8].ord
      return { error: true, exception: exception_code, message: modbus_exception_message(exception_code) }
    end

    # Verify function code
    return nil unless function_code == expected_fc

    # Parse response data based on function code
    case function_code
    when 1, 2  # Read Coils / Read Discrete Inputs
      byte_count = data[8].ord
      coil_data = data[9, byte_count]
      { error: false, data: coil_data, byte_count: byte_count }
    when 3, 4  # Read Holding Registers / Read Input Registers
      byte_count = data[8].ord
      register_data = data[9, byte_count]
      { error: false, data: register_data, byte_count: byte_count }
    else
      nil
    end
  end

  # Modbus exception code descriptions
  def modbus_exception_message(code)
    messages = {
      1 => 'Illegal Function',
      2 => 'Illegal Data Address',
      3 => 'Illegal Data Value',
      4 => 'Slave Device Failure',
      5 => 'Acknowledge',
      6 => 'Slave Device Busy',
      8 => 'Memory Parity Error',
      10 => 'Gateway Path Unavailable',
      11 => 'Gateway Target Device Failed to Respond'
    }
    messages[code] || "Unknown Exception (#{code})"
  end

  # Send Modbus request and receive response
  def send_modbus_request(unit_id, function_code, start_address, quantity)
    request = build_modbus_request(unit_id, function_code, start_address, quantity)

    begin
      sock.put(request)
      response = sock.get_once(-1, datastore['TIMEOUT'])
      parse_modbus_response(response, function_code)
    rescue ::Rex::ConnectionError, ::EOFError, ::Timeout::Error => e
      { error: true, message: "Communication error: #{e.message}" }
    end
  end

  # Read coils or discrete inputs (FC 01 or FC 02)
  def read_coils(unit_id, function_code, start_address, count)
    result = send_modbus_request(unit_id, function_code, start_address, count)
    return result if result.nil? || result[:error]

    # Convert byte data to bit array
    bits = []
    result[:data].each_byte do |byte|
      8.times do |i|
        bits << ((byte >> i) & 1)
        break if bits.length >= count
      end
    end

    result[:bits] = bits[0, count]
    result
  end

  # Read registers (FC 03 or FC 04)
  def read_registers(unit_id, function_code, start_address, count)
    send_modbus_request(unit_id, function_code, start_address, count)
  end

  # Convert register data to INT16 values
  def convert_to_int16(data)
    values = []
    (0...data.length).step(2) do |i|
      break if i + 1 >= data.length
      # Big-endian (network byte order) for Modbus registers
      raw = data[i, 2].unpack('n')[0]
      # Convert to signed
      value = raw > 0x7FFF ? raw - 0x10000 : raw
      values << value
    end
    values
  end

  # Convert register data to INT32 values (little-endian word order for CLICK)
  def convert_to_int32(data)
    values = []
    (0...data.length).step(4) do |i|
      break if i + 3 >= data.length
      # CLICK uses little-endian word order: low word first, then high word
      low_word = data[i, 2].unpack('n')[0]
      high_word = data[i + 2, 2].unpack('n')[0]
      raw = (high_word << 16) | low_word
      # Convert to signed
      value = raw > 0x7FFFFFFF ? raw - 0x100000000 : raw
      values << value
    end
    values
  end

  # Convert register data to FLOAT values (IEEE 754, little-endian word order)
  # CLICK PLC sends: Word1=low_word, Word2=high_word (little-endian word order)
  # Pack as big-endian (high, low) then interpret as big-endian float for correct IEEE 754
  def convert_to_float(data)
    values = []
    (0...data.length).step(4) do |i|
      break if i + 3 >= data.length
      # Extract words (each word is big-endian per Modbus spec)
      low_word = data[i, 2].unpack('n')[0]
      high_word = data[i + 2, 2].unpack('n')[0]
      # Pack as big-endian 16-bit values (high first, low second) and interpret as big-endian float
      # 'n' = network byte order (big-endian) 16-bit, 'g' = big-endian single-precision float
      value = [high_word, low_word].pack('nn').unpack('g')[0]
      values << value
    end
    values
  end

  # Format coil/input bits for display
  def format_bits(bits, prefix, start_num = 1)
    output = []
    bits.each_with_index do |bit, idx|
      addr = format('%s%03d', prefix, start_num + idx)
      output << "#{addr}: #{bit}"
    end
    output
  end

  # Format IP address from 4 register values
  def format_ip_from_registers(values)
    return 'N/A' if values.nil? || values.length < 4
    values[0, 4].map { |v| v & 0xFF }.join('.')
  end

  # Format MAC address from 6 register values
  def format_mac_from_registers(values)
    return 'N/A' if values.nil? || values.length < 6
    values[0, 6].map { |v| format('%02X', v & 0xFF) }.join(':')
  end

  # Format firmware version from register values
  # CLICK stores firmware as: SD5=minor (low byte), SD6=major (low byte)
  def format_firmware_from_registers(values)
    return 'N/A' if values.nil? || values.length < 2
    minor = values[0] & 0xFF
    major = values[1] & 0xFF
    "#{major}.#{minor}"
  end

  # Action: Read discrete inputs (X0)
  def action_read_inputs(ip)
    addr_info = CLICK_ADDRESSES['X0']
    start = datastore['ADDRESS_START'] || addr_info[:start]
    count = datastore['ADDRESS_COUNT'] || addr_info[:default_count]

    print_status("#{ip}:#{rport} - Reading X0 discrete inputs (#{count} points from 0x#{start.to_s(16).upcase.rjust(4, '0')})...")

    result = read_coils(datastore['UNIT_ID'], addr_info[:fc], start, count)

    if result.nil?
      print_error("#{ip}:#{rport} - No response received")
      return
    end

    if result[:error]
      print_error("#{ip}:#{rport} - #{result[:message]}")
      return
    end

    # Display results
    result[:bits].each_with_index do |bit, idx|
      addr = format('X%03d', idx + 1)
      print_good("#{ip}:#{rport} - #{addr}: #{bit == 1 ? 'ON' : 'OFF'}")

      report_note(
        host: ip,
        proto: 'tcp',
        port: rport,
        sname: 'modbus',
        type: 'modbus.click.x0',
        data: { address: addr, value: bit, state: bit == 1 ? 'ON' : 'OFF' }
      )
    end
  end

  # Action: Read coil outputs (Y0)
  def action_read_outputs(ip)
    addr_info = CLICK_ADDRESSES['Y0']
    start = datastore['ADDRESS_START'] || addr_info[:start]
    count = datastore['ADDRESS_COUNT'] || addr_info[:default_count]

    print_status("#{ip}:#{rport} - Reading Y0 coil outputs (#{count} points from 0x#{start.to_s(16).upcase.rjust(4, '0')})...")

    result = read_coils(datastore['UNIT_ID'], addr_info[:fc], start, count)

    if result.nil?
      print_error("#{ip}:#{rport} - No response received")
      return
    end

    if result[:error]
      print_error("#{ip}:#{rport} - #{result[:message]}")
      return
    end

    result[:bits].each_with_index do |bit, idx|
      addr = format('Y%03d', idx + 1)
      print_good("#{ip}:#{rport} - #{addr}: #{bit == 1 ? 'ON' : 'OFF'}")

      report_note(
        host: ip,
        proto: 'tcp',
        port: rport,
        sname: 'modbus',
        type: 'modbus.click.y0',
        data: { address: addr, value: bit, state: bit == 1 ? 'ON' : 'OFF' }
      )
    end
  end

  # Action: Read control relays (C)
  def action_read_control_relays(ip)
    addr_info = CLICK_ADDRESSES['C']
    start = datastore['ADDRESS_START'] || addr_info[:start]
    count = datastore['ADDRESS_COUNT'] || addr_info[:default_count]

    print_status("#{ip}:#{rport} - Reading C control relays (#{count} points from 0x#{start.to_s(16).upcase.rjust(4, '0')})...")

    result = read_coils(datastore['UNIT_ID'], addr_info[:fc], start, count)

    if result.nil?
      print_error("#{ip}:#{rport} - No response received")
      return
    end

    if result[:error]
      print_error("#{ip}:#{rport} - #{result[:message]}")
      return
    end

    result[:bits].each_with_index do |bit, idx|
      addr = format('C%d', idx + 1)
      print_good("#{ip}:#{rport} - #{addr}: #{bit == 1 ? 'ON' : 'OFF'}")

      report_note(
        host: ip,
        proto: 'tcp',
        port: rport,
        sname: 'modbus',
        type: 'modbus.click.c',
        data: { address: addr, value: bit, state: bit == 1 ? 'ON' : 'OFF' }
      )
    end
  end

  # Action: Read DS registers (INT16)
  def action_read_ds(ip)
    addr_info = CLICK_ADDRESSES['DS']
    start = datastore['ADDRESS_START'] || addr_info[:start]
    count = datastore['ADDRESS_COUNT'] || addr_info[:default_count]

    print_status("#{ip}:#{rport} - Reading DS registers (#{count} registers from 0x#{start.to_s(16).upcase.rjust(4, '0')})...")

    result = read_registers(datastore['UNIT_ID'], addr_info[:fc], start, count)

    if result.nil?
      print_error("#{ip}:#{rport} - No response received")
      return
    end

    if result[:error]
      print_error("#{ip}:#{rport} - #{result[:message]}")
      return
    end

    values = convert_to_int16(result[:data])
    values.each_with_index do |value, idx|
      addr = format('DS%d', idx + 1)
      hex_val = format('0x%04X', value & 0xFFFF)
      print_good("#{ip}:#{rport} - #{addr}: #{value} (#{hex_val})")

      report_note(
        host: ip,
        proto: 'tcp',
        port: rport,
        sname: 'modbus',
        type: 'modbus.click.ds',
        data: { address: addr, value: value, raw: hex_val }
      )
    end
  end

  # Action: Read DD registers (INT32)
  def action_read_dd(ip)
    addr_info = CLICK_ADDRESSES['DD']
    start = datastore['ADDRESS_START'] || addr_info[:start]
    count = datastore['ADDRESS_COUNT'] || addr_info[:default_count]
    words_to_read = count * addr_info[:words_per_value]

    print_status("#{ip}:#{rport} - Reading DD registers (#{count} registers from 0x#{start.to_s(16).upcase.rjust(4, '0')})...")

    result = read_registers(datastore['UNIT_ID'], addr_info[:fc], start, words_to_read)

    if result.nil?
      print_error("#{ip}:#{rport} - No response received")
      return
    end

    if result[:error]
      print_error("#{ip}:#{rport} - #{result[:message]}")
      return
    end

    values = convert_to_int32(result[:data])
    values.each_with_index do |value, idx|
      addr = format('DD%d', idx + 1)
      hex_val = format('0x%08X', value & 0xFFFFFFFF)
      print_good("#{ip}:#{rport} - #{addr}: #{value} (#{hex_val})")

      report_note(
        host: ip,
        proto: 'tcp',
        port: rport,
        sname: 'modbus',
        type: 'modbus.click.dd',
        data: { address: addr, value: value, raw: hex_val }
      )
    end
  end

  # Action: Read DF registers (FLOAT)
  def action_read_df(ip)
    addr_info = CLICK_ADDRESSES['DF']
    start = datastore['ADDRESS_START'] || addr_info[:start]
    count = datastore['ADDRESS_COUNT'] || addr_info[:default_count]
    words_to_read = count * addr_info[:words_per_value]

    print_status("#{ip}:#{rport} - Reading DF registers (#{count} registers from 0x#{start.to_s(16).upcase.rjust(4, '0')})...")

    result = read_registers(datastore['UNIT_ID'], addr_info[:fc], start, words_to_read)

    if result.nil?
      print_error("#{ip}:#{rport} - No response received")
      return
    end

    if result[:error]
      print_error("#{ip}:#{rport} - #{result[:message]}")
      return
    end

    values = convert_to_float(result[:data])
    values.each_with_index do |value, idx|
      addr = format('DF%d', idx + 1)
      # Format float with reasonable precision
      formatted = value.finite? ? format('%.6g', value) : value.to_s
      print_good("#{ip}:#{rport} - #{addr}: #{formatted}")

      report_note(
        host: ip,
        proto: 'tcp',
        port: rport,
        sname: 'modbus',
        type: 'modbus.click.df',
        data: { address: addr, value: value }
      )
    end
  end

  # Action: Read device information from SD registers
  def action_read_device_info(ip)
    print_status("#{ip}:#{rport} - Reading device information from SD registers...")

    device_info = {}

    # Read firmware version (SD5-SD8)
    info = SD_DEVICE_INFO[:firmware]
    result = read_registers(datastore['UNIT_ID'], 4, info[:start], info[:count])
    if result && !result[:error]
      values = convert_to_int16(result[:data])
      device_info[:firmware] = format_firmware_from_registers(values)
      print_good("#{ip}:#{rport} - Firmware Version: #{device_info[:firmware]}")
    else
      print_error("#{ip}:#{rport} - Failed to read firmware version")
    end

    # Read IP address (SD80-SD83)
    info = SD_DEVICE_INFO[:ip_address]
    result = read_registers(datastore['UNIT_ID'], 4, info[:start], info[:count])
    if result && !result[:error]
      values = convert_to_int16(result[:data])
      device_info[:ip_address] = format_ip_from_registers(values)
      print_good("#{ip}:#{rport} - IP Address: #{device_info[:ip_address]}")
    else
      print_error("#{ip}:#{rport} - Failed to read IP address")
    end

    # Read subnet mask (SD84-SD87)
    info = SD_DEVICE_INFO[:subnet_mask]
    result = read_registers(datastore['UNIT_ID'], 4, info[:start], info[:count])
    if result && !result[:error]
      values = convert_to_int16(result[:data])
      device_info[:subnet_mask] = format_ip_from_registers(values)
      print_good("#{ip}:#{rport} - Subnet Mask: #{device_info[:subnet_mask]}")
    else
      print_error("#{ip}:#{rport} - Failed to read subnet mask")
    end

    # Read gateway (SD88-SD91)
    info = SD_DEVICE_INFO[:gateway]
    result = read_registers(datastore['UNIT_ID'], 4, info[:start], info[:count])
    if result && !result[:error]
      values = convert_to_int16(result[:data])
      device_info[:gateway] = format_ip_from_registers(values)
      print_good("#{ip}:#{rport} - Gateway: #{device_info[:gateway]}")
    else
      print_error("#{ip}:#{rport} - Failed to read gateway")
    end

    # Read MAC address (SD188-SD193)
    info = SD_DEVICE_INFO[:mac_address]
    result = read_registers(datastore['UNIT_ID'], 4, info[:start], info[:count])
    if result && !result[:error]
      values = convert_to_int16(result[:data])
      device_info[:mac_address] = format_mac_from_registers(values)
      print_good("#{ip}:#{rport} - MAC Address: #{device_info[:mac_address]}")
    else
      print_error("#{ip}:#{rport} - Failed to read MAC address")
    end

    # Report device info to database
    unless device_info.empty?
      report_note(
        host: ip,
        proto: 'tcp',
        port: rport,
        sname: 'modbus',
        type: 'modbus.click.device_info',
        data: device_info
      )

      # Also report as a service
      report_service(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: 'modbus',
        info: "CLICK PLC - Firmware: #{device_info[:firmware] || 'Unknown'}"
      )
    end
  end

  # Action: Scan common address types
  def action_scan_common(ip)
    print_status("#{ip}:#{rport} - Scanning common CLICK address types...")

    # Read device info first
    action_read_device_info(ip)

    print_status("#{ip}:#{rport} - ")

    # Read X0 inputs (limited to 10 for overview)
    saved_count = datastore['ADDRESS_COUNT']
    datastore['ADDRESS_COUNT'] = 10
    action_read_inputs(ip)

    print_status("#{ip}:#{rport} - ")

    # Read Y0 outputs
    action_read_outputs(ip)

    print_status("#{ip}:#{rport} - ")

    # Read DS registers
    action_read_ds(ip)

    print_status("#{ip}:#{rport} - ")

    # Read DD registers
    datastore['ADDRESS_COUNT'] = 5
    action_read_dd(ip)

    print_status("#{ip}:#{rport} - ")

    # Read DF registers
    action_read_df(ip)

    # Restore original count
    datastore['ADDRESS_COUNT'] = saved_count
  end

  # Main execution method for scanner
  def run_host(ip)
    initialize_transaction_id

    begin
      connect

      case action.name
      when 'READ_INPUTS'
        action_read_inputs(ip)
      when 'READ_OUTPUTS'
        action_read_outputs(ip)
      when 'READ_CONTROL_RELAYS'
        action_read_control_relays(ip)
      when 'READ_DS'
        action_read_ds(ip)
      when 'READ_DD'
        action_read_dd(ip)
      when 'READ_DF'
        action_read_df(ip)
      when 'READ_DEVICE_INFO'
        action_read_device_info(ip)
      when 'SCAN_COMMON'
        action_scan_common(ip)
      else
        print_error("#{ip}:#{rport} - Unknown action: #{action.name}")
      end

    rescue ::Rex::ConnectionError => e
      print_error("#{ip}:#{rport} - Connection failed: #{e.message}")
    rescue ::Timeout::Error
      print_error("#{ip}:#{rport} - Connection timeout")
    rescue ::Interrupt
      print_error("#{ip}:#{rport} - Interrupted")
      raise $ERROR_INFO
    ensure
      disconnect
    end
  end

  def cleanup
    disconnect rescue nil
  end
end
