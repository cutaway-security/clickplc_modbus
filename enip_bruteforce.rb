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
        'Name' => 'EtherNet/IP CIP Object Enumerator',
        'Description' => %q{
          *** WARNING: FOR AUTHORIZED LAB/TEST ENVIRONMENTS ONLY ***

          This module enumerates CIP (Common Industrial Protocol) objects on EtherNet/IP
          devices by attempting to read attributes from various class/instance combinations.
          It can discover supported CIP objects, their instances, and readable attributes.

          IMPORTANT SAFETY NOTICE:
          - This module sends many CIP requests which may impact device performance
          - Some industrial devices may behave unexpectedly under enumeration load
          - NEVER run against production ICS/SCADA systems without explicit authorization
          - Use rate limiting (DELAY option) in sensitive environments
          - Test in isolated lab environments first

          The module supports scanning known common CIP objects or brute-forcing ranges
          of class IDs, instance IDs, and attribute IDs.

          This module performs READ-ONLY operations using CIP Get Attribute Single (0x0E).
        },
        'Author' => [
          'Don C. Weber (cutaway)',  # Module author
          'Cutaway Security, LLC'    # Organization
        ],
        'References' => [
          ['URL', 'https://github.com/cutaway-security/click-plc-scanner'],
          ['URL', 'https://www.odva.org/technology-standards/key-technologies/common-industrial-protocol-cip/'],
          ['URL', 'https://literature.rockwellautomation.com/idc/groups/literature/documents/pm/1756-pm020_-en-p.pdf']
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        },
        'Actions' => [
          ['KNOWN_OBJECTS', { 'Description' => 'Scan only well-known CIP objects (safest)' }],
          ['ENUMERATE_CLASSES', { 'Description' => 'Scan range of class IDs for supported classes' }],
          ['ENUMERATE_INSTANCES', { 'Description' => 'Scan instance range for specific class' }],
          ['ENUMERATE_ATTRIBUTES', { 'Description' => 'Scan attribute range for class/instance' }],
          ['FULL_ENUMERATION', { 'Description' => 'Comprehensive scan (use with caution)' }]
        ],
        'DefaultAction' => 'KNOWN_OBJECTS'
      )
    )

    register_options(
      [
        Opt::RPORT(44818),
        OptInt.new('TIMEOUT', [true, 'Socket timeout in seconds', 5]),
        OptInt.new('DELAY', [true, 'Delay between requests in milliseconds', 100]),
        OptInt.new('CLASS_START', [true, 'Starting class ID for enumeration', 1]),
        OptInt.new('CLASS_END', [true, 'Ending class ID for enumeration', 255]),
        OptInt.new('INSTANCE_START', [true, 'Starting instance ID', 0]),
        OptInt.new('INSTANCE_END', [true, 'Ending instance ID', 10]),
        OptInt.new('ATTRIBUTE_START', [true, 'Starting attribute ID', 1]),
        OptInt.new('ATTRIBUTE_END', [true, 'Ending attribute ID', 20]),
        OptInt.new('TARGET_CLASS', [false, 'Specific class ID for instance/attribute enumeration']),
        OptInt.new('TARGET_INSTANCE', [false, 'Specific instance ID for attribute enumeration'])
      ]
    )
  end

  # ENIP Encapsulation Commands
  ENIP_CMD_REGISTER_SESSION = 0x0065
  ENIP_CMD_UNREGISTER_SESSION = 0x0066
  ENIP_CMD_SEND_RR_DATA = 0x006F

  # CIP Services
  CIP_GET_ATTRIBUTE_SINGLE = 0x0E
  CIP_GET_ATTRIBUTE_ALL = 0x01

  # CPF Item Types
  CPF_NULL_ADDRESS = 0x0000
  CPF_UNCONNECTED_DATA = 0x00B2

  # CIP General Status Codes
  CIP_STATUS = {
    0x00 => 'Success',
    0x01 => 'Connection failure',
    0x02 => 'Resource unavailable',
    0x03 => 'Invalid parameter value',
    0x04 => 'Path segment error',
    0x05 => 'Path destination unknown',
    0x06 => 'Partial transfer',
    0x07 => 'Connection lost',
    0x08 => 'Service not supported',
    0x09 => 'Invalid attribute value',
    0x0A => 'Attribute list error',
    0x0B => 'Already in requested mode/state',
    0x0C => 'Object state conflict',
    0x0D => 'Object already exists',
    0x0E => 'Attribute not settable',
    0x0F => 'Privilege violation',
    0x10 => 'Device state conflict',
    0x11 => 'Reply data too large',
    0x12 => 'Fragmentation of primitive',
    0x13 => 'Not enough data',
    0x14 => 'Attribute not supported',
    0x15 => 'Too much data',
    0x16 => 'Object does not exist',
    0x17 => 'Service fragmentation sequence not in progress',
    0x18 => 'No stored attribute data',
    0x19 => 'Store operation failure',
    0x1A => 'Routing failure, request packet too large',
    0x1B => 'Routing failure, response packet too large',
    0x1C => 'Missing attribute list entry data',
    0x1D => 'Invalid attribute value list',
    0x1E => 'Embedded service error',
    0x1F => 'Vendor specific error',
    0x20 => 'Invalid parameter',
    0x21 => 'Write-once value or medium already written',
    0x22 => 'Invalid reply received',
    0x25 => 'Key failure in path',
    0x26 => 'Path size invalid',
    0x27 => 'Unexpected attribute in list',
    0x28 => 'Invalid Member ID',
    0x29 => 'Member not settable',
    0x2A => 'Group 2 only server general failure',
    0xFF => 'Unknown error'
  }.freeze

  # Common Vendor IDs (subset for display purposes)
  VENDOR_IDS = {
    1 => 'Rockwell Automation/Allen-Bradley',
    2 => 'Namco Controls Corp.',
    3 => 'Honeywell Inc.',
    5 => 'Rockwell Automation/Reliance Elec.',
    46 => 'ABB Industrial Systems',
    47 => 'Omron Corporation',
    50 => 'Real Time Automation',
    82 => 'Mitsubishi Electric',
    108 => 'Beckhoff Automation GmbH',
    109 => 'National Instruments',
    145 => 'Siemens',
    243 => 'Schneider Automation',
    326 => 'GE Fanuc',
    482 => 'Koyo Electronics (AutomationDirect)',
    660 => 'Automationdirect.com',
    898 => 'AutomationDirect'
  }.freeze

  # Common Device Types
  DEVICE_TYPES = {
    0 => 'Generic Device (deprecated)',
    2 => 'AC Drive',
    7 => 'General Purpose Discrete I/O',
    12 => 'Communications Adapter',
    14 => 'Programmable Logic Controller',
    24 => 'Human-Machine Interface',
    43 => 'Generic Device (keyable)'
  }.freeze

  # Well-known CIP Object Classes
  KNOWN_CLASSES = {
    0x01 => {
      name: 'Identity Object',
      instances: [1],
      attributes: [1, 2, 3, 4, 5, 6, 7],
      attr_names: {
        1 => 'Vendor ID',
        2 => 'Device Type',
        3 => 'Product Code',
        4 => 'Revision',
        5 => 'Status',
        6 => 'Serial Number',
        7 => 'Product Name'
      }
    },
    0x02 => {
      name: 'Message Router',
      instances: [1],
      attributes: [1, 2],
      attr_names: {
        1 => 'Object List',
        2 => 'Max Connections'
      }
    },
    0x04 => {
      name: 'Assembly Object',
      instances: [100, 101, 102, 103, 104, 105, 150, 151],
      attributes: [3],
      attr_names: {
        3 => 'Data'
      }
    },
    0x06 => {
      name: 'Connection Manager',
      instances: [1],
      attributes: [1, 2, 3],
      attr_names: {
        1 => 'Open Requests',
        2 => 'Open Format Rejects',
        3 => 'Open Resource Rejects'
      }
    },
    0xF4 => {
      name: 'Port Object',
      instances: [1, 2, 3, 4],
      attributes: [1, 2, 3, 4, 7],
      attr_names: {
        1 => 'Port Type',
        2 => 'Port Number',
        3 => 'Link Object',
        4 => 'Port Name',
        7 => 'Port Node Address'
      }
    },
    0xF5 => {
      name: 'TCP/IP Interface Object',
      instances: [1],
      attributes: [1, 2, 3, 4, 5, 6],
      attr_names: {
        1 => 'Status',
        2 => 'Configuration Capability',
        3 => 'Configuration Control',
        4 => 'Physical Link Object',
        5 => 'Interface Configuration',
        6 => 'Host Name'
      }
    },
    0xF6 => {
      name: 'Ethernet Link Object',
      instances: [1, 2, 3, 4],
      attributes: [1, 2, 3, 4, 5, 6, 10],
      attr_names: {
        1 => 'Interface Speed',
        2 => 'Interface Flags',
        3 => 'Physical Address',
        4 => 'Interface Counters',
        5 => 'Media Counters',
        6 => 'Interface Control',
        10 => 'Interface Label'
      }
    }
  }.freeze

  # Session handle for CIP explicit messaging
  attr_accessor :session_handle

  # Build ENIP encapsulation header
  def build_enip_header(command, length, session = 0)
    header = [command, length, session, 0].pack('vvVV')
    header += "\x00" * 8  # Sender Context
    header += [0].pack('V')  # Options
    header
  end

  # Register Session with ENIP device
  def register_session
    # Register Session command with protocol version 1, options flags 0
    data = [1, 0].pack('vv')
    packet = build_enip_header(ENIP_CMD_REGISTER_SESSION, data.length, 0) + data

    sock.put(packet)
    response = sock.get_once(-1, datastore['TIMEOUT'])

    return nil unless response && response.length >= 28

    # Parse response
    command = response[0, 2].unpack('v')[0]
    status = response[8, 4].unpack('V')[0]
    @session_handle = response[4, 4].unpack('V')[0]

    if status != 0
      vprint_error("Register Session failed with status: 0x#{status.to_s(16)}")
      return nil
    end

    vprint_status("Session registered: 0x#{@session_handle.to_s(16).rjust(8, '0')}")
    @session_handle
  end

  # Unregister Session
  def unregister_session
    return unless @session_handle

    packet = build_enip_header(ENIP_CMD_UNREGISTER_SESSION, 0, @session_handle)
    sock.put(packet) rescue nil
    @session_handle = nil
  end

  # Build CIP path for class/instance/attribute
  def build_cip_path(class_id, instance_id, attribute_id = nil)
    path = ''

    # Class segment
    if class_id <= 0xFF
      path += [0x20, class_id].pack('CC')  # 8-bit class
    else
      path += [0x21, 0, class_id].pack('CCV')[0, 4]  # 16-bit class
    end

    # Instance segment
    if instance_id <= 0xFF
      path += [0x24, instance_id].pack('CC')  # 8-bit instance
    else
      path += [0x25, 0, instance_id].pack('CCv')  # 16-bit instance
    end

    # Attribute segment (optional)
    if attribute_id
      if attribute_id <= 0xFF
        path += [0x30, attribute_id].pack('CC')  # 8-bit attribute
      else
        path += [0x31, 0, attribute_id].pack('CCv')  # 16-bit attribute
      end
    end

    path
  end

  # Build CIP Unconnected Send message
  def build_cip_request(service, class_id, instance_id, attribute_id = nil)
    path = build_cip_path(class_id, instance_id, attribute_id)
    path_size = path.length / 2

    # CIP request: Service (1) + Path Size (1) + Path (variable)
    cip_request = [service, path_size].pack('CC') + path

    # CPF (Common Packet Format): 2 items
    # Item 1: Null Address (type 0x0000, length 0)
    # Item 2: Unconnected Data (type 0x00B2, length = CIP request length)
    cpf = [2].pack('v')  # Item count
    cpf += [CPF_NULL_ADDRESS, 0].pack('vv')  # Null address item
    cpf += [CPF_UNCONNECTED_DATA, cip_request.length].pack('vv') + cip_request

    # Send RR Data command
    # Interface Handle (4) + Timeout (2) + CPF
    send_data = [0, 0].pack('Vv') + cpf

    build_enip_header(ENIP_CMD_SEND_RR_DATA, send_data.length, @session_handle) + send_data
  end

  # Send CIP request and parse response
  def send_cip_request(service, class_id, instance_id, attribute_id = nil)
    packet = build_cip_request(service, class_id, instance_id, attribute_id)

    sock.put(packet)
    response = sock.get_once(-1, datastore['TIMEOUT'])

    return nil unless response && response.length >= 44

    # Parse ENIP header
    enip_status = response[8, 4].unpack('V')[0]
    return nil if enip_status != 0

    # Find CIP response in CPF data
    # Skip ENIP header (24) + Interface Handle (4) + Timeout (2) + Item Count (2)
    # Skip Null Address Item (4) + Unconnected Data Item header (4)
    cip_offset = 24 + 4 + 2 + 2 + 4 + 4

    return nil if response.length < cip_offset + 2

    # Parse CIP response
    cip_service = response[cip_offset].ord
    cip_status = response[cip_offset + 2].ord

    # Check if response is for our request (service + 0x80)
    expected_service = service | 0x80
    return nil unless cip_service == expected_service

    {
      service: cip_service,
      status: cip_status,
      status_name: CIP_STATUS[cip_status] || "Unknown (0x#{cip_status.to_s(16)})",
      data: cip_status == 0 ? response[cip_offset + 4..-1] : nil
    }
  end

  # Get single attribute from CIP object
  def get_attribute(class_id, instance_id, attribute_id)
    send_cip_request(CIP_GET_ATTRIBUTE_SINGLE, class_id, instance_id, attribute_id)
  end

  # Format raw data for display
  def format_data(data, max_bytes = 32)
    return 'N/A' if data.nil? || data.empty?

    hex = data.bytes[0, max_bytes].map { |b| format('%02X', b) }.join(' ')
    hex += '...' if data.length > max_bytes
    hex
  end

  # Interpret data as various types
  def interpret_data(data)
    return {} if data.nil? || data.empty?

    result = { hex: format_data(data) }

    case data.length
    when 1
      result[:uint8] = data.unpack('C')[0]
    when 2
      result[:uint16] = data.unpack('v')[0]
      result[:int16] = data.unpack('s<')[0]
    when 4
      result[:uint32] = data.unpack('V')[0]
      result[:int32] = data.unpack('l<')[0]
      result[:float] = data.unpack('e')[0]
    when 6
      result[:mac] = data.bytes.map { |b| format('%02X', b) }.join(':')
    end

    # Try string interpretation if printable
    if data.bytes.all? { |b| b >= 0x20 && b <= 0x7E }
      result[:string] = data
    end

    result
  end

  # Interpret known CIP attributes with human-readable formatting
  def interpret_known_attribute(class_id, attr_id, data)
    return nil if data.nil? || data.empty?

    case class_id
    when 0x01  # Identity Object
      case attr_id
      when 1  # Vendor ID
        vendor_id = data.unpack('v')[0]
        vendor_name = VENDOR_IDS[vendor_id] || "Unknown Vendor"
        "#{vendor_name} (#{vendor_id})"
      when 2  # Device Type
        device_type = data.unpack('v')[0]
        type_name = DEVICE_TYPES[device_type] || "Unknown Type"
        "#{type_name} (#{device_type})"
      when 3  # Product Code
        data.unpack('v')[0].to_s
      when 4  # Revision (major.minor)
        major = data[0].ord
        minor = data[1].ord
        "#{major}.#{minor}"
      when 5  # Status
        status = data.unpack('v')[0]
        "0x#{status.to_s(16).rjust(4, '0').upcase}"
      when 6  # Serial Number
        serial = data.unpack('V')[0]
        "0x#{serial.to_s(16).rjust(8, '0').upcase}"
      when 7  # Product Name (CIP SHORT_STRING: 1-byte length + string)
        return nil if data.length < 1
        str_len = data[0].ord
        return '' if str_len == 0 || data.length < 1 + str_len
        data[1, str_len]
      end

    when 0xF5  # TCP/IP Interface Object
      case attr_id
      when 5  # Interface Configuration (IP, Subnet, Gateway at minimum)
        return nil if data.length < 12
        ip = data[0, 4].bytes.reverse.join('.')
        subnet = data[4, 4].bytes.reverse.join('.')
        gateway = data[8, 4].bytes.reverse.join('.')
        "IP: #{ip}, Subnet: #{subnet}, Gateway: #{gateway}"
      when 6  # Host Name (CIP STRING: 2-byte length + string)
        return nil if data.length < 2
        str_len = data.unpack('v')[0]
        return '(empty)' if str_len == 0 || data.length < 2 + str_len
        data[2, str_len]
      end

    when 0xF6  # Ethernet Link Object
      case attr_id
      when 1  # Interface Speed
        speed = data.unpack('V')[0]
        "#{speed} Mbps"
      when 2  # Interface Flags
        flags = data.unpack('V')[0]
        "0x#{flags.to_s(16).rjust(8, '0').upcase}"
      when 3  # Physical Address (MAC)
        return nil if data.length < 6
        data[0, 6].bytes.map { |b| format('%02X', b) }.join(':')
      end

    when 0x06  # Connection Manager
      case attr_id
      when 1, 2, 3  # Counter values
        data.unpack('v')[0].to_s
      end

    when 0xF4  # Port Object
      case attr_id
      when 1  # Port Type
        data.unpack('v')[0].to_s
      when 2  # Port Number
        data.unpack('v')[0].to_s
      when 4  # Port Name (CIP SHORT_STRING)
        return nil if data.length < 1
        str_len = data[0].ord
        return '(empty)' if str_len == 0 || data.length < 1 + str_len
        data[1, str_len]
      end
    end
  end

  # Display safety warning
  def display_warning
    print_warning('=' * 70)
    print_warning('  CIP OBJECT ENUMERATION - FOR AUTHORIZED LAB USE ONLY')
    print_warning('=' * 70)
    print_warning('This module sends multiple CIP requests to enumerate objects.')
    print_warning('Running against production systems may cause:')
    print_warning('  - Increased network traffic')
    print_warning('  - Device performance degradation')
    print_warning('  - Unexpected device behavior')
    print_warning('')
    print_warning("Delay between requests: #{datastore['DELAY']}ms")
    print_warning('=' * 70)
    print_line
  end

  # Action: Scan known CIP objects
  def action_known_objects(ip)
    display_warning
    print_status("#{ip}:#{rport} - Scanning known CIP objects...")

    connect
    unless register_session
      print_error("#{ip}:#{rport} - Failed to register session")
      disconnect
      return
    end

    discovered = []

    KNOWN_CLASSES.each do |class_id, class_info|
      print_status("#{ip}:#{rport} - Checking #{class_info[:name]} (0x#{class_id.to_s(16).rjust(2, '0')})")

      class_info[:instances].each do |instance_id|
        class_info[:attributes].each do |attr_id|
          sleep(datastore['DELAY'] / 1000.0)

          result = get_attribute(class_id, instance_id, attr_id)
          next unless result

          attr_name = class_info[:attr_names][attr_id] || "Attribute #{attr_id}"

          if result[:status] == 0
            # Try known attribute interpretation first, fall back to generic
            known_value = interpret_known_attribute(class_id, attr_id, result[:data])
            interpreted = interpret_data(result[:data])

            if known_value
              value_str = known_value
              interpreted[:known_value] = known_value
            else
              value_str = interpreted[:uint16] || interpreted[:uint32] || interpreted[:string] || interpreted[:hex]
            end

            print_good("  Instance #{instance_id}, #{attr_name}: #{value_str}")

            discovered << {
              class_id: class_id,
              class_name: class_info[:name],
              instance_id: instance_id,
              attribute_id: attr_id,
              attribute_name: attr_name,
              value: value_str,
              data: result[:data],
              interpreted: interpreted
            }
          else
            vprint_status("  Instance #{instance_id}, #{attr_name}: #{result[:status_name]}")
          end
        end
      end
    end

    unregister_session
    disconnect

    # Report to database
    unless discovered.empty?
      report_note(
        host: ip,
        port: rport,
        proto: 'tcp',
        sname: 'enip',
        type: 'enip.cip_objects',
        data: { objects: discovered, count: discovered.length }
      )
      print_good("#{ip}:#{rport} - Discovered #{discovered.length} readable attributes")
    end

    discovered
  end

  # Action: Enumerate class range
  def action_enumerate_classes(ip)
    display_warning
    print_status("#{ip}:#{rport} - Enumerating classes #{datastore['CLASS_START']}-#{datastore['CLASS_END']}...")

    connect
    unless register_session
      print_error("#{ip}:#{rport} - Failed to register session")
      disconnect
      return
    end

    supported_classes = []

    (datastore['CLASS_START']..datastore['CLASS_END']).each do |class_id|
      sleep(datastore['DELAY'] / 1000.0)

      # Try to get attribute 1 from instance 1
      result = get_attribute(class_id, 1, 1)
      next unless result

      if result[:status] == 0
        class_name = KNOWN_CLASSES[class_id]&.dig(:name) || "Class 0x#{class_id.to_s(16).rjust(2, '0')}"
        print_good("#{ip}:#{rport} - Found: #{class_name}")
        supported_classes << { class_id: class_id, name: class_name }
      elsif result[:status] == 0x14  # Attribute not supported but class exists
        class_name = KNOWN_CLASSES[class_id]&.dig(:name) || "Class 0x#{class_id.to_s(16).rjust(2, '0')}"
        print_good("#{ip}:#{rport} - Found (attr unsupported): #{class_name}")
        supported_classes << { class_id: class_id, name: class_name }
      end
    end

    unregister_session
    disconnect

    unless supported_classes.empty?
      report_note(
        host: ip,
        port: rport,
        proto: 'tcp',
        sname: 'enip',
        type: 'enip.supported_classes',
        data: { classes: supported_classes, count: supported_classes.length }
      )
      print_good("#{ip}:#{rport} - Found #{supported_classes.length} supported classes")
    end

    supported_classes
  end

  # Action: Enumerate instances for specific class
  def action_enumerate_instances(ip)
    target_class = datastore['TARGET_CLASS']
    unless target_class
      print_error('TARGET_CLASS option required for ENUMERATE_INSTANCES action')
      return
    end

    display_warning
    class_name = KNOWN_CLASSES[target_class]&.dig(:name) || "Class 0x#{target_class.to_s(16)}"
    print_status("#{ip}:#{rport} - Enumerating instances for #{class_name}...")

    connect
    unless register_session
      print_error("#{ip}:#{rport} - Failed to register session")
      disconnect
      return
    end

    supported_instances = []

    (datastore['INSTANCE_START']..datastore['INSTANCE_END']).each do |instance_id|
      sleep(datastore['DELAY'] / 1000.0)

      # Try to get attribute 1
      result = get_attribute(target_class, instance_id, 1)
      next unless result

      if result[:status] == 0 || result[:status] == 0x14
        print_good("#{ip}:#{rport} - Instance #{instance_id} exists")
        supported_instances << instance_id
      end
    end

    unregister_session
    disconnect

    unless supported_instances.empty?
      report_note(
        host: ip,
        port: rport,
        proto: 'tcp',
        sname: 'enip',
        type: "enip.class_#{target_class.to_s(16)}_instances",
        data: { instances: supported_instances, count: supported_instances.length }
      )
      print_good("#{ip}:#{rport} - Found #{supported_instances.length} instances")
    end

    supported_instances
  end

  # Action: Enumerate attributes for specific class/instance
  def action_enumerate_attributes(ip)
    target_class = datastore['TARGET_CLASS']
    target_instance = datastore['TARGET_INSTANCE'] || 1

    unless target_class
      print_error('TARGET_CLASS option required for ENUMERATE_ATTRIBUTES action')
      return
    end

    display_warning
    class_name = KNOWN_CLASSES[target_class]&.dig(:name) || "Class 0x#{target_class.to_s(16)}"
    print_status("#{ip}:#{rport} - Enumerating attributes for #{class_name} instance #{target_instance}...")

    connect
    unless register_session
      print_error("#{ip}:#{rport} - Failed to register session")
      disconnect
      return
    end

    discovered_attrs = []

    (datastore['ATTRIBUTE_START']..datastore['ATTRIBUTE_END']).each do |attr_id|
      sleep(datastore['DELAY'] / 1000.0)

      result = get_attribute(target_class, target_instance, attr_id)
      next unless result

      if result[:status] == 0
        attr_name = KNOWN_CLASSES[target_class]&.dig(:attr_names, attr_id) || "Attribute #{attr_id}"
        interpreted = interpret_data(result[:data])

        print_good("#{ip}:#{rport} - Attr #{attr_id} (#{attr_name}): #{interpreted[:hex]}")

        discovered_attrs << {
          attribute_id: attr_id,
          attribute_name: attr_name,
          data: result[:data],
          interpreted: interpreted
        }
      end
    end

    unregister_session
    disconnect

    unless discovered_attrs.empty?
      report_note(
        host: ip,
        port: rport,
        proto: 'tcp',
        sname: 'enip',
        type: "enip.class_#{target_class.to_s(16)}_inst_#{target_instance}_attrs",
        data: { attributes: discovered_attrs, count: discovered_attrs.length }
      )
      print_good("#{ip}:#{rport} - Found #{discovered_attrs.length} readable attributes")
    end

    discovered_attrs
  end

  # Action: Full enumeration (comprehensive scan)
  def action_full_enumeration(ip)
    display_warning
    print_warning("#{ip}:#{rport} - Starting FULL enumeration (this may take a while)...")

    # First enumerate known objects
    print_status("#{ip}:#{rport} - Phase 1: Known objects")
    known_results = action_known_objects(ip)

    # Then enumerate class range
    print_status("#{ip}:#{rport} - Phase 2: Class enumeration")
    class_results = action_enumerate_classes(ip)

    print_good("#{ip}:#{rport} - Full enumeration complete")

    {
      known_objects: known_results,
      supported_classes: class_results
    }
  end

  # Main scanner execution
  def run_host(ip)
    case action.name
    when 'KNOWN_OBJECTS'
      action_known_objects(ip)
    when 'ENUMERATE_CLASSES'
      action_enumerate_classes(ip)
    when 'ENUMERATE_INSTANCES'
      action_enumerate_instances(ip)
    when 'ENUMERATE_ATTRIBUTES'
      action_enumerate_attributes(ip)
    when 'FULL_ENUMERATION'
      action_full_enumeration(ip)
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
    disconnect rescue nil
  end
end
