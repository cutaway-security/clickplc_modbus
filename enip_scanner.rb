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
        'Name' => 'EtherNet/IP Device Scanner',
        'Description' => %q{
          This module scans for EtherNet/IP (ENIP) devices and retrieves device identity
          information using the List Identity command. It works with any ENIP-compatible
          device including PLCs, HMIs, drives, and I/O modules from various vendors.

          The module extracts vendor ID, device type, product code, revision, serial
          number, product name, and device IP address from the List Identity response.

          This module performs READ-ONLY operations and does not modify device state.

          Supports both TCP and UDP transport (UDP is faster for discovery).

          Vendor ID table sourced from Nmap enip-info.nse (1500+ vendors).
        },
        'Author' => [
          'Don C. Weber (cutaway)',  # Module author
          'Cutaway Security, LLC'    # Organization
        ],
        'References' => [
          ['URL', 'https://github.com/cutaway-security/click-plc-scanner'],
          ['URL', 'https://www.odva.org/technology-standards/key-technologies/ethernet-ip/'],
          ['URL', 'https://nmap.org/nsedoc/scripts/enip-info.html']
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        },
        'Actions' => [
          ['LIST_IDENTITY', { 'Description' => 'Send List Identity request and parse response' }],
          ['NETWORK_INFO', { 'Description' => 'Read network configuration via CIP explicit messaging' }],
          ['FULL_SCAN', { 'Description' => 'Perform full device enumeration (identity + network info)' }]
        ],
        'DefaultAction' => 'LIST_IDENTITY'
      )
    )

    register_options(
      [
        Opt::RPORT(44818),
        OptBool.new('UDP', [true, 'Use UDP instead of TCP', false]),
        OptInt.new('TIMEOUT', [true, 'Socket timeout in seconds', 2])
      ]
    )
  end

  # ENIP Encapsulation Commands
  ENIP_CMD_LIST_IDENTITY = 0x0063
  ENIP_CMD_LIST_INTERFACES = 0x0064
  ENIP_CMD_REGISTER_SESSION = 0x0065
  ENIP_CMD_UNREGISTER_SESSION = 0x0066
  ENIP_CMD_SEND_RR_DATA = 0x006F
  ENIP_CMD_SEND_UNIT_DATA = 0x0070

  # CPF Item Type IDs
  CPF_TYPE_NULL = 0x0000
  CPF_TYPE_LIST_IDENTITY = 0x000C
  CPF_TYPE_CONNECTED_ADDRESS = 0x00A1
  CPF_TYPE_CONNECTED_DATA = 0x00B1
  CPF_TYPE_UNCONNECTED_DATA = 0x00B2
  CPF_TYPE_SOCKADDR_O2T = 0x8000
  CPF_TYPE_SOCKADDR_T2O = 0x8001

  # CIP Services
  CIP_GET_ATTRIBUTE_SINGLE = 0x0E

  # CIP General Status Codes
  CIP_STATUS = {
    0x00 => 'Success',
    0x08 => 'Service not supported',
    0x14 => 'Attribute not supported',
    0x16 => 'Object does not exist'
  }.freeze

  # CIP Object Classes for network info
  CIP_TCP_IP_INTERFACE = 0xF5
  CIP_ETHERNET_LINK = 0xF6

  # Session handle for CIP explicit messaging
  attr_accessor :session_handle

  # Vendor ID lookup table (from Nmap enip-info.nse)
  # Contains 1500+ registered ODVA vendor IDs
  VENDOR_IDS = {
    0 => 'Reserved',
    1 => 'Rockwell Automation/Allen-Bradley',
    2 => 'Namco Controls Corp.',
    3 => 'Honeywell Inc.',
    4 => 'Parker Hannifin Corp. (Veriflo Division)',
    5 => 'Rockwell Automation/Reliance Elec.',
    7 => 'SMC Corporation',
    8 => 'Molex Incorporated',
    9 => 'Western Reserve Controls Corp.',
    10 => 'Advanced Micro Controls Inc. (AMCI)',
    11 => 'ASCO Pneumatic Controls',
    12 => 'Banner Engineering Corp.',
    13 => 'Belden Wire & Cable Company',
    14 => 'Cooper Interconnect',
    16 => 'Daniel Woodhead Co. (Woodhead Connectivity)',
    17 => 'Dearborn Group Inc.',
    19 => 'Helm Instrument Company',
    20 => 'Huron Net Works',
    21 => 'Lumberg Inc.',
    22 => 'Online Development Inc.(Automation Value)',
    23 => 'Vorne Industries Inc.',
    24 => 'ODVA Special Reserve',
    26 => 'Festo Corporation',
    30 => 'Unico Inc.',
    31 => 'Ross Controls',
    34 => 'Hohner Corp.',
    35 => 'Micro Mo Electronics Inc.',
    36 => 'MKS Instruments Inc.',
    37 => 'Yaskawa Electric America',
    39 => 'AVG Automation (Uticor)',
    40 => 'Wago Corporation',
    41 => 'Kinetics (Unit Instruments)',
    42 => 'IMI Norgren Limited',
    43 => 'BALLUFF Inc.',
    44 => 'Yaskawa Electric America Inc.',
    45 => 'Eurotherm Controls Inc',
    46 => 'ABB Industrial Systems',
    47 => 'Omron Corporation',
    48 => 'TURCk Inc.',
    49 => 'Grayhill Inc.',
    50 => 'Real Time Automation (C&ID)',
    52 => 'Numatics Inc.',
    53 => 'Lutze Inc.',
    56 => 'Softing GmbH',
    57 => 'Pepperl + Fuchs',
    58 => 'Spectrum Controls Inc.',
    59 => 'D.I.P. Inc. MKS Inst.',
    60 => 'Applied Motion Products Inc.',
    61 => 'Sencon Inc.',
    62 => 'High Country Tek',
    63 => 'SWAC Automation Consult GmbH',
    64 => 'Clippard Instrument Laboratory',
    68 => 'Eaton Electrical',
    71 => 'Toshiba International Corp.',
    72 => 'Control Technology Incorporated',
    73 => 'TCS (NZ) Ltd.',
    74 => 'Hitachi Ltd.',
    75 => 'ABB Robotics Products AB',
    76 => 'NKE Corporation',
    77 => 'Rockwell Software Inc.',
    78 => 'Escort Memory Systems',
    79 => 'Berk-Tek',
    80 => 'Industrial Devices Corporation',
    81 => 'IXXAT Automation GmbH',
    82 => 'Mitsubishi Electric Automation Inc.',
    83 => 'OPTO-22',
    86 => 'Horner Electric',
    87 => 'Burkert Werke GmbH & Co. KG',
    88 => 'Industrial Indexing Systems, Inc.',
    90 => 'HMS Industrial Networks AB',
    91 => 'Robicon',
    92 => 'Helix Technology (Granville-Phillips)',
    93 => 'Arlington Laboratory',
    94 => 'Advantech Co. Ltd.',
    95 => 'Square D Company',
    96 => 'Digital Electronics Corp.',
    97 => 'Danfoss',
    100 => 'Bosch Rexroth Corporation',
    101 => 'Applied Materials Inc.',
    102 => 'Showa Electric Wire & Cable Co.',
    103 => 'Pacific Scientific (API Controls Inc.)',
    104 => 'Sharp Manufacturing Systems Corp.',
    105 => 'Olflex Wire & Cable Inc.',
    107 => 'Unitrode',
    108 => 'Beckhoff Automation GmbH',
    109 => 'National Instruments',
    110 => 'Mykrolis Corporations (Millipore)',
    111 => 'International Motion Controls Corp.',
    113 => 'SEG Kempen GmbH',
    116 => 'MTS Systems Corp.',
    117 => 'Krones Inc',
    119 => 'EXOR Electronic R & D',
    120 => 'SIEI S.p.A.',
    121 => 'KUKA Roboter GmbH',
    123 => 'SEC (Samsung Electronics Co.Ltd)',
    124 => 'Binary Electronics Ltd',
    125 => 'Flexible Machine Controls',
    127 => 'ABB Inc. (Entrelec)',
    128 => 'MAC Valves Inc.',
    129 => 'Auma Actuators Inc',
    130 => 'Toyoda Machine Works Ltd',
    133 => 'Balogh T.A.G. Corporation',
    134 => 'TR Systemtechnik GmbH',
    135 => 'UNIPULSE Corporation',
    138 => 'Conxall Corporation Inc.',
    141 => 'Kuramo Electric Co.Ltd.',
    142 => 'Creative Micro Designs',
    143 => 'GE Industrial Systems',
    144 => 'Leybold Vacuum GmbH',
    145 => 'Siemens Energy & Automation/Drives',
    146 => 'Kodensha Ltd',
    147 => 'Motion Engineering Inc.',
    148 => 'Honda Engineering Co.Ltd',
    149 => 'EIM Valve Controls',
    150 => 'Melec Inc.',
    151 => 'Sony Manufacturing Systems Corporation',
    152 => 'North American Mfg.',
    153 => 'WATLOW',
    154 => 'Japan Radio Co.Ltd',
    155 => 'NADEX Co.Ltd',
    156 => 'Ametek Automation & Process Technologies',
    157 => 'FACTS, Inc.',
    158 => 'KVASER AB',
    159 => 'IDEC IZUMI Corporation',
    160 => 'Mitsubishi Heavy Industries Ltd',
    161 => 'Mitsubishi Electric Corporation',
    162 => 'Horiba-STEC Inc.',
    163 => 'esd electronic system design gmbh',
    164 => 'DAIHEN Corporation',
    165 => 'Tyco Valves & Controls/Keystone',
    166 => 'EBARA Corporation',
    169 => 'Hokuyo Electric Co. Ltd',
    170 => 'Pyramid Solutions Inc.',
    171 => 'Denso Wave Incorporated',
    172 => 'HLS Hard-Line Solutions Inc',
    173 => 'Caterpillar Inc.',
    174 => 'PDL Electronics Ltd.',
    176 => 'Red Lion Controls',
    177 => 'ANELVA Corporation',
    178 => 'Toyo Denki Seizo KK',
    179 => 'Sanyo Denki Co.Ltd',
    180 => 'Advanced Energy Japan K.K.',
    181 => 'Pilz GmbH & Co',
    182 => 'Marsh Bellofram',
    184 => 'M-SYSTEM Co. Ltd',
    185 => 'Nissin Electric Co.Ltd',
    186 => 'Hitachi Metals Ltd.',
    187 => 'Oriental Motor Company',
    188 => 'A&D Co.Ltd',
    189 => 'Phasetronics Inc.',
    190 => 'Cummins Engine Company',
    191 => 'Deltron Inc.',
    192 => 'Geneer Corporation',
    193 => 'Anatol Automation Inc.',
    196 => 'Medar Inc.',
    197 => 'Comdel Inc.',
    198 => 'Advanced Energy Industries Inc',
    200 => 'DAIDEN Co.Ltd',
    201 => 'CKD Corporation',
    202 => 'Toyo Electric Corporation',
    204 => 'AuCom Electronics Ltd',
    205 => 'Shinko Electric Co.Ltd',
    206 => 'Vector Informatik GmbH',
    208 => 'Moog Inc.',
    209 => 'Contemporary Controls',
    210 => 'Tokyo Sokki Kenkyujo Co.Ltd',
    211 => 'Schenck-AccuRate Inc.',
    212 => 'The Oilgear Company',
    214 => 'ASM Japan K.K.',
    215 => 'HIRATA Corp.',
    216 => 'SUNX Limited',
    217 => 'Meidensha Corp.',
    218 => 'NIDEC SANKYO CORPORATION',
    219 => 'KAMRO Corp.',
    220 => 'Nippon System Development Co.Ltd',
    221 => 'EBARA Technologies Inc.',
    224 => 'SG Co.Ltd',
    225 => 'Vaasa Institute of Technology',
    226 => 'MKS Instruments (ENI Technology)',
    227 => 'Tateyama System Laboratory Co.Ltd.',
    228 => 'QLOG Corporation',
    229 => 'Matric Limited Inc.',
    230 => 'NSD Corporation',
    232 => 'Sumitomo Wiring Systems Ltd',
    233 => 'Group 3 Technology Ltd',
    234 => 'CTI Cryogenics',
    235 => 'POLSYS CORP',
    236 => 'Ampere Inc.',
    238 => 'Simplatroll Ltd',
    241 => 'Leading Edge Design',
    242 => 'Humphrey Products',
    243 => 'Schneider Automation Inc.',
    244 => 'Westlock Controls Corp.',
    245 => 'Nihon Weidmuller Co.Ltd',
    246 => 'Brooks Instrument (Div. of Emerson)',
    248 => 'Moeller GmbH',
    249 => 'Varian Vacuum Products',
    250 => 'Yokogawa Electric Corporation',
    251 => 'Electrical Design Daiyu Co.Ltd',
    252 => 'Omron Software Co.Ltd',
    253 => 'BOC Edwards',
    254 => 'Control Technology Corporation',
    255 => 'Bosch Rexroth',
    256 => 'Turck',
    257 => 'Control Techniques PLC',
    258 => 'Hardy Instruments Inc.',
    259 => 'LS Industrial Systems',
    260 => 'E.O.A. Systems Inc.',
    262 => 'New Cosmos Electric Co.Ltd.',
    263 => 'Sense Eletronica LTDA',
    264 => 'Xycom Inc.',
    265 => 'Baldor Electric',
    267 => 'Patlite Corporation',
    269 => 'Mogami Wire & Cable Corporation',
    270 => 'Welding Technology Corporation (WTC)',
    272 => 'Deutschmann Automation GmbH',
    273 => 'ICP Panel-Tec Inc.',
    274 => 'Bray Controls USA',
    276 => 'Status Technologies',
    277 => 'Trio Motion Technology Ltd',
    278 => 'Sherrex Systems Ltd',
    279 => 'Adept Technology Inc.',
    280 => 'Spang Power Electronics',
    282 => 'Acrosser Technology Co.Ltd',
    283 => 'Hilscher GmbH',
    284 => 'IMAX Corporation',
    285 => 'Electronic Innovation Inc.',
    286 => 'Netlogic Inc.',
    287 => 'Bosch Rexroth Corporation Indramat',
    290 => 'Murata Machinery Ltd.',
    291 => 'MTT Company Ltd.',
    292 => 'Kanematsu Semiconductor Corp.',
    293 => 'Takebishi Electric Sales Co.',
    294 => 'Tokyo Electron Device Ltd',
    295 => 'PFU Limited',
    296 => 'Hakko Automation Co.Ltd.',
    297 => 'Advanet Inc.',
    298 => 'Tokyo Electron Software Technologies Ltd.',
    300 => 'Shinagawa Electric Wire Co.Ltd.',
    301 => 'Yokogawa M&C Corporation',
    302 => 'KONAN Electric Co.Ltd.',
    303 => 'Binar Elektronik AB',
    304 => 'Furukawa Electric Co.',
    305 => 'Cooper Energy Services',
    306 => 'Schleicher GmbH & Co.',
    307 => 'Hirose Electric Co.Ltd',
    308 => 'Western Servo Design Inc.',
    309 => 'Prosoft Technology',
    311 => 'Towa Shoko Co.Ltd',
    312 => 'Kyopal Co.Ltd',
    313 => 'Extron Co.',
    314 => 'Wieland Electric GmbH',
    315 => 'SEW Eurodrive GmbH',
    316 => 'Aera Corporation',
    317 => 'STA Reutlingen',
    319 => 'Fuji Electric Co.Ltd.',
    322 => 'ifm efector inc.',
    324 => 'IDEACOD-Hohner Automation S.A.',
    325 => 'CommScope Inc.',
    326 => 'GE Fanuc Automation North America Inc.',
    327 => 'Matsushita Electric Industrial Co.Ltd',
    328 => 'Okaya Electronics Corporation',
    329 => 'KASHIYAMA Industries Ltd',
    330 => 'JVC',
    331 => 'Interface Corporation',
    332 => 'Grape Systems Inc.',
    334 => 'KEBA AG',
    335 => 'Toshiba IT & Control Systems Corporation',
    336 => 'Sanyo Machine Works Ltd.',
    337 => 'Vansco Electronics Ltd.',
    338 => 'Dart Container Corp.',
    339 => 'Livingston & Co. Inc.',
    340 => 'Alfa Laval LKM as',
    341 => 'BF ENTRON Ltd. (British Federal)',
    342 => 'Bekaert Engineering NV',
    343 => 'Ferran Scientific Inc.',
    345 => 'Endress + Hauser',
    346 => 'Lincoln Electric Company',
    347 => 'ABB ALSTOM Power UK Ltd. (EGT)',
    348 => 'Berger Lahr GmbH',
    350 => 'Federal Signal Corp.',
    351 => 'Kawasaki Robotics (USA) Inc.',
    352 => 'Bently Nevada Corporation',
    354 => 'FRABA Posital GmbH',
    355 => 'Elsag Bailey Inc.',
    356 => 'Fanuc Robotics America',
    358 => 'Surface Combustion Inc.',
    360 => 'AILES Electronics Ind. Co.Ltd.',
    361 => 'Wonderware Corporation',
    362 => 'Particle Measuring Systems Inc.',
    365 => 'BITS Co.Ltd',
    366 => 'Japan Aviation Electronics Industry Ltd',
    367 => 'Keyence Corporation',
    368 => 'Kuroda Precision Industries Ltd.',
    369 => 'Mitsubishi Electric Semiconductor Application',
    370 => 'Nippon Seisen Cable Ltd.',
    371 => 'Omron ASO Co.Ltd',
    372 => 'Seiko Seiki Co.Ltd.',
    373 => 'Sumitomo Heavy Industries Ltd.',
    374 => 'Tango Computer Service Corporation',
    375 => 'Technology Service Inc.',
    376 => 'Toshiba Information Systems (Japan) Corporation',
    377 => 'TOSHIBA Schneider Inverter Corporation',
    378 => 'Toyooki Kogyo Co.Ltd.',
    379 => 'XEBEC',
    380 => 'Madison Cable Corporation',
    381 => 'Hitati Engineering & Services Co.Ltd',
    382 => 'TEM-TECH Lab Co.Ltd',
    383 => 'International Laboratory Corporation',
    384 => 'Dyadic Systems Co.Ltd.',
    385 => 'SETO Electronics Industry Co.Ltd',
    386 => 'Tokyo Electron Kyushu Limited',
    387 => 'KEI System Co.Ltd',
    389 => 'Asahi Engineering Co.Ltd',
    390 => 'Contrex Inc.',
    391 => 'Paradigm Controls Ltd.',
    393 => 'Ohm Electric Co.Ltd.',
    394 => 'RKC Instrument Inc.',
    395 => 'Suzuki Motor Corporation',
    396 => 'Custom Servo Motors Inc.',
    397 => 'PACE Control Systems',
    398 => 'Selectron Systems AG',
    400 => 'LINTEC Co.Ltd.',
    401 => 'Hitachi Cable Ltd.',
    402 => 'BUSWARE Direct',
    403 => 'Eaton Electric B.V.',
    404 => 'VAT Vakuumventile AG',
    405 => 'Scientific Technologies Incorporated',
    406 => 'Alfa Instrumentos Eletronicos Ltda',
    407 => 'TWK Elektronik GmbH',
    408 => 'ABB Welding Systems AB',
    409 => 'BYSTRONIC Maschinen AG',
    410 => 'Kimura Electric Co.Ltd',
    411 => 'Nissei Plastic Industrial Co.Ltd',
    413 => 'Kistler-Morse Corporation',
    414 => 'Proteous Industries Inc.',
    415 => 'IDC Corporation',
    416 => 'Nordson Corporation',
    417 => 'Rapistan Systems',
    418 => 'LP-Elektronik GmbH',
    419 => 'GERBI & FASE S.p.A.',
    420 => 'Phoenix Digital Corporation',
    421 => 'Z-World Engineering',
    422 => 'Honda R&D Co.Ltd.',
    423 => 'Bionics Instrument Co.Ltd.',
    424 => 'Teknic Inc.',
    425 => 'R.Stahl Inc.',
    427 => 'Ryco Graphic Manufacturing Inc.',
    428 => 'Giddings & Lewis Inc.',
    429 => 'Koganei Corporation',
    431 => 'Nichigoh Communication Electric Wire Co.Ltd.',
    433 => 'Fujikura Ltd.',
    434 => 'AD Link Technology Inc.',
    435 => 'StoneL Corporation',
    436 => 'Computer Optical Products Inc.',
    437 => 'CONOS Inc.',
    438 => 'Erhardt + Leimer GmbH',
    439 => 'UNIQUE Co. Ltd',
    440 => 'Roboticsware Inc.',
    441 => 'Nachi Fujikoshi Corporation',
    442 => 'Hengstler GmbH',
    443 => 'Vacon Plc',
    444 => 'SUNNY GIKEN Inc.',
    445 => 'Lenze Drive Systems GmbH',
    446 => 'CD Systems B.V.',
    447 => 'FMT/Aircraft Gate Support Systems AB',
    448 => 'Axiomatic Technologies Corp',
    449 => 'Embedded System Products Inc.',
    451 => 'Mencom Corporation',
    452 => 'Kollmorgen',
    453 => 'Matsushita Welding Systems Co.Ltd.',
    454 => 'Dengensha Mfg. Co. Ltd.',
    455 => 'Quinn Systems Ltd.',
    456 => 'Tellima Technology Ltd',
    457 => 'MDT Software',
    458 => 'Taiwan Keiso Co.Ltd',
    459 => 'Pinnacle Systems',
    460 => 'Ascom Hasler Mailing Sys',
    461 => 'INSTRUMAR Limited',
    463 => 'Navistar International Transportation Corp',
    464 => 'Huettinger Elektronik GmbH + Co. KG',
    465 => 'OCM Technology Inc.',
    466 => 'Professional Supply Inc.',
    467 => 'Control Solutions',
    468 => 'Baumer IVO GmbH & Co. KG',
    469 => 'Worcester Controls Corporation',
    470 => 'Pyramid Technical Consultants Inc.',
    471 => 'Eilersen Electric A/S',
    472 => 'Apollo Fire Detectors Limited',
    473 => 'Avtron Manufacturing Inc.',
    475 => 'Tokyo Keiso Co.Ltd.',
    476 => 'Daishowa Swiki Co.Ltd.',
    477 => 'Kojima Instruments Inc.',
    478 => 'Shimadzu Corporation',
    479 => 'Tatsuta Electric Wire & Cable Co.Ltd.',
    480 => 'MECS Corporation',
    481 => 'Tahara Electric',
    482 => 'Koyo Electronics',
    483 => 'Clever Devices',
    484 => 'GCD Hardware & Software GmbH',
    486 => 'Miller Electric Mfg Co.',
    487 => 'GEA Tuchenhagen GmbH',
    488 => 'Riken Keiki Co. LTD',
    489 => 'Keisokugiken Corporation',
    490 => 'Fuji Machine Mfg. Co.Ltd',
    492 => 'Nidec-Shimpo Corp.',
    493 => 'UTEC Corporation',
    494 => 'Sanyo Electric Co. Ltd.',
    497 => 'Okano Electric Wire Co. Ltd',
    498 => 'Shimaden Co. Ltd.',
    499 => 'Teddington Controls Ltd',
    501 => 'VIPA GmbH',
    502 => 'Warwick Manufacturing Group',
    503 => 'Danaher Controls',
    506 => 'American Science & Engineering',
    507 => 'Accutron Controls International Inc.',
    508 => 'Norcott Technologies Ltd',
    509 => 'TB Woods Inc',
    510 => 'Proportion-Air Inc.',
    511 => 'SICK Stegmann GmbH',
    513 => 'Edwards Signaling',
    514 => 'Sumitomo Metal Industries Ltd',
    515 => 'Cosmo Instruments Co.Ltd.',
    516 => 'Denshosha Co.Ltd.',
    517 => 'Kaijo Corp.',
    518 => 'Michiproducts Co.Ltd.',
    519 => 'Miura Corporation',
    520 => 'TG Information Network Co.Ltd.',
    521 => 'Fujikin Inc.',
    522 => 'Estic Corp.',
    523 => 'GS Hydraulic Sales',
    524 => 'Leuze Electronic GmbH & Co. KG',
    525 => 'MTE Limited',
    526 => 'Hyde Park Electronics Inc.',
    527 => 'Pfeiffer Vacuum GmbH',
    528 => 'Cyberlogic Technologies',
    529 => 'OKUMA Corporation FA Systems Division',
    531 => 'Hitachi Kokusai Electric Co.Ltd.',
    532 => 'SHINKO TECHNOS Co.Ltd.',
    533 => 'Itoh Electric Co.Ltd.',
    534 => 'Colorado Flow Tech Inc.',
    535 => 'Love Controls Division/Dwyer Inst.',
    536 => 'Alstom Drives and Controls',
    537 => 'The Foxboro Company',
    538 => 'Tescom Corporation',
    540 => 'Atlas Copco Controls UK',
    542 => 'Autojet Technologies',
    543 => 'Prima Electronics S.p.A.',
    544 => 'PMA GmbH',
    545 => 'Shimafuji Electric Co.Ltd',
    546 => 'Oki Electric Industry Co.Ltd',
    547 => 'Kyushu Matsushita Electric Co.Ltd',
    548 => 'Nihon Electric Wire & Cable Co.Ltd',
    549 => 'Tsuken Electric Ind Co.Ltd',
    550 => 'Tamadic Co.',
    551 => 'MAATEL SA',
    552 => 'OKUMA America',
    553 => 'Control Techniques PLC-NA',
    554 => 'TPC Wire & Cable',
    555 => 'ATI Industrial Automation',
    556 => 'Microcontrol (Australia) Pty Ltd',
    557 => 'Serra Soldadura S.A.',
    558 => 'Southwest Research Institute',
    559 => 'Cabinplant International',
    560 => 'Sartorius Mechatronics T&H GmbH',
    561 => 'Comau S.p.A. Robotics & Final Assembly Division',
    562 => 'Phoenix Contact',
    563 => 'Yokogawa MAT Corporation',
    564 => 'asahi sangyo co. ltd.',
    566 => 'Akita Myotoku Ltd.',
    567 => 'OBARA Corp.',
    568 => 'Suetron Electronic GmbH',
    570 => 'Serck Controls Limited',
    571 => 'Fairchild Industrial Products Company',
    572 => 'ARO S.A.',
    573 => 'M2C GmbH',
    574 => 'Shin Caterpillar Mitsubishi Ltd.',
    575 => 'Santest Co.Ltd.',
    576 => 'Cosmotechs Co.Ltd.',
    577 => 'Hitachi Electric Systems',
    578 => 'Smartscan Ltd',
    579 => 'Woodhead Software & Electronics France',
    580 => 'Athena Controls Inc.',
    581 => 'Syron Engineering & Manufacturing Inc.',
    582 => 'Asahi Optical Co.Ltd.',
    583 => 'Sansha Electric Mfg. Co.Ltd.',
    584 => 'Nikki Denso Co.Ltd.',
    585 => 'Star Micronics Co.Ltd.',
    586 => 'Ecotecnia Socirtat Corp.',
    587 => 'AC Technology Corp.',
    588 => 'West Instruments Limited',
    589 => 'NTI Limited',
    590 => 'Delta Computer Systems Inc.',
    591 => 'FANUC Ltd.',
    592 => 'Hearn-Gu Lee',
    593 => 'ABB Automation Products',
    594 => 'Orion Machinery Co.Ltd.',
    596 => 'Wire-Pro Inc.',
    597 => 'Beijing Huakong Technology Co. Ltd.',
    598 => 'Yokoyama Shokai Co.Ltd.',
    599 => 'Toyogiken Co.Ltd.',
    600 => 'Coester Equipamentos Eletronicos Ltda.',
    601 => 'Kawasaki Heavy Industries, Ltd.',
    602 => 'Electroplating Engineers of Japan Ltd.',
    603 => 'ROBOX S.p.A.',
    604 => 'Spraying Systems Company',
    605 => 'Benshaw Inc.',
    606 => 'ZPA-DP A.S.',
    607 => 'Wired Rite Systems',
    608 => 'Tandis Research Inc.',
    609 => 'SSD Drives GmbH',
    610 => 'ULVAC Japan Ltd.',
    611 => 'DYNAX Corporation',
    612 => 'Nor-Cal Products Inc.',
    613 => 'Aros Electronics AB',
    614 => 'Jun-Tech Co.Ltd.',
    615 => 'HAN-MI Co. Ltd.',
    616 => 'uniNtech',
    617 => 'Hae Pyung Electronics Research Institute',
    618 => 'Milwaukee Electronics',
    619 => 'OBERG Industries',
    620 => 'Parker Hannifin/Compumotor Division',
    621 => 'TECHNO DIGITAL CORPORATION',
    622 => 'Network Supply Co.Ltd.',
    623 => 'Union Electronics Co.Ltd.',
    624 => 'Tritronics Services PM Ltd.',
    625 => 'Rockwell Automation-Sprecher+Schuh',
    626 => 'Matsushita Electric Industrial Co.Ltd/Motor Co.',
    627 => 'Rolls-Royce Energy Systems Inc.',
    628 => 'JEONGIL INTERCOM CO. LTD',
    629 => 'Interroll Corp.',
    630 => 'Hubbell Wiring Device-Kellems',
    631 => 'Intelligent Motion Systems',
    633 => 'INFICON AG',
    634 => 'Hirschmann Inc.',
    635 => 'The Siemon Company',
    636 => 'YAMAHA Motor Co. Ltd.',
    637 => 'aska corporation',
    638 => 'Woodhead Connectivity',
    639 => 'Trimble AB',
    640 => 'Murrelektronik GmbH',
    641 => 'Creatrix Labs Inc.',
    642 => 'TopWorx',
    643 => 'Kumho Industrial Co.Ltd.',
    644 => 'Wind River Systems Inc.',
    645 => 'Bihl & Wiedemann GmbH',
    646 => 'Harmonic Drive Systems Inc.',
    647 => 'Rikei Corporation',
    648 => 'BL Autotec Ltd.',
    649 => 'Hana Information & Technology Co.Ltd.',
    650 => 'Seoil Electric Co.Ltd.',
    651 => 'Fife Corporation',
    652 => 'Shanghai Electrical Apparatus Research Institute',
    653 => 'Detector Electronics',
    654 => 'Parasense Development Centre',
    657 => 'Six Tau S.p.A.',
    658 => 'Aucos GmbH',
    659 => 'Rotork Controls',
    660 => 'Automationdirect.com',
    661 => 'Thermo BLH',
    662 => 'System Controls Ltd.',
    663 => 'Univer S.p.A.',
    664 => 'MKS-Tenta Technology',
    665 => 'Lika Electronic SNC',
    666 => 'Mettler-Toledo Inc.',
    667 => 'DXL USA Inc.',
    668 => 'Rockwell Automation/Entek IRD Intl.',
    669 => 'Nippon Otis Elevator Company',
    670 => 'Sinano Electric Co.Ltd.',
    671 => 'Sony Manufacturing Systems',
    673 => 'Contec Co.Ltd.',
    674 => 'Automated Solutions',
    675 => 'Controlweigh',
    677 => 'Fincor Electronics',
    678 => 'Cognex Corporation',
    679 => 'Qualiflow',
    680 => 'Weidmuller Inc.',
    681 => 'Morinaga Milk Industry Co.Ltd.',
    682 => 'Takagi Industrial Co.Ltd.',
    683 => 'Wittenstein AG',
    684 => 'Sena Technologies Inc.',
    686 => 'APV Products Unna',
    687 => 'Creator Teknisk Utvedkling AB',
    689 => 'Mibu Denki Industrial Co.Ltd.',
    690 => 'Takamastsu Machineer Section',
    691 => 'Startco Engineering Ltd.',
    693 => 'Holjeron',
    694 => 'ALCATEL High Vacuum Technology',
    695 => 'Taesan LCD Co.Ltd.',
    696 => 'POSCON',
    697 => 'VMIC',
    698 => 'Matsushita Electric Works Ltd.',
    699 => 'IAI Corporation',
    700 => 'Horst GmbH',
    701 => 'MicroControl GmbH & Co.',
    702 => 'Leine & Linde AB',
    704 => 'EC Elettronica Srl',
    705 => 'VIT Software HB',
    706 => 'Bronkhorst High-Tech B.V.',
    707 => 'Optex Co.Ltd.',
    708 => 'Yosio Electronic Co.',
    709 => 'Terasaki Electric Co.Ltd.',
    710 => 'Sodick Co.Ltd.',
    711 => 'MTS Systems Corporation-Automation Division',
    712 => 'Mesa Systemtechnik',
    713 => 'SHIN HO SYSTEM Co.Ltd.',
    714 => 'Goyo Electronics Co Ltd.',
    715 => 'Loreme',
    716 => 'SAB Brockskes GmbH & Co. KG',
    717 => 'Trumpf Laser GmbH + Co. KG',
    718 => 'Niigata Electronic Instruments Co.Ltd.',
    719 => 'Yokogawa Digital Computer Corporation',
    720 => 'O.N. Electronic Co.Ltd.',
    721 => 'Industrial Control Communication Inc.',
    722 => 'ABB Inc.',
    723 => 'ElectroWave USA Inc.',
    724 => 'Industrial Network Controls LLC',
    725 => 'KDT Systems Co.Ltd.',
    726 => 'SEFA Technology Inc.',
    727 => 'Nippon POP Rivets and Fasteners Ltd.',
    728 => 'Yamato Scale Co.Ltd.',
    729 => 'Zener Electric',
    730 => 'GSE Scale Systems',
    731 => 'ISAS (Integrated Switchgear & Sys. Pty Ltd)',
    732 => 'Beta LaserMike Limited',
    733 => 'TOEI Electric Co.Ltd.',
    734 => 'Hakko Electronics Co.Ltd',
    736 => 'RFID Inc.',
    737 => 'Adwin Corporation',
    738 => 'Osaka Vacuum Ltd.',
    739 => 'A-Kyung Motion Inc.',
    740 => 'Camozzi S.P.A.',
    741 => 'Crevis Co. LTD',
    742 => 'Rice Lake Weighing Systems',
    743 => 'Linux Network Services',
    744 => 'KEB Antriebstechnik GmbH',
    745 => 'Hagiwara Electric Co.Ltd.',
    746 => 'Glass Inc. International',
    748 => 'DVT Corporation',
    749 => 'Woodward Governor',
    750 => 'Mosaic Systems Inc.',
    751 => 'Laserline GmbH',
    752 => 'COM-TEC Inc.',
    753 => 'Weed Instrument',
    754 => 'Prof-face European Technology Center',
    755 => 'Fuji Automation Co.Ltd.',
    756 => 'Matsutame Co.Ltd.',
    757 => 'Hitachi Via Mechanics Ltd.',
    758 => 'Dainippon Screen Mfg. Co. Ltd.',
    759 => 'FLS Automation A/S',
    760 => 'ABB Stotz Kontakt GmbH',
    761 => 'Technical Marine Service',
    762 => 'Advanced Automation Associates Inc.',
    763 => 'Baumer Ident GmbH',
    764 => 'Tsubakimoto Chain Co.',
    766 => 'Furukawa Co.Ltd.',
    767 => 'Active Power',
    768 => 'CSIRO Mining Automation',
    769 => 'Matrix Integrated Systems',
    770 => 'Digitronic Automationsanlagen GmbH',
    771 => 'SICK STEGMANN Inc.',
    772 => 'TAE-Antriebstechnik GmbH',
    773 => 'Electronic Solutions',
    774 => 'Rocon L.L.C.',
    775 => 'Dijitized Communications Inc.',
    776 => 'Asahi Organic Chemicals Industry Co.Ltd.',
    777 => 'Hodensha',
    778 => 'Harting Inc. NA',
    779 => 'Kubler GmbH',
    780 => 'Yamatake Corporation',
    781 => 'JEOL',
    782 => 'Yamatake Industrial Systems Co.Ltd.',
    783 => 'HAEHNE Elektronische Messgerate GmbH',
    784 => 'Ci Technologies Pty Ltd',
    785 => 'N. SCHLUMBERGER & CIE',
    786 => 'Teijin Seiki Co.Ltd.',
    787 => 'DAIKIN Industries Ltd',
    788 => 'RyuSyo Industrial Co.Ltd.',
    789 => 'SAGINOMIYA SEISAKUSHO INC.',
    790 => 'Seishin Engineering Co.Ltd.',
    791 => 'Japan Support System Ltd.',
    792 => 'Decsys',
    793 => 'Metronix Messgerate u. Elektronik GmbH',
    794 => 'ROPEX Industrie-Elektronik GmbH',
    795 => 'Vaccon Company Inc.',
    796 => 'Siemens Energy & Automation Inc.',
    797 => 'Ten X Technology Inc.',
    798 => 'Tyco Electronics',
    799 => 'Delta Power Electronics Center',
    800 => 'Denker',
    801 => 'Autonics Corporation',
    802 => 'JFE Electronic Engineering Pty. Ltd.',
    804 => 'Electro-Sensors Inc.',
    805 => 'Digi International Inc.',
    806 => 'Texas Instruments',
    807 => 'ADTEC Plasma Technology Co.Ltd',
    808 => 'SICK AG',
    809 => 'Ethernet Peripherals Inc.',
    810 => 'Animatics Corporation',
    812 => 'Process Control Corporation',
    813 => 'SystemV. Inc.',
    814 => 'Danaher Motion SRL',
    815 => 'SHINKAWA Sensor Technology Inc.',
    816 => 'Tesch GmbH & Co. KG',
    818 => 'Trend Controls Systems Ltd.',
    819 => 'Guangzhou ZHIYUAN Electronic Co.Ltd.',
    820 => 'Mykrolis Corporation',
    821 => 'Bethlehem Steel Corporation',
    822 => 'KK ICP',
    823 => 'Takemoto Denki Corporation',
    824 => 'The Montalvo Corporation',
    826 => 'LEONI Special Cables GmbH',
    828 => 'ONO SOKKI CO.,LTD.',
    829 => 'Rockwell Samsung Automation',
    830 => 'SHINDENGEN ELECTRIC MFG. CO. LTD',
    831 => 'Origin Electric Co. Ltd.',
    832 => 'Quest Technical Solutions Inc.',
    833 => 'LS Cable Ltd.',
    834 => 'Enercon-Nord Electronic GmbH',
    835 => 'Northwire Inc.',
    836 => 'Engel Elektroantriebe GmbH',
    837 => 'The Stanley Works',
    838 => 'Celesco Transducer Products Inc.',
    839 => 'Chugoku Electric Wire and Cable Co.',
    840 => 'Kongsberg Simrad AS',
    841 => 'Panduit Corporation',
    842 => 'Spellman High Voltage Electronics Corp.',
    843 => 'Kokusai Electric Alpha Co.Ltd.',
    844 => 'Brooks Automation Inc.',
    845 => 'ANYWIRE CORPORATION',
    846 => 'Honda Electronics Co. Ltd',
    847 => 'REO Elektronik AG',
    848 => 'Fusion UV Systems Inc.',
    849 => 'ASI Advanced Semiconductor Instruments GmbH',
    850 => 'Datalogic Inc.',
    851 => 'SoftPLC Corporation',
    852 => 'Dynisco Instruments LLC',
    853 => 'WEG Industrias SA',
    854 => 'Frontline Test Equipment Inc.',
    855 => 'Tamagawa Seiki Co.Ltd.',
    856 => 'Multi Computing Co.Ltd.',
    857 => 'RVSI',
    858 => 'Commercial Timesharing Inc.',
    859 => 'Tennessee Rand Automation LLC',
    860 => 'Wacogiken Co.Ltd',
    861 => 'Reflex Integration Inc.',
    862 => 'Siemens AG A&D PI Flow Instruments',
    863 => 'G. Bachmann Electronic GmbH',
    864 => 'NT International',
    865 => 'Schweitzer Engineering Laboratories',
    866 => 'ATR Industrie-Elektronik GmbH Co.',
    867 => 'PLASMATECH Co.Ltd',
    869 => 'GEMU GmbH & Co. KG',
    870 => 'Alcorn McBride Inc.',
    871 => 'MORI SEIKI CO. LTD',
    872 => 'NodeTech Systems Ltd',
    873 => 'Emhart Teknologies',
    874 => 'Cervis Inc.',
    875 => 'FieldServer Technologies',
    876 => 'NEDAP Power Supplies',
    877 => 'Nippon Sanso Corporation',
    878 => 'Mitomi Giken Co.Ltd.',
    879 => 'PULS GmbH',
    881 => 'Japan Control Engineering Ltd',
    882 => 'Embedded Systems Korea',
    883 => 'Automa SRL',
    884 => 'Harms+Wende GmbH & Co KG',
    885 => 'SAE-STAHL GmbH',
    886 => 'Microwave Data Systems',
    887 => 'Bernecker + Rainer Industrie-Elektronik GmbH',
    888 => 'Hiprom Technologies',
    890 => 'Nitta Corporation',
    891 => 'Kontron Modular Computers GmbH',
    892 => 'Marlin Controls',
    893 => 'ELCIS s.r.l.',
    894 => 'Acromag Inc.',
    895 => 'Avery Weigh-Tronix',
    899 => 'Practicon Ltd',
    900 => 'Schunk GmbH & Co. KG',
    901 => 'MYNAH Technologies',
    902 => 'Defontaine Groupe',
    903 => 'Emerson Process Management Power & Water Solutions',
    904 => 'F.A. Elec',
    905 => 'Hottinger Baldwin Messtechnik GmbH',
    906 => 'Coreco Imaging Inc.',
    907 => 'London Electronics Ltd.',
    908 => 'HSD SpA',
    909 => 'Comtrol Corporation',
    910 => 'TEAM S.A.',
    911 => 'MAN B&W Diesel Ltd.',
    914 => 'Micro Motion Inc.',
    915 => 'Eckelmann AG',
    916 => 'Hanyoung Nux',
    917 => 'Ransburg Industrial Finishing KK',
    918 => 'Kun Hung Electric Co. Ltd.',
    919 => 'Brimos wegbebakening b.v.',
    920 => 'Nitto Seiki Co.Ltd',
    921 => 'PPT Vision Inc.',
    922 => 'Yamazaki Machinery Works',
    923 => 'SCHMIDT Technology GmbH',
    924 => 'Parker Hannifin SpA (SBC Division)',
    925 => 'HIMA Paul Hildebrandt GmbH',
    926 => 'RivaTek Inc.',
    927 => 'Misumi Corporation',
    928 => 'GE Multilin',
    929 => 'Measurement Computing Corporation',
    930 => 'Jetter AG',
    931 => 'Tokyo Electronics Systems Corporation',
    932 => 'Togami Electric Mfg. Co.Ltd.',
    933 => 'HK Systems',
    934 => 'CDA Systems Ltd.',
    935 => 'Aerotech Inc.',
    936 => 'JVL Industrie Elektronik A/S',
    937 => 'NovaTech Process Solutions LLC',
    939 => 'Cisco Systems',
    940 => 'Grid Connect',
    941 => 'ITW Automotive Finishing',
    942 => 'HanYang System',
    943 => 'ABB K.K. Technical Center',
    944 => 'Taiyo Electric Wire & Cable Co.Ltd.',
    946 => 'SEREN IPS INC',
    947 => 'Belden CDT Electronics Division',
    948 => 'ControlNet International',
    949 => 'Gefran S.P.A.',
    950 => 'Jokab Safety AB',
    951 => 'SUMITA OPTICAL GLASS INC.',
    952 => 'Biffi Italia srl',
    953 => 'Beck IPC GmbH',
    954 => 'Copley Controls Corporation',
    955 => 'Fagor Automation S. Coop.',
    956 => 'DARCOM',
    957 => 'Frick Controls',
    958 => 'SymCom Inc.',
    959 => 'Infranor',
    960 => 'Kyosan Cable Ltd.',
    961 => 'Varian Vacuum Technologies',
    962 => 'Messung Systems',
    963 => 'Xantrex Technology Inc.',
    964 => 'StarThis Inc.',
    965 => 'Chiyoda Co.Ltd.',
    966 => 'Flowserve Corporation',
    967 => 'Spyder Controls Corp.',
    968 => 'IBA AG',
    969 => 'SHIMOHIRA ELECTRIC MFG.CO.,LTD',
    971 => 'Siemens L&A',
    972 => 'Micro Innovations AG',
    973 => 'Switchgear & Instrumentation',
    974 => 'PRE-TECH CO. LTD.',
    975 => 'National Semiconductor',
    976 => 'Invensys Process Systems',
    977 => 'Ametek HDR Power Systems',
    979 => 'TETRA-K Corporation',
    980 => 'C & M Corporation',
    981 => 'Siempelkamp Maschinen',
    983 => 'Daifuku America Corporation',
    984 => 'Electro-Matic Products Inc.',
    985 => 'BUSSAN MICROELECTRONICS CORP.',
    986 => 'ELAU AG',
    987 => 'Hetronic USA',
    988 => 'NIIGATA POWER SYSTEMS Co.Ltd.',
    989 => 'Software Horizons Inc.',
    990 => 'B3 Systems Inc.',
    991 => 'Moxa Networking Co.Ltd.',
    993 => 'S4 Integration',
    994 => 'Elettro Stemi S.R.L.',
    995 => 'AquaSensors',
    996 => 'Ifak System GmbH',
    997 => 'SANKEI MANUFACTURING Co.,LTD.',
    998 => 'Emerson Network Power Co.Ltd.',
    999 => 'Fairmount Automation Inc.',
    1000 => 'Bird Electronic Corporation',
    1001 => 'Nabtesco Corporation',
    1002 => 'AGM Electronics Inc.',
    1003 => 'ARCX Inc.',
    1004 => 'DELTA I/O Co.',
    1005 => 'Chun IL Electric Ind. Co.',
    1006 => 'N-Tron',
    1007 => 'Nippon Pneumatics/Fludics System CO.,LTD.',
    1008 => 'DDK Ltd.',
    1009 => 'Seiko Epson Corporation',
    1010 => 'Halstrup-Walcher GmbH',
    1011 => 'ITT',
    1012 => 'Ground Fault Systems bv',
    1013 => 'Scolari Engineering S.p.A.',
    1014 => 'Vialis Traffic bv',
    1015 => 'Weidmueller Interface GmbH & Co. KG',
    1016 => 'Shanghai Sibotech Automation Co. Ltd',
    1017 => 'AEG Power Supply Systems GmbH',
    1018 => 'Komatsu Electronics Inc.',
    1019 => 'Souriau',
    1020 => 'Baumuller Chicago Corp.',
    1021 => 'J. Schmalz GmbH',
    1022 => 'SEN Corporation',
    1023 => 'Korenix Technology Co. Ltd',
    1024 => 'Cooper Power Tools',
    1025 => 'INNOBIS',
    1026 => 'Shinho System',
    1027 => 'Xm Services Ltd.',
    1028 => 'KVC Co.Ltd.',
    1029 => 'Sanyu Seiki Co.Ltd.',
    1030 => 'TuxPLC',
    1031 => 'Northern Network Solutions',
    1032 => 'Converteam GmbH',
    1033 => 'Symbol Technologies',
    1034 => 'S-TEAM Lab',
    1035 => 'Maguire Products Inc.',
    1036 => 'AC&T',
    1037 => 'MITSUBISHI HEAVY INDUSTRIES LTD.',
    1038 => 'Hurletron Inc.',
    1039 => 'Chunichi Denshi Co.Ltd',
    1040 => 'Cardinal Scale Mfg. Co.',
    1041 => 'BTR NETCOM via RIA Connect Inc.',
    1042 => 'Base2',
    1043 => 'ASRC Aerospace',
    1044 => 'Beijing Stone Automation',
    1045 => 'Changshu Switchgear Manufacture Ltd.',
    1046 => 'METRONIX Corp.',
    1047 => 'WIT',
    1048 => 'ORMEC Systems Corp.',
    1049 => 'ASATech (China) Inc.',
    1050 => 'Controlled Systems Limited',
    1051 => 'Mitsubishi Heavy Ind. Digital System Co.Ltd.',
    1052 => 'Electrogrip',
    1053 => 'TDS Automation',
    1054 => 'T&C Power Conversion Inc.',
    1055 => 'Robostar Co.Ltd',
    1056 => 'Scancon A/S',
    1057 => 'Haas Automation Inc.',
    1058 => 'Eshed Technology',
    1059 => 'Delta Electronic Inc.',
    1060 => 'Innovasic Semiconductor',
    1061 => 'SoftDEL Systems Limited',
    1062 => 'FiberFin Inc.',
    1063 => 'Nicollet Technologies Corp.',
    1064 => 'B.F. Systems',
    1065 => 'Empire Wire and Supply LLC',
    1066 => 'ENDO KOGYO CO., LTD',
    1067 => 'Elmo Motion Control LTD',
    1069 => 'Asahi Keiki Co.Ltd.',
    1070 => 'Joy Mining Machinery',
    1071 => 'MPM Engineering Ltd',
    1072 => 'Wolke Inks & Printers GmbH',
    1073 => 'Mitsubishi Electric Engineering Co.Ltd.',
    1074 => 'COMET AG',
    1075 => 'Real Time Objects & Systems LLC',
    1076 => 'MISCO Refractometer',
    1077 => 'JT Engineering Inc.',
    1078 => 'Automated Packing Systems',
    1079 => 'Niobrara R&D Corp.',
    1080 => 'Garmin Ltd.',
    1081 => 'Japan Mobile Platform Co.Ltd',
    1082 => 'Advosol Inc.',
    1083 => 'ABB Global Services Limited',
    1084 => 'Sciemetric Instruments Inc.',
    1085 => 'Tata Elxsi Ltd.',
    1086 => 'TPC Mechatronics Co.Ltd.',
    1087 => 'Cooper Bussmann',
    1088 => 'Trinite Automatisering B.V.',
    1089 => 'Peek Traffic B.V.',
    1090 => 'Acrison Inc',
    1091 => 'Applied Robotics Inc.',
    1092 => 'FireBus Systems Inc.',
    1093 => 'Beijing Sevenstar Huachuang Electronics',
    1094 => 'Magnetek',
    1095 => 'Microscan',
    1096 => 'Air Water Inc.',
    1097 => 'Sensopart Industriesensorik GmbH',
    1098 => 'Tiefenbach Control Systems GmbH',
    1099 => 'INOXPA S.A',
    1100 => 'Zurich University of Applied Sciences',
    1101 => 'Ethernet Direct',
    1102 => 'GSI-Micro-E Systems',
    1103 => 'S-Net Automation Co.Ltd.',
    1104 => 'Power Electronics S.L.',
    1105 => 'Renesas Technology Corp.',
    1106 => 'NSWCCD-SSES',
    1107 => 'Porter Engineering Ltd.',
    1108 => 'Meggitt Airdynamics Inc.',
    1109 => 'Inductive Automation',
    1110 => 'Neural ID',
    1111 => 'EEPod LLC',
    1112 => 'Hitachi Industrial Equipment Systems Co.Ltd.',
    1113 => 'Salem Automation',
    1114 => 'port GmbH',
    1115 => 'B & PLUS',
    1116 => 'Graco Inc.',
    1117 => 'Altera Corporation',
    1118 => 'Technology Brewing Corporation',
    1121 => 'CSE Servelec',
    1124 => 'Fluke Networks',
    1125 => 'Tetra Pak Packaging Solutions SPA',
    1126 => 'Racine Federated Inc.',
    1127 => 'Pureron Japan Co.Ltd.',
    1130 => 'Brother Industries Ltd.',
    1132 => 'Leroy Automation',
    1134 => 'THK CO. LTD.',
    1137 => 'TR-Electronic GmbH',
    1138 => 'ASCON S.p.A.',
    1139 => 'Toledo do Brasil Industria de Balancas Ltda.',
    1140 => 'Bucyrus DBT Europe GmbH',
    1141 => 'Emerson Process Management Valve Automation',
    1142 => 'Alstom Transport',
    1144 => 'Matrox Electronic Systems',
    1145 => 'Littelfuse',
    1146 => 'PLASMART Inc.',
    1147 => 'Miyachi Corporation',
    1150 => 'Promess Incorporated',
    1151 => 'COPA-DATA GmbH',
    1152 => 'Precision Engine Controls Corporation',
    1153 => 'Alga Automacao e controle LTDA',
    1154 => 'U.I. Lapp GmbH',
    1155 => 'ICES',
    1156 => 'Philips Lighting bv',
    1157 => 'Aseptomag AG',
    1158 => 'ARC Informatique',
    1159 => 'Hesmor GmbH',
    1160 => 'Kobe Steel Ltd.',
    1161 => 'FLIR Systems',
    1162 => 'Simcon A/S',
    1163 => 'COPALP',
    1164 => 'Zypcom Inc.',
    1165 => 'Swagelok',
    1166 => 'Elspec',
    1167 => 'ITT Water & Wastewater AB',
    1168 => 'Kunbus GmbH Industrial Communication',
    1170 => 'Performance Controls Inc.',
    1171 => 'ACS Motion Control Ltd.',
    1173 => 'IStar Technology Limited',
    1174 => 'Alicat Scientific Inc.',
    1176 => 'ADFweb.com SRL',
    1177 => 'Tata Consultancy Services Limited',
    1178 => 'CXR Ltd.',
    1179 => 'Vishay Nobel AB',
    1181 => 'SolaHD',
    1182 => 'Endress+Hauser',
    1183 => 'Bartec GmbH',
    1185 => 'AccuSentry Inc.',
    1186 => 'Exlar Corporation',
    1187 => 'ILS Technology',
    1188 => 'Control Concepts Inc.',
    1190 => 'Procon Engineering Limited',
    1191 => 'Hermary Opto Electronics Inc.',
    1192 => 'Q-Lambda',
    1194 => 'VAMP Ltd',
    1195 => 'FlexLink',
    1196 => 'Office FA.com Co.Ltd.',
    1197 => 'SPMC (Changzhou) Co. Ltd.',
    1198 => 'Anton Paar GmbH',
    1199 => 'Zhuzhou CSR Times Electric Co.Ltd.',
    1200 => 'DeStaCo',
    1201 => 'Synrad Inc',
    1202 => 'Bonfiglioli Vectron GmbH',
    1203 => 'Pivotal Systems',
    1204 => 'TKSCT',
    1206 => 'CENTRALP',
    1207 => 'Tengen Group',
    1208 => 'OES Inc.',
    1209 => 'Actel Corporation',
    1210 => 'Monaghan Engineering Inc.',
    1211 => 'wenglor sensoric gmbh',
    1212 => 'HSA Systems',
    1213 => 'MK Precision Co.Ltd.',
    1214 => 'Tappan Wire and Cable',
    1215 => 'Heinzmann GmbH & Co. KG',
    1216 => 'Process Automation International Ltd.',
    1217 => 'Secure Crossing',
    1218 => 'SMA Railway Technology GmbH',
    1219 => 'FMS Force Measuring Systems AG',
    1221 => 'MagneMotion Inc.',
    1222 => 'STS Co.Ltd.',
    1223 => 'MERAK SIC SA',
    1224 => 'ABOUNDI Inc.',
    1225 => 'Rosemount Inc.',
    1226 => 'GEA FES Inc.',
    1227 => 'TMG Technologie und Engineering GmbH',
    1228 => 'embeX GmbH',
    1229 => 'GH Electrotermia S.A.',
    1230 => 'Tolomatic',
    1231 => 'Dukane',
    1232 => 'Elco (Tian Jin) Electronics Co.Ltd.',
    1233 => 'Jacobs Automation',
    1234 => 'Noda Radio Frequency Technologies Co.Ltd.',
    1235 => 'MSC Tuttlingen GmbH',
    1236 => 'Hitachi Cable Manchester',
    1237 => 'ACOREL SAS',
    1238 => 'Global Engineering Solutions Co.Ltd.',
    1239 => 'ALTE Transportation S.L.',
    1240 => 'Penko Engineering B.V.',
    1241 => 'Z-Tec Automation Systems Inc.',
    1242 => 'ENTRON Controls LLC',
    1243 => 'Johannes Huebner Fabrik Elektrischer Maschinen GmbH',
    1244 => 'RF IDeas, Inc.',
    1245 => 'Pentronic AB',
    1246 => 'SCA Schucker GmbH & Co. KG',
    1247 => 'TDK-Lambda',
    1250 => 'Altronic LLC',
    1251 => 'Siemens AG',
    1252 => 'Liebherr Transportation Systems GmbH & Co KG',
    1254 => 'SKF USA Inc.',
    1256 => 'LMI Technologies',
    1259 => 'EN Technologies Inc.',
    1261 => 'CEPHALOS Automatisierung mbH',
    1262 => 'Atronix Engineering, Inc.',
    1263 => 'Monode Marking Products, Inc.',
    1265 => 'Quabbin Wire & Cable Co., Inc.',
    1266 => 'GPSat Systems Australia',
    1269 => 'Tri-Tronics Co., Inc.',
    1270 => 'Rovema GmbH',
    1272 => 'IEP GmbH',
    1277 => 'Control Chief Corporation',
    1280 => 'Jacktek Systems Inc.',
    1282 => 'PRIMES GmbH',
    1283 => 'Branson Ultrasonics',
    1284 => 'DEIF A/S',
    1285 => '3S-Smart Software Solutions GmbH',
    1287 => 'Smarteye Corporation',
    1288 => 'Toshiba Machine',
    1289 => 'eWON',
    1290 => 'OFS',
    1291 => 'KROHNE',
    1293 => 'General Cable Industries, Inc.',
    1295 => 'Kistler Instrumente AG',
    1296 => 'YJS Co., Ltd.',
    1301 => 'Xylem Analytics Germany GmbH',
    1302 => 'Lenord, Bauer & Co. GmbH',
    1303 => 'Carlo Gavazzi Controls',
    1304 => 'Faiveley Transport',
    1306 => 'vMonitor',
    1307 => 'Kepware Technologies',
    1308 => 'duagon AG',
    1310 => 'Xylem Water Solutions',
    1311 => 'Automation Professionals, LLC',
    1313 => 'CEIA SpA',
    1314 => 'Marine Technologies LLC',
    1315 => 'Alphagate Automatisierungstechnik GmbH',
    1316 => 'Mecco Partners, LLC',
    1317 => 'LAP GmbH Laser Applikationen',
    1318 => 'ABB S.p.A. - SACE Division',
    1322 => 'Thermo Ramsey Inc.',
    1323 => 'Helmholz GmbH & Co. KG',
    1324 => 'EUCHNER GmbH + Co. KG',
    1325 => 'AMK GmbH & Co. KG',
    1326 => 'Badger Meter',
    1328 => 'Fisher-Rosemount Systems, Inc.',
    1329 => 'LJU Automatisierungstechnik GmbH',
    1330 => 'Fairbanks Scales, Inc.',
    1331 => 'Imperx, Inc.',
    1332 => 'FRONIUS International GmbH',
    1333 => 'Hoffman Enclosures',
    1334 => 'Elecsys Corporation',
    1335 => 'Bedrock Automation',
    1336 => 'RACO Manufacturing and Engineering',
    1337 => 'Hein Lanz Industrial Tech.',
    1338 => 'Synopsys, Inc.',
    1341 => 'Sensirion AG',
    1342 => 'SIKO GmbH',
    1344 => 'GRUNDFOS',
    1346 => 'Beijer Electronics Products AB',
    1348 => 'AIMCO',
    1350 => 'Coval Vacuum Managers',
    1351 => 'Powell Industries',
    1353 => 'IPDisplays',
    1354 => 'SCAIME SAS',
    1355 => 'Metal Work SpA',
    1356 => 'Telsonic AG',
    1358 => 'Hauch & Bach ApS',
    1359 => 'Pago AG',
    1360 => 'ULTIMATE Europe Transportation Equipment GmbH',
    1362 => 'Enovation Controls',
    1363 => 'Lake Cable LLC',
    1367 => 'Laird',
    1368 => 'Nanotec Electronic GmbH & Co. KG',
    1369 => 'SAMWON ACT Co., Ltd.',
    1370 => 'Aparian Inc.',
    1371 => 'Cosys Inc.',
    1372 => 'Insight Automation Inc.',
    1374 => 'FASTECH',
    1375 => 'K.A. Schmersal GmbH & Co. KG',
    1377 => 'Chromalox',
    1378 => 'SEIDENSHA ELECTRONICS CO., LTD',
    1380 => 'Don Electronics Ltd',
    1381 => 'burster gmbh & co kg',
    1382 => 'Unitronics (1989) (RG) LTD',
    1383 => 'OEM Technology Solutions',
    1384 => 'Allied Motion',
    1385 => 'Mitron Oy',
    1386 => 'Dengensha TOA',
    1387 => 'Systec Systemtechnik und Industrieautomation GmbH',
    1389 => 'Jenny Science AG',
    1390 => 'Baumer Optronic GmbH',
    1391 => 'Invertek Drives Ltd',
    1392 => 'High Grade Controls Corporation',
    1394 => 'Ishida Europe Limited',
    1396 => 'Actia Systems',
    1398 => 'Beijing Tiandi-Marco Electro-Hydraulic Control System Co., Ltd.',
    1399 => 'Universal Robots A/S',
    1401 => 'Dialight',
    1402 => 'E-T-A Elektrotechnische Apparate GmbH',
    1403 => 'Kemppi Oy',
    1404 => 'Tianjin Geneuo Technology Co., Ltd.',
    1405 => 'ORing Industrial Networking Corp.',
    1406 => 'Benchmark Electronics',
    1408 => 'ELAP S.R.L.',
    1409 => 'Applied Mining Technologies',
    1410 => 'KITZ SCT Corporation',
    1411 => 'VTEX Corporation',
    1412 => 'ESYSE GmbH Embedded Systems Engineering',
    1413 => 'Automation Controls',
    1415 => 'Cincinnati Test Systems',
    1417 => 'Zumbach Electronics Corp.',
    1418 => 'Emerson Process Management',
    1419 => 'CCS Inc.',
    1420 => 'Videojet, Inc.',
    1421 => 'Zebra Technologies',
    1422 => 'Anritsu Infivis',
    1423 => 'Dimetix AG',
    1424 => 'General Measure (China)',
    1425 => 'Fortress Interlocks',
    1427 => 'Task Force Tips',
    1428 => 'SERVO-ROBOT INC.',
    1429 => 'Flow Devices and Systems, Inc.',
    1430 => 'nLIGHT, Inc.',
    1431 => 'Microchip Technology Inc.',
    1432 => 'DENT Instruments',
    1433 => 'CMC Industrial Electronics Ltd.',
    1434 => 'Accutron Instruments Inc.',
    1435 => 'Kaeser Kompressoren SE',
    1436 => 'Optoelectronics',
    1437 => 'Coherix, Inc.',
    1438 => 'FLSmidth A/S',
    1439 => 'Kyland Corporation',
    1440 => 'Cole-Parmer Instrument Company',
    1441 => 'Wachendorff Automation GmbH & Co., KG',
    1442 => 'SMAC Moving Coil Actuators',
    1444 => 'PushCorp, Inc.',
    1445 => 'Fluke Process Instruments GmbH',
    1446 => 'Mini Motor srl',
    1447 => 'I-CON Industry Tech.',
    1448 => 'Grace Engineered Products, Inc.',
    1449 => 'Zaxis Inc.',
    1450 => 'Lumasense Technologies',
    1451 => 'Domino Printing',
    1452 => 'LightMachinery Inc',
    1453 => 'DEUTA-WERKE GmbH',
    1454 => 'Altus Sistemas de Automação S.A.',
    1455 => 'Criterion NDT',
    1456 => 'InterTech Development Company',
    1457 => 'Action Labs, Incorporated',
    1458 => 'Perle Systems Limited',
    1459 => 'Utthunga Technologies Pvt Ltd.',
    1460 => 'Dong IL Vision, Co., Ltd.',
    1461 => 'Wipotec Wiege-und Positioniersysteme GmbH',
    1462 => 'Atos spa',
    1463 => 'Solartron Metrology LTD',
    1464 => 'Willowglen Systems Inc.',
    1465 => 'Analog Devices',
    1466 => 'Power Electronics International, Inc.',
    1468 => 'Campbell Wrapper Corporation',
    1469 => 'Herkules-Resotec Elektronik GmbH',
    1470 => 'aignep spa',
    1471 => 'SHANGHAI CARGOA M.&E.EQUIPMENT CO.LTD',
    1472 => 'PMV Automation AB',
    1473 => 'K-Patents Oy',
    1474 => 'Dynatronix',
    1475 => 'Atop Technologies',
    1476 => 'Bitronics, LLC.',
    1477 => 'Delta Tau Data Systems',
    1478 => 'WITZ Corporation',
    1479 => 'AUTOSOL',
    1480 => 'ADB Safegate',
    1481 => 'VersaBuilt, Inc',
    1482 => 'Visual Technologies, Inc.',
    1483 => 'Artis GmbH',
    1484 => 'Reliance Electric Limited',
    1485 => 'Vanderlande',
    1486 => 'Packet Power',
    1487 => 'ima-tec gmbh',
    1488 => 'Vision Automation A/S',
    1489 => 'PROCENTEC BV',
    1490 => 'HETRONIK GmbH',
    1491 => 'Lanmark Controls Inc.',
    1492 => 'profichip GmbH',
    1493 => 'flexlog GmbH',
    1494 => 'YUCHANGTECH',
    1495 => 'Dynapower Company',
    1496 => 'TAKIKAWA ENGINEERING',
    1497 => 'Ingersoll Rand',
    1498 => 'ASA-RT s.r.l',
    1499 => 'Trumpf Laser- und Systemtechnik Gmbh',
    1500 => 'SYNTEC TECHNOLOGY CORPORATION COMPANY',
    1501 => 'Rinstrum',
    1502 => 'Symbotic LLC',
    1503 => 'GE Healthcare Life Sciences',
    1504 => 'BlueBotics SA',
    1505 => 'Dynapar Corporation',
    1506 => 'Blum-Novotest',
    1507 => 'CIMON',
    1508 => 'Dalian SeaSky Automation Co., ltd',
    1509 => 'Rethink Robotics, Inc.',
    1510 => 'Ingeteam',
    1511 => 'TOSEI ENGINEERING CORP.',
    1512 => 'SAMSON AG',
    1513 => 'TGW Mechanics GmbH'
  }.freeze

  # Device Type lookup table (from ODVA specification)
  DEVICE_TYPES = {
    0 => 'Generic Device (deprecated)',
    2 => 'AC Drive Device',
    3 => 'Motor Overload',
    4 => 'Limit Switch',
    5 => 'Inductive Proximity Switch',
    6 => 'Photoelectric Sensor',
    7 => 'General Purpose Discrete I/O',
    9 => 'Resolver',
    12 => 'Communications Adapter',
    14 => 'Programmable Logic Controller',
    16 => 'Position Controller',
    19 => 'DC Drive',
    21 => 'Contactor',
    22 => 'Motor Starter',
    23 => 'Softstart Starter',
    24 => 'Human-Machine Interface',
    26 => 'Mass Flow Controller',
    27 => 'Pneumatic Valve(s)',
    28 => 'Vacuum Pressure Gauge',
    29 => 'Process Control Value',
    30 => 'Residual Gas Analyzer',
    31 => 'DC Power Generator',
    32 => 'RF Power Generator',
    33 => 'Turbomolecular Vacuum Pump',
    34 => 'Encoder',
    35 => 'Safety Discrete I/O Device',
    36 => 'Fluid Flow Controller',
    37 => 'CIP Motion Drive',
    38 => 'CompoNet Repeater',
    39 => 'Mass Flow Controller Enhanced',
    40 => 'CIP Modbus Device',
    41 => 'CIP Modbus Translator',
    43 => 'Generic Device (CLICK)'
  }.freeze

  # Lookup vendor name by ID
  def vendor_name(vendor_id)
    VENDOR_IDS[vendor_id] || "Unknown Vendor (#{vendor_id})"
  end

  # Lookup device type by ID
  def device_type_name(device_type)
    DEVICE_TYPES[device_type] || "Unknown Device Type (#{device_type})"
  end

  # Build ENIP encapsulation header
  def build_enip_header(command, length = 0, session_handle = 0)
    # Encapsulation Header (24 bytes):
    # Command (2) + Length (2) + Session Handle (4) + Status (4) + Sender Context (8) + Options (4)
    header = [command, length, session_handle, 0].pack('vvVV')
    header += "\x00" * 8  # Sender Context
    header += [0].pack('V')  # Options
    header
  end

  # Build List Identity request
  def build_list_identity_request
    build_enip_header(ENIP_CMD_LIST_IDENTITY, 0, 0)
  end

  # Parse ENIP encapsulation header
  def parse_enip_header(data)
    return nil if data.nil? || data.length < 24

    command, length, session_handle, status = data[0, 12].unpack('vvVV')
    sender_context = data[12, 8]
    options = data[20, 4].unpack('V')[0]

    {
      command: command,
      length: length,
      session_handle: session_handle,
      status: status,
      sender_context: sender_context,
      options: options
    }
  end

  # Parse List Identity response
  def parse_list_identity_response(data)
    return nil if data.nil? || data.length < 26

    # Skip encapsulation header (24 bytes) and get CPF item count
    item_count = data[24, 2].unpack('v')[0]
    return nil if item_count.zero?

    pos = 26

    # Find Identity item (Type ID 0x000C)
    item_count.times do
      break if pos + 4 > data.length

      type_id = data[pos, 2].unpack('v')[0]
      item_length = data[pos + 2, 2].unpack('v')[0]
      pos += 4

      if type_id == CPF_TYPE_LIST_IDENTITY
        return parse_identity_item(data[pos, item_length])
      end

      pos += item_length
    end

    nil
  end

  # Parse Identity item from CPF
  def parse_identity_item(data)
    return nil if data.nil? || data.length < 33

    # Identity item structure:
    # Encapsulation Protocol Version (2)
    # Socket Address (16): sin_family(2), sin_port(2), sin_addr(4), sin_zero(8)
    # Vendor ID (2)
    # Device Type (2)
    # Product Code (2)
    # Revision (2 bytes: major, minor)
    # Status (2)
    # Serial Number (4)
    # Product Name Length (1)
    # Product Name (variable)

    identity = {}

    # Parse socket address to get device IP
    sin_family = data[2, 2].unpack('n')[0]
    sin_port = data[4, 2].unpack('n')[0]
    identity[:device_ip] = data[6, 4].bytes.join('.')

    # Parse identity fields
    identity[:vendor_id] = data[18, 2].unpack('v')[0]
    identity[:device_type] = data[20, 2].unpack('v')[0]
    identity[:product_code] = data[22, 2].unpack('v')[0]
    identity[:revision_major] = data[24].ord
    identity[:revision_minor] = data[25].ord
    identity[:status] = data[26, 2].unpack('v')[0]
    identity[:serial_number] = data[28, 4].unpack('V')[0]

    name_length = data[32].ord
    if name_length > 0 && data.length >= 33 + name_length
      identity[:product_name] = data[33, name_length].strip
    else
      identity[:product_name] = 'Unknown'
    end

    # Add human-readable names
    identity[:vendor_name] = vendor_name(identity[:vendor_id])
    identity[:device_type_name] = device_type_name(identity[:device_type])
    identity[:revision] = "#{identity[:revision_major]}.#{identity[:revision_minor]}"

    identity
  end

  # Register Session with ENIP device for CIP explicit messaging
  def register_session
    # Register Session command with protocol version 1, options flags 0
    data = [1, 0].pack('vv')
    packet = build_enip_header(ENIP_CMD_REGISTER_SESSION, data.length, 0) + data

    sock.put(packet)
    response = sock.get_once(-1, datastore['TIMEOUT'])

    return nil unless response && response.length >= 28

    # Parse response
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

    # Class segment: 0x20 (8-bit) or 0x21 (16-bit)
    if class_id <= 0xFF
      path += [0x20, class_id].pack('CC')
    else
      path += [0x21, 0, class_id].pack('CCV')[0, 4]
    end

    # Instance segment: 0x24 (8-bit) or 0x25 (16-bit)
    if instance_id <= 0xFF
      path += [0x24, instance_id].pack('CC')
    else
      path += [0x25, 0, instance_id].pack('CCv')
    end

    # Attribute segment: 0x30 (8-bit) or 0x31 (16-bit)
    if attribute_id
      if attribute_id <= 0xFF
        path += [0x30, attribute_id].pack('CC')
      else
        path += [0x31, 0, attribute_id].pack('CCv')
      end
    end

    path
  end

  # Build CIP request wrapped in Send RR Data
  def build_cip_request(service, class_id, instance_id, attribute_id = nil)
    path = build_cip_path(class_id, instance_id, attribute_id)
    path_size = path.length / 2

    # CIP request: Service (1) + Path Size (1) + Path (variable)
    cip_request = [service, path_size].pack('CC') + path

    # CPF (Common Packet Format): 2 items
    # Item 1: Null Address (type 0x0000, length 0)
    # Item 2: Unconnected Data (type 0x00B2, length = CIP request length)
    cpf = [2].pack('v')  # Item count
    cpf += [CPF_TYPE_NULL, 0].pack('vv')  # Null address item
    cpf += [CPF_TYPE_UNCONNECTED_DATA, cip_request.length].pack('vv') + cip_request

    # Send RR Data: Interface Handle (4) + Timeout (2) + CPF
    send_data = [0, 0].pack('Vv') + cpf

    build_enip_header(ENIP_CMD_SEND_RR_DATA, send_data.length, @session_handle) + send_data
  end

  # Send CIP request and parse response
  def send_cip_request(service, class_id, instance_id, attribute_id = nil)
    packet = build_cip_request(service, class_id, instance_id, attribute_id)

    sock.put(packet)
    response = sock.get_once(-1, datastore['TIMEOUT'])

    return nil unless response && response.length >= 44

    # Parse ENIP header status
    enip_status = response[8, 4].unpack('V')[0]
    return nil if enip_status != 0

    # Find CIP response in CPF data
    # Skip: ENIP header (24) + Interface Handle (4) + Timeout (2) + Item Count (2)
    # Skip: Null Address Item (4) + Unconnected Data Item header (4)
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

  # Parse TCP/IP Interface Attribute 5 (Interface Configuration)
  # Structure: IP (4) + Subnet (4) + Gateway (4) + Name Server (4) + Name Server 2 (4) + Domain Name
  def parse_interface_config(data)
    return nil if data.nil? || data.length < 12

    {
      ip_address: data[0, 4].bytes.reverse.join('.'),
      subnet_mask: data[4, 4].bytes.reverse.join('.'),
      gateway: data[8, 4].bytes.reverse.join('.')
    }
  end

  # Parse TCP/IP Interface Attribute 6 (Host Name)
  # Structure: String length (2) + String data
  def parse_hostname(data)
    return nil if data.nil? || data.length < 2

    str_len = data[0, 2].unpack('v')[0]
    return '' if str_len == 0 || data.length < 2 + str_len

    data[2, str_len].strip
  end

  # Parse Ethernet Link Attribute 3 (Physical Address / MAC)
  def parse_mac_address(data)
    return nil if data.nil? || data.length < 6

    data[0, 6].bytes.map { |b| format('%02X', b) }.join(':')
  end

  # Parse Ethernet Link Attribute 1 (Interface Speed in Mbps)
  def parse_interface_speed(data)
    return nil if data.nil? || data.length < 4

    data[0, 4].unpack('V')[0]
  end

  # Send List Identity request via TCP
  def send_list_identity_tcp(ip)
    begin
      connect
      sock.put(build_list_identity_request)
      response = sock.get_once(-1, datastore['TIMEOUT'])
      disconnect

      if response && response.length > 24
        parse_list_identity_response(response)
      else
        nil
      end
    rescue ::Rex::ConnectionError, ::EOFError, ::Timeout::Error => e
      vprint_error("#{ip}:#{rport} - TCP error: #{e.message}")
      nil
    end
  end

  # Send List Identity request via UDP
  def send_list_identity_udp(ip)
    begin
      udp_sock = Rex::Socket::Udp.create(
        'PeerHost' => ip,
        'PeerPort' => rport,
        'Context' => { 'Msf' => framework, 'MsfExploit' => self }
      )

      udp_sock.put(build_list_identity_request)

      response = nil
      begin
        ready = ::IO.select([udp_sock.fd], nil, nil, datastore['TIMEOUT'])
        if ready
          response, = udp_sock.recvfrom(65535)
        end
      rescue ::Errno::EAGAIN, ::Errno::EWOULDBLOCK
        # Timeout
      end

      udp_sock.close

      if response && response.length > 24
        parse_list_identity_response(response)
      else
        nil
      end
    rescue ::Rex::ConnectionError, ::EOFError, ::Timeout::Error => e
      vprint_error("#{ip}:#{rport} - UDP error: #{e.message}")
      nil
    end
  end

  # Action: List Identity
  def action_list_identity(ip)
    transport = datastore['UDP'] ? 'UDP' : 'TCP'
    print_status("#{ip}:#{rport} - Sending List Identity request via #{transport}...")

    identity = if datastore['UDP']
                 send_list_identity_udp(ip)
               else
                 send_list_identity_tcp(ip)
               end

    if identity.nil?
      print_error("#{ip}:#{rport} - No response received")
      return
    end

    # Display results
    print_good("#{ip}:#{rport} - EtherNet/IP Device Identified")
    print_status("  Vendor:        #{identity[:vendor_name]} (#{identity[:vendor_id]})")
    print_status("  Device Type:   #{identity[:device_type_name]} (#{identity[:device_type]})")
    print_status("  Product Code:  #{identity[:product_code]}")
    print_status("  Product Name:  #{identity[:product_name]}")
    print_status("  Revision:      #{identity[:revision]}")
    print_status("  Serial Number: 0x#{identity[:serial_number].to_s(16).upcase.rjust(8, '0')}")
    print_status("  Status:        0x#{identity[:status].to_s(16).upcase.rjust(4, '0')}")
    print_status("  Device IP:     #{identity[:device_ip]}")

    # Report to database
    report_service(
      host: ip,
      port: rport,
      proto: datastore['UDP'] ? 'udp' : 'tcp',
      name: 'enip',
      info: "#{identity[:vendor_name]} - #{identity[:product_name]} (#{identity[:revision]})"
    )

    report_note(
      host: ip,
      proto: datastore['UDP'] ? 'udp' : 'tcp',
      port: rport,
      sname: 'enip',
      type: 'enip.device_identity',
      data: identity
    )

    identity
  end

  # Action: Network Info via CIP explicit messaging
  def action_network_info(ip)
    print_status("#{ip}:#{rport} - Reading network configuration via CIP...")

    begin
      connect
      unless register_session
        print_error("#{ip}:#{rport} - Failed to register CIP session")
        disconnect
        return nil
      end

      network_info = {}

      # Read TCP/IP Interface Object (0xF5), Instance 1
      # Attribute 5: Interface Configuration (IP, Subnet, Gateway)
      result = get_attribute(CIP_TCP_IP_INTERFACE, 1, 5)
      if result && result[:status] == 0
        config = parse_interface_config(result[:data])
        if config
          network_info[:ip_address] = config[:ip_address]
          network_info[:subnet_mask] = config[:subnet_mask]
          network_info[:gateway] = config[:gateway]
        end
      else
        vprint_status("#{ip}:#{rport} - Could not read interface configuration")
      end

      # Attribute 6: Host Name
      result = get_attribute(CIP_TCP_IP_INTERFACE, 1, 6)
      if result && result[:status] == 0
        hostname = parse_hostname(result[:data])
        network_info[:hostname] = hostname if hostname && !hostname.empty?
      else
        vprint_status("#{ip}:#{rport} - Could not read hostname")
      end

      # Read Ethernet Link Object (0xF6), Instance 1
      # Attribute 3: Physical Address (MAC)
      result = get_attribute(CIP_ETHERNET_LINK, 1, 3)
      if result && result[:status] == 0
        mac = parse_mac_address(result[:data])
        network_info[:mac_address] = mac if mac
      else
        vprint_status("#{ip}:#{rport} - Could not read MAC address")
      end

      # Attribute 1: Interface Speed
      result = get_attribute(CIP_ETHERNET_LINK, 1, 1)
      if result && result[:status] == 0
        speed = parse_interface_speed(result[:data])
        network_info[:interface_speed] = speed if speed
      else
        vprint_status("#{ip}:#{rport} - Could not read interface speed")
      end

      unregister_session
      disconnect

      if network_info.empty?
        print_warning("#{ip}:#{rport} - No network information available via CIP")
        return nil
      end

      # Display results
      print_good("#{ip}:#{rport} - Network Configuration (via CIP)")
      print_status("  IP Address:    #{network_info[:ip_address]}") if network_info[:ip_address]
      print_status("  Subnet Mask:   #{network_info[:subnet_mask]}") if network_info[:subnet_mask]
      print_status("  Gateway:       #{network_info[:gateway]}") if network_info[:gateway]
      print_status("  MAC Address:   #{network_info[:mac_address]}") if network_info[:mac_address]
      print_status("  Hostname:      #{network_info[:hostname]}") if network_info[:hostname]
      print_status("  Link Speed:    #{network_info[:interface_speed]} Mbps") if network_info[:interface_speed]

      # Report to database
      report_note(
        host: ip,
        proto: 'tcp',
        port: rport,
        sname: 'enip',
        type: 'enip.network_config',
        data: network_info
      )

      network_info
    rescue ::Rex::ConnectionError, ::EOFError, ::Timeout::Error => e
      vprint_error("#{ip}:#{rport} - CIP error: #{e.message}")
      nil
    ensure
      disconnect rescue nil
    end
  end

  # Action: Full Scan (List Identity + Network Info)
  def action_full_scan(ip)
    print_status("#{ip}:#{rport} - Performing full device enumeration...")

    results = {}

    # Phase 1: List Identity (session-less, works with TCP or UDP)
    identity = action_list_identity(ip)
    results[:identity] = identity if identity

    # Phase 2: Network Info via CIP explicit messaging (TCP only)
    if datastore['UDP']
      print_warning("#{ip}:#{rport} - Network info requires TCP, skipping (UDP mode)")
    else
      network_info = action_network_info(ip)
      results[:network_info] = network_info if network_info
    end

    results
  end

  # Main execution method for scanner
  def run_host(ip)
    case action.name
    when 'LIST_IDENTITY'
      action_list_identity(ip)
    when 'NETWORK_INFO'
      if datastore['UDP']
        print_error("#{ip}:#{rport} - NETWORK_INFO requires TCP, disable UDP option")
        return
      end
      action_network_info(ip)
    when 'FULL_SCAN'
      action_full_scan(ip)
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
  end
end
